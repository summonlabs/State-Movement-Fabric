// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/digest.hpp"

#include <cstring>

namespace smf {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

constexpr std::array<std::uint32_t, 8> kInitialState{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU,
    0x5be0cd19U};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32U - shift));
}

[[nodiscard]] std::uint32_t load_be32(const Byte* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) | (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | static_cast<std::uint32_t>(p[3]);
}

void store_be32(std::uint32_t value, Byte* p) noexcept {
  p[0] = static_cast<Byte>((value >> 24U) & 0xFFU);
  p[1] = static_cast<Byte>((value >> 16U) & 0xFFU);
  p[2] = static_cast<Byte>((value >> 8U) & 0xFFU);
  p[3] = static_cast<Byte>(value & 0xFFU);
}

}  // namespace

Result<Digest> Digest::from_hex(std::string_view text) {
  if (text.size() != kBytes * 2U) {
    return Status(ReasonCode::INVALID_DIGEST, "digest hex must be 64 characters");
  }
  Bytes raw;
  if (!smf::from_hex(text, raw) || raw.size() != kBytes) {
    return Status(ReasonCode::INVALID_DIGEST, "digest hex is not valid hexadecimal");
  }
  std::array<Byte, kBytes> out{};
  std::memcpy(out.data(), raw.data(), kBytes);
  return Digest(out);
}

Result<Digest> Digest::from_bytes(ByteView raw) {
  if (raw.size() != kBytes) {
    return Status(ReasonCode::INVALID_DIGEST, "digest requires exactly 32 bytes");
  }
  std::array<Byte, kBytes> out{};
  std::memcpy(out.data(), raw.data(), kBytes);
  return Digest(out);
}

std::string Digest::hex() const { return to_hex(view()); }

bool Digest::is_zero() const noexcept {
  Byte accumulator = 0;
  for (const Byte b : bytes_) accumulator = static_cast<Byte>(accumulator | b);
  return accumulator == 0;
}

void Sha256::reset() noexcept {
  state_ = kInitialState;
  buffer_.fill(0);
  buffered_ = 0;
  total_ = 0;
}

void Sha256::compress(const Byte* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = load_be32(block + (i * 4U));
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7U) ^ rotr(w[i - 15], 18U) ^ (w[i - 15] >> 3U);
    const std::uint32_t s1 = rotr(w[i - 2], 17U) ^ rotr(w[i - 2], 19U) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(ByteView data) noexcept {
  total_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;

  if (buffered_ != 0) {
    const std::size_t need = kBlockBytes - buffered_;
    const std::size_t take = data.size() < need ? data.size() : need;
    std::memcpy(buffer_.data() + buffered_, data.data(), take);
    buffered_ += take;
    offset = take;
    if (buffered_ == kBlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }

  while ((data.size() - offset) >= kBlockBytes) {
    compress(data.data() + offset);
    offset += kBlockBytes;
  }

  if (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    std::memcpy(buffer_.data(), data.data() + offset, remaining);
    buffered_ = remaining;
  }
}

Digest Sha256::finalize() noexcept {
  const std::uint64_t bit_length = total_ * 8U;

  const Byte pad = 0x80U;
  update(ByteView(&pad, 1));

  const Byte zero = 0x00U;
  while (buffered_ != 56U) {
    update(ByteView(&zero, 1));
  }

  Byte length_bytes[8];
  for (std::size_t i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<Byte>((bit_length >> ((7U - i) * 8U)) & 0xFFU);
  }
  update(ByteView(length_bytes, 8));

  std::array<Byte, Digest::kBytes> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    store_be32(state_[i], out.data() + (i * 4U));
  }
  reset();
  return Digest(out);
}

Digest sha256(ByteView data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finalize();
}

Digest sha256(std::string_view data) noexcept { return sha256(as_bytes(data)); }

HmacSha256::HmacSha256(ByteView key) noexcept {
  std::array<Byte, kBlockBytes> key_block{};
  if (key.size() > kBlockBytes) {
    Sha256 hasher;
    hasher.update(key);
    const Digest reduced = hasher.finalize();
    std::memcpy(key_block.data(), reduced.data(), Digest::kBytes);
  } else if (!key.empty()) {
    std::memcpy(key_block.data(), key.data(), key.size());
  }

  std::array<Byte, kBlockBytes> ipad{};
  for (std::size_t i = 0; i < kBlockBytes; ++i) {
    ipad[i] = static_cast<Byte>(key_block[i] ^ 0x36U);
    opad_[i] = static_cast<Byte>(key_block[i] ^ 0x5CU);
  }
  inner_.update(ByteView(ipad.data(), ipad.size()));
}

Digest HmacSha256::finalize() noexcept {
  const Digest inner_digest = inner_.finalize();
  Sha256 outer;
  outer.update(ByteView(opad_.data(), opad_.size()));
  outer.update(inner_digest.view());
  return outer.finalize();
}

Digest hmac_sha256(ByteView key, ByteView data) noexcept {
  HmacSha256 mac(key);
  mac.update(data);
  return mac.finalize();
}

Digest hmac_sha256(std::string_view key, std::string_view data) noexcept {
  return hmac_sha256(as_bytes(key), as_bytes(data));
}

bool verify_truncated_tag(const Digest& expected, ByteView provided, std::size_t tag_bytes) noexcept {
  if (tag_bytes == 0 || tag_bytes > Digest::kBytes) return false;
  if (provided.size() != tag_bytes) return false;
  return constant_time_equal(ByteView(expected.data(), tag_bytes), provided);
}

}  // namespace smf
