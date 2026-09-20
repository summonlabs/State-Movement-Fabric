// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/codec.hpp"

#include <cstring>

namespace smf {
namespace {

[[nodiscard]] std::uint64_t load_le(const Byte* data, std::size_t width) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8U * i);
  }
  return value;
}

}  // namespace

void CanonicalEncoder::store_le(std::uint64_t value, std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    buffer_.push_back(static_cast<Byte>((value >> (8U * i)) & 0xFFU));
  }
}

void CanonicalEncoder::blob(ByteView value) {
  store_le(value.size(), 8);
  append(buffer_, value);
}

void CanonicalEncoder::text(std::string_view value) {
  store_le(value.size(), 8);
  append(buffer_, value);
}

Status CanonicalDecoder::bounds_failure(const char* what) const {
  if (over_limit_) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "decoded buffer exceeds the configured input limit");
  }
  return Status(ReasonCode::PROTOCOL_TRUNCATED, what);
}

Result<std::uint8_t> CanonicalDecoder::u8() {
  if (limited()) return bounds_failure("u8 read past the end of the buffer");
  if (remaining() < 1) return bounds_failure("u8 read past the end of the buffer");
  const std::uint8_t value = input_[offset_];
  offset_ += 1;
  return value;
}

Result<bool> CanonicalDecoder::boolean() {
  const auto raw = u8();
  if (!raw.ok()) return raw.status();
  if (raw.value() > 1U) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION,
                  "boolean must be encoded as exactly 0x00 or 0x01");
  }
  return raw.value() == 1U;
}

Result<std::uint16_t> CanonicalDecoder::u16() {
  if (limited()) return bounds_failure("u16 read past the end of the buffer");
  if (remaining() < 2) return bounds_failure("u16 read past the end of the buffer");
  const std::uint16_t value = static_cast<std::uint16_t>(load_le(input_.data() + offset_, 2));
  offset_ += 2;
  return value;
}

Result<std::uint32_t> CanonicalDecoder::u32() {
  if (limited()) return bounds_failure("u32 read past the end of the buffer");
  if (remaining() < 4) return bounds_failure("u32 read past the end of the buffer");
  const std::uint32_t value = static_cast<std::uint32_t>(load_le(input_.data() + offset_, 4));
  offset_ += 4;
  return value;
}

Result<std::uint64_t> CanonicalDecoder::u64() {
  if (limited()) return bounds_failure("u64 read past the end of the buffer");
  if (remaining() < 8) return bounds_failure("u64 read past the end of the buffer");
  const std::uint64_t value = load_le(input_.data() + offset_, 8);
  offset_ += 8;
  return value;
}

Result<std::int64_t> CanonicalDecoder::i64() {
  const auto raw = u64();
  if (!raw.ok()) return raw.status();
  return static_cast<std::int64_t>(raw.value());
}

Result<ByteView> CanonicalDecoder::blob(std::size_t max_bytes) {
  const auto declared = u64();
  if (!declared.ok()) return declared.status();

  const std::uint64_t length = declared.value();
  const std::uint64_t allowed = static_cast<std::uint64_t>(max_bytes < limits_.max_blob_bytes
                                                              ? max_bytes
                                                              : limits_.max_blob_bytes);
  if (length > allowed) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED,
                  "declared blob length exceeds the permitted maximum");
  }
  if (length > static_cast<std::uint64_t>(remaining())) {
    return Status(ReasonCode::PROTOCOL_TRUNCATED, "declared blob length exceeds the remaining input");
  }
  const std::size_t width = static_cast<std::size_t>(length);
  const ByteView value(input_.data() + offset_, width);
  offset_ += width;
  return value;
}

Result<std::string_view> CanonicalDecoder::text(std::size_t max_bytes) {
  const auto raw = blob(max_bytes < limits_.max_text_bytes ? max_bytes : limits_.max_text_bytes);
  if (!raw.ok()) return raw.status();
  if (!is_valid_utf8(raw.value())) {
    return Status(ReasonCode::INVALID_UTF8, "text field is not valid UTF-8");
  }
  return as_string_view(raw.value());
}

Result<Digest> CanonicalDecoder::digest() {
  if (limited()) return bounds_failure("digest read past the end of the buffer");
  if (remaining() < Digest::kBytes) {
    return Status(ReasonCode::PROTOCOL_TRUNCATED, "digest requires 32 bytes");
  }
  const ByteView raw(input_.data() + offset_, Digest::kBytes);
  offset_ += Digest::kBytes;
  return Digest::from_bytes(raw);
}

Result<std::size_t> CanonicalDecoder::count(std::size_t max_count) {
  const auto raw = u32();
  if (!raw.ok()) return raw.status();
  if (raw.value() > max_count) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "declared collection count exceeds the maximum");
  }
  return static_cast<std::size_t>(raw.value());
}

Status CanonicalDecoder::require_end() const {
  if (over_limit_) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "decoded buffer exceeds the configured input limit");
  }
  if (!at_end()) {
    return Status(ReasonCode::PROTOCOL_TRAILING_GARBAGE, "message carried unconsumed trailing bytes");
  }
  return Status::success();
}

Digest canonical_digest(const CanonicalEncoder& encoder) noexcept {
  return sha256(encoder.view());
}

Digest canonical_mac(ByteView key, const CanonicalEncoder& encoder) noexcept {
  return hmac_sha256(key, encoder.view());
}

Digest canonical_mac(std::string_view key, const CanonicalEncoder& encoder) noexcept {
  return hmac_sha256(as_bytes(key), encoder.view());
}

}  // namespace smf
