// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// SHA-256, HMAC-SHA-256, and the domain-separated digest builder that makes
// every binding in this system unambiguous under concatenation.

#ifndef SMF_DIGEST_HPP
#define SMF_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "smf/bytes.hpp"
#include "smf/status.hpp"

namespace smf {

class Digest {
 public:
  static constexpr std::size_t kBytes = 32;

  Digest() noexcept = default;
  explicit Digest(std::array<Byte, kBytes> bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] static Result<Digest> from_hex(std::string_view text);
  [[nodiscard]] static Result<Digest> from_bytes(ByteView raw);

  [[nodiscard]] const std::array<Byte, kBytes>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] const Byte* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] ByteView view() const noexcept { return ByteView(bytes_.data(), bytes_.size()); }
  [[nodiscard]] std::string hex() const;
  [[nodiscard]] bool is_zero() const noexcept;

  friend bool operator==(const Digest& a, const Digest& b) noexcept {
    return constant_time_equal(a.view(), b.view());
  }
  friend bool operator!=(const Digest& a, const Digest& b) noexcept { return !(a == b); }
  friend bool operator<(const Digest& a, const Digest& b) noexcept { return a.bytes_ < b.bytes_; }

 private:
  std::array<Byte, kBytes> bytes_{};
};

// Incremental SHA-256. finalize() consumes the state and returns the digest;
// the object is left reset and reusable.
class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = Digest::kBytes;
  static constexpr std::size_t kBlockBytes = 64;

  Sha256() noexcept { reset(); }

  void update(ByteView data) noexcept;
  void update(std::string_view data) noexcept { update(as_bytes(data)); }
  [[nodiscard]] Digest finalize() noexcept;
  void reset() noexcept;

 private:
  void compress(const Byte* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<Byte, kBlockBytes> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_ = 0;
};

[[nodiscard]] Digest sha256(ByteView data) noexcept;
[[nodiscard]] Digest sha256(std::string_view data) noexcept;

class HmacSha256 {
 public:
  static constexpr std::size_t kBlockBytes = 64;

  explicit HmacSha256(ByteView key) noexcept;
  explicit HmacSha256(std::string_view key) noexcept : HmacSha256(as_bytes(key)) {}

  void update(ByteView data) noexcept { inner_.update(data); }
  void update(std::string_view data) noexcept { inner_.update(as_bytes(data)); }
  [[nodiscard]] Digest finalize() noexcept;

 private:
  Sha256 inner_;
  std::array<Byte, kBlockBytes> opad_{};
};

[[nodiscard]] Digest hmac_sha256(ByteView key, ByteView data) noexcept;
[[nodiscard]] Digest hmac_sha256(std::string_view key, std::string_view data) noexcept;

// Constant-time verification of a truncated authentication tag.
[[nodiscard]] bool verify_truncated_tag(const Digest& expected, ByteView provided, std::size_t tag_bytes) noexcept;

}  // namespace smf

#endif  // SMF_DIGEST_HPP
