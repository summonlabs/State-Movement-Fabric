// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical, length-delimited binary encoding used by the wire protocol, the
// durable stores, and every digest/MAC binding in the system.
//
// Rules, in full:
//   * integers are fixed width, little endian, never varint;
//   * booleans are exactly 0x00 or 0x01 and nothing else;
//   * blobs and text are prefixed with a 64-bit length, so concatenation can
//     never be ambiguous;
//   * text must be valid UTF-8;
//   * decoding is bounded: every read declares its own maximum, and the whole
//     buffer is bounded by DecodeLimits;
//   * trailing bytes are an error unless the caller explicitly accepts them.

#ifndef SMF_CODEC_HPP
#define SMF_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "smf/bytes.hpp"
#include "smf/digest.hpp"
#include "smf/status.hpp"

namespace smf {

struct DecodeLimits {
  std::size_t max_blob_bytes = 1U << 20;   // 1 MiB
  std::size_t max_text_bytes = 64U << 10;  // 64 KiB
  std::size_t max_input_bytes = 8U << 20;  // 8 MiB
};

class CanonicalEncoder {
 public:
  CanonicalEncoder() = default;

  // Encodes the domain string as the first field, which is what makes two
  // different bindings over the same field values distinguishable.
  explicit CanonicalEncoder(std::string_view domain) { text(domain); }

  void u8(std::uint8_t value) { buffer_.push_back(value); }
  void boolean(bool value) { buffer_.push_back(value ? 1U : 0U); }
  void u16(std::uint16_t value) { store_le(value, 2); }
  void u32(std::uint32_t value) { store_le(value, 4); }
  void u64(std::uint64_t value) { store_le(value, 8); }
  void i64(std::int64_t value) { store_le(static_cast<std::uint64_t>(value), 8); }
  void blob(ByteView value);
  void text(std::string_view value);
  void digest(const Digest& value) { append(buffer_, value.view()); }

  [[nodiscard]] const Bytes& bytes() const noexcept { return buffer_; }
  [[nodiscard]] ByteView view() const noexcept { return ByteView(buffer_.data(), buffer_.size()); }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }

 private:
  void store_le(std::uint64_t value, std::size_t width);

  Bytes buffer_;
};

class CanonicalDecoder {
 public:
  explicit CanonicalDecoder(ByteView input, DecodeLimits limits = {}) noexcept
      : input_(input), limits_(limits), over_limit_(input.size() > limits.max_input_bytes) {}

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<bool> boolean();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<std::int64_t> i64();

  // Length-prefixed payloads. blob() returns a view into the decoded buffer and
  // therefore never allocates; callers that need to outlive the buffer copy it.
  [[nodiscard]] Result<ByteView> blob(std::size_t max_bytes);
  [[nodiscard]] Result<std::string_view> text(std::size_t max_bytes);
  [[nodiscard]] Result<Digest> digest();

  // Reads a collection count and rejects anything above max_count before the
  // caller can use it to size a loop or an allocation.
  [[nodiscard]] Result<std::size_t> count(std::size_t max_count);

  [[nodiscard]] std::size_t remaining() const noexcept { return input_.size() - offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == input_.size(); }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

  // Fails unless every byte was consumed.
  [[nodiscard]] Status require_end() const;

 private:
  [[nodiscard]] bool limited() const noexcept { return over_limit_; }
  [[nodiscard]] Status bounds_failure(const char* what) const;

  ByteView input_;
  DecodeLimits limits_;
  std::size_t offset_ = 0;
  bool over_limit_ = false;
};

// Digest and MAC of a canonical encoding, both constant-time verifiable.
[[nodiscard]] Digest canonical_digest(const CanonicalEncoder& encoder) noexcept;
[[nodiscard]] Digest canonical_mac(ByteView key, const CanonicalEncoder& encoder) noexcept;
[[nodiscard]] Digest canonical_mac(std::string_view key, const CanonicalEncoder& encoder) noexcept;

}  // namespace smf

#endif  // SMF_CODEC_HPP
