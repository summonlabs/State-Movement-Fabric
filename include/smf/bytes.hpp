// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Byte vocabulary shared by every layer of the fabric. Nothing here allocates
// implicitly: views are views, and conversions are explicit.

#ifndef SMF_BYTES_HPP
#define SMF_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace smf {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using ByteSpan = std::span<Byte>;
using ByteView = std::span<const Byte>;

[[nodiscard]] inline ByteView as_bytes(std::string_view value) noexcept {
  return ByteView(reinterpret_cast<const Byte*>(value.data()), value.size());
}

[[nodiscard]] inline ByteView as_bytes(const Bytes& value) noexcept {
  return ByteView(value.data(), value.size());
}

[[nodiscard]] inline ByteView as_bytes(const std::string& value) noexcept {
  return ByteView(reinterpret_cast<const Byte*>(value.data()), value.size());
}

[[nodiscard]] inline std::string_view as_string_view(ByteView value) noexcept {
  return std::string_view(reinterpret_cast<const char*>(value.data()), value.size());
}

// Lowercase hexadecimal, no separators, no prefix.
[[nodiscard]] std::string to_hex(ByteView value);

// Strict hexadecimal decoding: even length, lowercase or uppercase digits, no
// whitespace, no prefixes. Returns false and leaves out untouched on any
// deviation. Because the whole input must be consumed, callers get
// reject-trailing-garbage semantics for free.
[[nodiscard]] bool from_hex(std::string_view text, Bytes& out);

// Strict UTF-8 validation: rejects overlong encodings, UTF-16 surrogate code
// points, code points above U+10FFFF, and truncated sequences.
[[nodiscard]] bool is_valid_utf8(ByteView value) noexcept;

// Length-independent-of-content comparison. Returns false immediately when the
// lengths differ (length is not treated as a secret anywhere in this system).
[[nodiscard]] bool constant_time_equal(ByteView a, ByteView b) noexcept;

inline void append(Bytes& dst, ByteView src) {
  dst.insert(dst.end(), src.begin(), src.end());
}

inline void append(Bytes& dst, std::string_view src) {
  append(dst, as_bytes(src));
}

// Checked size arithmetic. Every externally supplied length travels through
// these helpers before it can reach an allocation or an offset computation.
[[nodiscard]] bool checked_add(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool checked_mul(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;

}  // namespace smf

#endif  // SMF_BYTES_HPP
