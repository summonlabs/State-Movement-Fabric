// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/bytes.hpp"

#include <limits>

namespace smf {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string to_hex(ByteView value) {
  std::string out;
  out.reserve(value.size() * 2U);
  for (const Byte b : value) {
    out.push_back(kHexDigits[(b >> 4U) & 0x0FU]);
    out.push_back(kHexDigits[b & 0x0FU]);
  }
  return out;
}

bool from_hex(std::string_view text, Bytes& out) {
  if ((text.size() % 2U) != 0U) return false;
  Bytes decoded;
  decoded.reserve(text.size() / 2U);
  for (std::size_t i = 0; i < text.size(); i += 2U) {
    const int hi = hex_value(text[i]);
    const int lo = hex_value(text[i + 1U]);
    if (hi < 0 || lo < 0) return false;
    decoded.push_back(static_cast<Byte>((hi << 4) | lo));
  }
  out = std::move(decoded);
  return true;
}

bool is_valid_utf8(ByteView value) noexcept {
  std::size_t i = 0;
  while (i < value.size()) {
    const std::uint32_t lead = value[i];
    if (lead < 0x80U) {
      ++i;
      continue;
    }
    std::size_t continuation = 0;
    std::uint32_t code_point = 0;
    if ((lead & 0xE0U) == 0xC0U) {
      continuation = 1;
      code_point = lead & 0x1FU;
    } else if ((lead & 0xF0U) == 0xE0U) {
      continuation = 2;
      code_point = lead & 0x0FU;
    } else if ((lead & 0xF8U) == 0xF0U) {
      continuation = 3;
      code_point = lead & 0x07U;
    } else {
      return false;
    }
    if (i + continuation >= value.size()) return false;
    for (std::size_t k = 1; k <= continuation; ++k) {
      const std::uint32_t next = value[i + k];
      if ((next & 0xC0U) != 0x80U) return false;
      code_point = (code_point << 6U) | (next & 0x3FU);
    }
    if (continuation == 1 && code_point < 0x80U) return false;
    if (continuation == 2 && code_point < 0x800U) return false;
    if (continuation == 3 && code_point < 0x10000U) return false;
    if (code_point > 0x10FFFFU) return false;
    if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;
    i += continuation + 1U;
  }
  return true;
}

bool constant_time_equal(ByteView a, ByteView b) noexcept {
  if (a.size() != b.size()) return false;
  Byte accumulator = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    accumulator = static_cast<Byte>(accumulator | (a[i] ^ b[i]));
  }
  return accumulator == 0;
}

bool checked_add(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a > std::numeric_limits<std::uint64_t>::max() - b) return false;
  out = a + b;
  return true;
}

bool checked_mul(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a != 0U && b > std::numeric_limits<std::uint64_t>::max() / a) return false;
  out = a * b;
  return true;
}

}  // namespace smf
