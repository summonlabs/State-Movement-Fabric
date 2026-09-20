// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/time.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>

namespace smf {
namespace {

[[nodiscard]] std::tm to_utc_tm(Millis unix_millis) noexcept {
  const std::time_t seconds = static_cast<std::time_t>(unix_millis / 1000);
  std::tm tm_value{};
#if defined(_WIN32)
  gmtime_s(&tm_value, &seconds);
#else
  gmtime_r(&seconds, &tm_value);
#endif
  return tm_value;
}

}  // namespace

Millis SystemClock::unix_millis() const {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

Millis SystemClock::monotonic_millis() const {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

const Clock& system_clock() noexcept {
  static const SystemClock instance;
  return instance;
}

std::string format_utc(Millis unix_millis) {
  const std::tm tm_value = to_utc_tm(unix_millis);
  Millis remainder = unix_millis % 1000;
  if (remainder < 0) remainder += 1000;

  char buffer[40];
  const int written = std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                                    tm_value.tm_year + 1900, tm_value.tm_mon + 1, tm_value.tm_mday,
                                    tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec,
                                    static_cast<int>(remainder));
  if (written <= 0) return std::string();
  return std::string(buffer, static_cast<std::size_t>(written));
}

}  // namespace smf
