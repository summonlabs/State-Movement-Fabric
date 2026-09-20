// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Clock seam. Everything that needs to reason about time takes a Clock so that
// proofs can be deterministic and so that no component silently depends on
// wall-clock behaviour it was not given.

#ifndef SMF_TIME_HPP
#define SMF_TIME_HPP

#include <cstdint>
#include <string>

namespace smf {

using Millis = std::int64_t;

// 2026-01-01T00:00:00Z. Used as the deterministic origin for ManualClock.
inline constexpr Millis kEpoch2026 = 1767225600000LL;

class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;
  virtual ~Clock() = default;

  // Wall-clock milliseconds since the Unix epoch. Used only for human-facing
  // records (provenance timestamps, marker contents).
  [[nodiscard]] virtual Millis unix_millis() const = 0;

  // Monotonic milliseconds. Used for every elapsed-time decision. Never
  // compared against unix_millis().
  [[nodiscard]] virtual Millis monotonic_millis() const = 0;
};

// Process-wide clock backed by the operating system.
class SystemClock final : public Clock {
 public:
  SystemClock() = default;
  [[nodiscard]] Millis unix_millis() const override;
  [[nodiscard]] Millis monotonic_millis() const override;
};

// Deterministic clock for proofs. Time advances only when told to.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(Millis start_unix_millis = kEpoch2026) noexcept
      : unix_millis_(start_unix_millis) {}

  [[nodiscard]] Millis unix_millis() const override { return unix_millis_; }
  [[nodiscard]] Millis monotonic_millis() const override { return monotonic_millis_; }

  void advance(Millis delta_millis) noexcept {
    unix_millis_ += delta_millis;
    monotonic_millis_ += delta_millis;
  }

 private:
  Millis unix_millis_ = kEpoch2026;
  Millis monotonic_millis_ = 0;
};

// Shared process-wide system clock instance.
[[nodiscard]] const Clock& system_clock() noexcept;

// RFC 3339 / ISO 8601 UTC rendering with millisecond precision, for example
// "2026-01-01T00:00:00.000Z".
[[nodiscard]] std::string format_utc(Millis unix_millis);

}  // namespace smf

#endif  // SMF_TIME_HPP
