// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Explicit, opt-in fault injection.
//
// The fabric's hardest guarantees are about what happens when a process dies at
// an inconvenient instant. Proving those guarantees needs the death to land at
// a chosen barrier, so the runtime exposes a small set of named injection
// points. Injection is disabled unless a process is started with an explicit
// specification, and every action is reported in the README.

#ifndef SMF_FAULT_INJECTION_HPP
#define SMF_FAULT_INJECTION_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

#include "smf/status.hpp"

namespace smf {

enum class FaultAction : std::uint8_t {
  NONE = 0,
  EXIT_NOW = 1,  // abrupt process death: no unwinding, no flush, no destructors
  HOLD = 2,      // block forever at the point so an external killer can land there
};

[[nodiscard]] const char* to_string(FaultAction action) noexcept;

// Named injection points. Adding one is a deliberate act: each is documented and
// each is referenced by at least one proof.
namespace fault_points {
inline constexpr std::string_view kSourceAfterChunkSend = "source.after_chunk_send";
inline constexpr std::string_view kSourceBeforeEnd = "source.before_end";
inline constexpr std::string_view kDestinationAfterChunkWrite = "destination.after_chunk_write";
inline constexpr std::string_view kDestinationBeforeMarker = "destination.before_commit_marker";
inline constexpr std::string_view kDestinationAfterMarker = "destination.after_commit_marker";
inline constexpr std::string_view kDestinationBeforeAck = "destination.before_ack";
inline constexpr std::string_view kCoordinatorBeforeCommit = "coordinator.before_commit_request";
inline constexpr std::string_view kCoordinatorAfterAuthorize = "coordinator.after_authorize";
inline constexpr std::string_view kEndpointAfterRegister = "endpoint.after_register";
}  // namespace fault_points

class FaultInjector {
 public:
  [[nodiscard]] static FaultInjector& instance();

  // Specification grammar: comma separated entries of the form
  //   point=action            fire on every occurrence
  //   point@N=action          fire on the Nth occurrence only (1-based)
  // action is one of: exit, hold
  // Example: "destination.after_commit_marker@2=exit,source.before_end=hold"
  [[nodiscard]] Status configure(std::string_view specification);

  [[nodiscard]] bool enabled() const noexcept;
  [[nodiscard]] std::string specification() const;

  // Called at an injection point. Never returns when the action is EXIT_NOW.
  // Only the point name is supplied here; which occurrence fires is decided by
  // the configured specification.
  void reach(std::string_view point);

  // True when a HOLD is configured for the point; used by proofs that need to
  // know the process is parked rather than slow.
  [[nodiscard]] bool will_hold(std::string_view point) const;

 private:
  struct Rule {
    FaultAction action = FaultAction::NONE;
    bool every = true;
    std::uint64_t ordinal = 0;
    std::uint64_t seen = 0;
  };

  mutable std::mutex mutex_;
  std::map<std::string, Rule> rules_;
  std::string specification_;
};

// Convenience: reach a point on the process-wide injector.
inline void fault_point(std::string_view point) { FaultInjector::instance().reach(point); }

}  // namespace smf

#endif  // SMF_FAULT_INJECTION_HPP
