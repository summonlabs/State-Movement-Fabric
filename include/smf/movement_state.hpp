// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The movement transaction state machine, in isolation from everything else so
// that its semantics can be proven without a network, a store, or a clock.

#ifndef SMF_MOVEMENT_STATE_HPP
#define SMF_MOVEMENT_STATE_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "smf/status.hpp"

namespace smf {

enum class MovementState : std::uint8_t {
  PLANNED = 0,
  AUTHORIZED = 1,
  TRANSFERRING = 2,
  BYTES_ARRIVED = 3,
  VERIFIED = 4,
  COMMITTED = 5,
  CANCELLED = 6,
  FAILED = 7,
  OUTCOME_UNKNOWN = 8,
  SUPERSEDED = 9,
};

[[nodiscard]] const char* to_string(MovementState state) noexcept;
[[nodiscard]] bool movement_state_from_string(std::string_view text, MovementState& out) noexcept;

// Terminal states admit no further transition. OUTCOME_UNKNOWN is deliberately
// not terminal: it is a claim about knowledge, not about outcome, and only
// reconciliation may resolve it.
[[nodiscard]] bool is_terminal(MovementState state) noexcept;

// True while the movement still holds a claim on transfer resources.
[[nodiscard]] bool is_active(MovementState state) noexcept;

[[nodiscard]] bool is_committed(MovementState state) noexcept;

// Deterministic legality of a transition. Returns OK when permitted and
// ILLEGAL_TRANSITION with an explanatory message otherwise.
[[nodiscard]] Status check_transition(MovementState from, MovementState to);

// Every state reachable in one legal step from the given state.
[[nodiscard]] const char* describe_transitions(MovementState from) noexcept;

}  // namespace smf

#endif  // SMF_MOVEMENT_STATE_HPP
