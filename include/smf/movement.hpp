// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The movement transaction record. It carries every generation and incarnation
// that the decision to move was made under, so that a stale decision can be
// recognised later without re-deriving anything.

#ifndef SMF_MOVEMENT_HPP
#define SMF_MOVEMENT_HPP

#include <cstdint>
#include <string>

#include "smf/codec.hpp"
#include "smf/ids.hpp"
#include "smf/movement_state.hpp"
#include "smf/policy.hpp"
#include "smf/provenance.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"

namespace smf {

// A decision is always a code plus an explanation. There is no boolean
// authority answer anywhere in the public API.
struct MovementDecision {
  bool allowed = false;
  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] static MovementDecision allow() noexcept { return MovementDecision{true, ReasonCode::OK, {}}; }
  [[nodiscard]] static MovementDecision allow(ReasonCode code, std::string detail) {
    return MovementDecision{true, code, std::move(detail)};
  }
  [[nodiscard]] static MovementDecision deny(ReasonCode code, std::string detail) {
    return MovementDecision{false, code, std::move(detail)};
  }

  [[nodiscard]] bool ok() const noexcept { return allowed; }
  [[nodiscard]] Status status() const { return allowed ? Status::success() : Status(code, detail); }
};

struct MovementRecord {
  MovementId id;
  // Fencing token. Advances on every accepted transition, so a late report
  // computed against an older revision is rejected rather than applied.
  MovementGeneration generation;

  StateObjectDescriptor object;

  EndpointId source;
  EndpointId destination;
  SourceIncarnation source_incarnation;
  DestinationIncarnation destination_incarnation;

  CompatibilityGeneration compatibility_generation;
  Digest compatibility_evidence;
  TopologyGeneration topology_generation;
  PolicyGeneration policy_generation;

  MovementState state = MovementState::PLANNED;
  ReasonCode last_reason = ReasonCode::OK;
  std::string last_detail;

  TransferAttemptId attempt;
  std::uint32_t attempt_count = 0;
  std::uint64_t bytes_transferred = 0;
  std::uint32_t chunks_verified = 0;

  Digest source_verified_digest;
  Digest destination_verified_digest;
  Digest commit_marker_digest;

  Millis created_unix_millis = 0;
  Millis updated_unix_millis = 0;

  bool repeatable = true;
  bool cancel_requested = false;

  ProvenanceChain provenance;

  [[nodiscard]] Status validate() const;
  [[nodiscard]] bool is_terminal() const noexcept { return smf::is_terminal(state); }

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementRecord> decode(CanonicalDecoder& decoder);

  // Digest over the whole record as stored, used to detect store tampering.
  [[nodiscard]] Digest record_digest() const;
};

// Applies a transition. The state machine decides legality; this function
// records the decision, advances the movement generation, and appends exactly
// one provenance event. Nothing else in the runtime mutates record.state.
[[nodiscard]] Status apply_transition(MovementRecord& record, MovementState next,
                                      MovementDecision decision, ProvenanceEventKind kind,
                                      Millis now);

// Convenience for recording an attempt start, which advances the attempt
// identity and appends provenance without changing the movement state.
[[nodiscard]] Status record_attempt_started(MovementRecord& record, TransferAttemptId attempt,
                                            Millis now);

// True when the descriptor supplied by the source is no longer the version the
// movement was authorized to move.
[[nodiscard]] MovementDecision evaluate_supersession(const MovementRecord& record,
                                                     const StateObjectDescriptor& current);

// Short single-line summary for the CLI.
[[nodiscard]] std::string summarize(const MovementRecord& record);

}  // namespace smf

#endif  // SMF_MOVEMENT_HPP
