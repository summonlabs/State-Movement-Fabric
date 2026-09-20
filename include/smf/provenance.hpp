// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Movement provenance: an append-only, bounded record of who did what to a
// movement, in order, with the reason code and the evidence digest for each
// step. Provenance is what makes a completed movement explainable after the
// fact, and it is retained for completed movements only.

#ifndef SMF_PROVENANCE_HPP
#define SMF_PROVENANCE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "smf/codec.hpp"
#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/movement_state.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"

namespace smf {

enum class ProvenanceEventKind : std::uint8_t {
  CREATED = 0,
  AUTHORIZED = 1,
  GRANT_ISSUED = 2,
  ATTEMPT_STARTED = 3,
  PROGRESS = 4,
  BYTES_ARRIVED = 5,
  VERIFIED = 6,
  COMMIT_REQUESTED = 7,
  COMMITTED = 8,
  CANCELLED = 9,
  FAILED = 10,
  OUTCOME_UNKNOWN = 11,
  SUPERSEDED = 12,
  RECONCILED = 13,
  RETRY_SCHEDULED = 14,
  STALE_REJECTED = 15,
  CLEANED = 16,
  QUARANTINED = 17,
};

[[nodiscard]] const char* to_string(ProvenanceEventKind kind) noexcept;
[[nodiscard]] bool provenance_kind_from_string(std::string_view text, ProvenanceEventKind& out) noexcept;

struct ProvenanceEvent {
  std::uint64_t sequence = 0;
  Millis unix_millis = 0;
  ProvenanceEventKind kind = ProvenanceEventKind::CREATED;
  MovementState state = MovementState::PLANNED;
  MovementGeneration movement_generation;
  ReasonCode reason = ReasonCode::OK;
  EndpointId actor;
  BootId actor_boot;
  IncarnationEpoch actor_epoch;
  TransferAttemptId attempt;
  Digest evidence;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ProvenanceEvent> decode(CanonicalDecoder& decoder);
};

// Bounded append-only chain. Appending past the bound is refused rather than
// silently dropping history, so that a movement either has complete provenance
// or reports that it does not.
class ProvenanceChain {
 public:
  ProvenanceChain() = default;

  [[nodiscard]] Status append(ProvenanceEvent event);
  [[nodiscard]] Status append(ProvenanceEventKind kind, MovementState state,
                              MovementGeneration generation, ReasonCode reason, Millis now,
                              std::string detail);

  [[nodiscard]] const std::vector<ProvenanceEvent>& events() const noexcept { return events_; }
  [[nodiscard]] std::size_t size() const noexcept { return events_.size(); }
  [[nodiscard]] bool empty() const noexcept { return events_.empty(); }
  [[nodiscard]] std::uint64_t next_sequence() const noexcept {
    return static_cast<std::uint64_t>(events_.size()) + 1U;
  }
  [[nodiscard]] std::size_t bound() const noexcept { return bound_; }
  void set_bound(std::size_t bound) noexcept;

  // The last event of a given kind, if any.
  [[nodiscard]] const ProvenanceEvent* last_of(ProvenanceEventKind kind) const noexcept;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ProvenanceChain> decode(CanonicalDecoder& decoder);

 private:
  std::vector<ProvenanceEvent> events_;
  std::size_t bound_ = kMaxProvenanceEvents;
};

}  // namespace smf

#endif  // SMF_PROVENANCE_HPP
