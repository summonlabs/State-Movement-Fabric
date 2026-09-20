// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/provenance.hpp"

#include <algorithm>

namespace smf {

const char* to_string(ProvenanceEventKind kind) noexcept {
  switch (kind) {
    case ProvenanceEventKind::CREATED:
      return "CREATED";
    case ProvenanceEventKind::AUTHORIZED:
      return "AUTHORIZED";
    case ProvenanceEventKind::GRANT_ISSUED:
      return "GRANT_ISSUED";
    case ProvenanceEventKind::ATTEMPT_STARTED:
      return "ATTEMPT_STARTED";
    case ProvenanceEventKind::PROGRESS:
      return "PROGRESS";
    case ProvenanceEventKind::BYTES_ARRIVED:
      return "BYTES_ARRIVED";
    case ProvenanceEventKind::VERIFIED:
      return "VERIFIED";
    case ProvenanceEventKind::COMMIT_REQUESTED:
      return "COMMIT_REQUESTED";
    case ProvenanceEventKind::COMMITTED:
      return "COMMITTED";
    case ProvenanceEventKind::CANCELLED:
      return "CANCELLED";
    case ProvenanceEventKind::FAILED:
      return "FAILED";
    case ProvenanceEventKind::OUTCOME_UNKNOWN:
      return "OUTCOME_UNKNOWN";
    case ProvenanceEventKind::SUPERSEDED:
      return "SUPERSEDED";
    case ProvenanceEventKind::RECONCILED:
      return "RECONCILED";
    case ProvenanceEventKind::RETRY_SCHEDULED:
      return "RETRY_SCHEDULED";
    case ProvenanceEventKind::STALE_REJECTED:
      return "STALE_REJECTED";
    case ProvenanceEventKind::CLEANED:
      return "CLEANED";
    case ProvenanceEventKind::QUARANTINED:
      return "QUARANTINED";
  }
  return "UNRECOGNIZED_PROVENANCE_KIND";
}

bool provenance_kind_from_string(std::string_view text, ProvenanceEventKind& out) noexcept {
  for (std::uint8_t value = 0; value <= static_cast<std::uint8_t>(ProvenanceEventKind::QUARANTINED);
       ++value) {
    const auto kind = static_cast<ProvenanceEventKind>(value);
    if (text == to_string(kind)) {
      out = kind;
      return true;
    }
  }
  return false;
}

Status ProvenanceEvent::validate() const {
  if (sequence == 0) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance sequence must start at one");
  }
  if (unix_millis <= 0) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance event requires a timestamp");
  }
  if (!movement_generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "provenance event requires a movement generation");
  }
  if (detail.size() > kMaxDetailBytes) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance detail exceeds the text bound");
  }
  if (!detail.empty() && !is_valid_utf8(as_bytes(detail))) {
    return Status(ReasonCode::INVALID_UTF8, "provenance detail is not valid UTF-8");
  }
  return Status::success();
}

void ProvenanceEvent::encode(CanonicalEncoder& encoder) const {
  encoder.u64(sequence);
  encoder.i64(unix_millis);
  encoder.u8(static_cast<std::uint8_t>(kind));
  encoder.u8(static_cast<std::uint8_t>(state));
  encoder.u64(movement_generation.value());
  encoder.u16(static_cast<std::uint16_t>(reason));
  encoder.text(actor.value());
  actor_boot.encode(encoder);
  encoder.u64(actor_epoch.value());
  attempt.encode(encoder);
  encoder.digest(evidence);
  encoder.text(detail);
}

Result<ProvenanceEvent> ProvenanceEvent::decode(CanonicalDecoder& decoder) {
  ProvenanceEvent event;

  const auto sequence = decoder.u64();
  if (!sequence.ok()) return sequence.status();
  event.sequence = sequence.value();

  const auto time = decoder.i64();
  if (!time.ok()) return time.status();
  event.unix_millis = time.value();

  const auto kind = decoder.u8();
  if (!kind.ok()) return kind.status();
  if (kind.value() > static_cast<std::uint8_t>(ProvenanceEventKind::QUARANTINED)) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance kind is not recognized");
  }
  event.kind = static_cast<ProvenanceEventKind>(kind.value());

  const auto state = decoder.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(MovementState::SUPERSEDED)) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance movement state is not recognized");
  }
  event.state = static_cast<MovementState>(state.value());

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  event.movement_generation = MovementGeneration(generation.value());

  const auto reason = decoder.u16();
  if (!reason.ok()) return reason.status();
  event.reason = static_cast<ReasonCode>(reason.value());

  const auto actor = decoder.text(kMaxEndpointIdBytes);
  if (!actor.ok()) return actor.status();
  if (!actor.value().empty()) {
    const auto parsed = EndpointId::parse(actor.value());
    if (!parsed.ok()) return parsed.status();
    event.actor = parsed.value();
  }

  const auto boot = BootId::decode(decoder);
  if (!boot.ok()) return boot.status();
  event.actor_boot = boot.value();

  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  event.actor_epoch = IncarnationEpoch(epoch.value());

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  event.attempt = attempt.value();

  const auto evidence = decoder.digest();
  if (!evidence.ok()) return evidence.status();
  event.evidence = evidence.value();

  const auto detail = decoder.text(kMaxDetailBytes);
  if (!detail.ok()) return detail.status();
  event.detail = std::string(detail.value());

  const Status status = event.validate();
  if (!status.ok()) return status;
  return event;
}

Status ProvenanceChain::append(ProvenanceEvent event) {
  if (events_.size() >= bound_) {
    return Status(ReasonCode::HISTORY_LIMIT_REACHED,
                  "provenance bound reached; the movement's history is already complete");
  }
  if (event.sequence == 0) {
    event.sequence = next_sequence();
  }
  if (event.sequence != next_sequence()) {
    return Status(ReasonCode::STORE_RECORD_INVALID,
                  "provenance events must be appended with contiguous sequences");
  }
  const Status status = event.validate();
  if (!status.ok()) return status;
  events_.push_back(std::move(event));
  return Status::success();
}

Status ProvenanceChain::append(ProvenanceEventKind kind, MovementState state,
                               MovementGeneration generation, ReasonCode reason, Millis now,
                               std::string detail) {
  ProvenanceEvent event;
  event.sequence = next_sequence();
  event.unix_millis = now;
  event.kind = kind;
  event.state = state;
  event.movement_generation = generation;
  event.reason = reason;
  event.detail = std::move(detail);
  return append(std::move(event));
}

void ProvenanceChain::set_bound(std::size_t bound) noexcept {
  bound_ = bound == 0 ? 1 : (bound > kMaxProvenanceEvents ? kMaxProvenanceEvents : bound);
}

const ProvenanceEvent* ProvenanceChain::last_of(ProvenanceEventKind kind) const noexcept {
  for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
    if (it->kind == kind) return &*it;
  }
  return nullptr;
}

void ProvenanceChain::encode(CanonicalEncoder& encoder) const {
  encoder.u32(static_cast<std::uint32_t>(events_.size()));
  for (const ProvenanceEvent& event : events_) {
    event.encode(encoder);
  }
}

Result<ProvenanceChain> ProvenanceChain::decode(CanonicalDecoder& decoder) {
  ProvenanceChain chain;
  const auto count = decoder.count(kMaxProvenanceEvents);
  if (!count.ok()) return count.status();

  for (std::size_t i = 0; i < count.value(); ++i) {
    const auto event = ProvenanceEvent::decode(decoder);
    if (!event.ok()) return event.status();
    if (event.value().sequence != i + 1U) {
      return Status(ReasonCode::STORE_RECORD_INVALID,
                    "provenance chain is not contiguous or is out of order");
    }
    const Status status = chain.append(event.value());
    if (!status.ok()) return status;
  }
  if (chain.size() > chain.bound()) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "provenance chain exceeds its bound");
  }
  return chain;
}

}  // namespace smf
