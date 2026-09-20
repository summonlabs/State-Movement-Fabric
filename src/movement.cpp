// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/movement.hpp"

namespace smf {
namespace {

struct Transition {
  MovementState from;
  MovementState to;
};

// The complete transition relation. Everything not listed here is illegal and
// is reported as ILLEGAL_TRANSITION with the exact pair.
constexpr Transition kTransitions[] = {
    {MovementState::PLANNED, MovementState::AUTHORIZED},
    {MovementState::PLANNED, MovementState::CANCELLED},
    {MovementState::PLANNED, MovementState::FAILED},
    {MovementState::PLANNED, MovementState::SUPERSEDED},

    {MovementState::AUTHORIZED, MovementState::TRANSFERRING},
    {MovementState::AUTHORIZED, MovementState::CANCELLED},
    {MovementState::AUTHORIZED, MovementState::FAILED},
    {MovementState::AUTHORIZED, MovementState::SUPERSEDED},
    {MovementState::AUTHORIZED, MovementState::OUTCOME_UNKNOWN},

    {MovementState::TRANSFERRING, MovementState::BYTES_ARRIVED},
    {MovementState::TRANSFERRING, MovementState::CANCELLED},
    {MovementState::TRANSFERRING, MovementState::FAILED},
    {MovementState::TRANSFERRING, MovementState::SUPERSEDED},
    {MovementState::TRANSFERRING, MovementState::OUTCOME_UNKNOWN},

    // A retry after bytes arrived but failed independent verification: the
    // staged bytes are not authority, so a fresh attempt re-transfers them.
    {MovementState::BYTES_ARRIVED, MovementState::TRANSFERRING},
    {MovementState::BYTES_ARRIVED, MovementState::VERIFIED},
    {MovementState::BYTES_ARRIVED, MovementState::CANCELLED},
    {MovementState::BYTES_ARRIVED, MovementState::FAILED},
    {MovementState::BYTES_ARRIVED, MovementState::SUPERSEDED},
    {MovementState::BYTES_ARRIVED, MovementState::OUTCOME_UNKNOWN},

    {MovementState::VERIFIED, MovementState::COMMITTED},
    {MovementState::VERIFIED, MovementState::CANCELLED},
    {MovementState::VERIFIED, MovementState::FAILED},
    {MovementState::VERIFIED, MovementState::SUPERSEDED},
    {MovementState::VERIFIED, MovementState::OUTCOME_UNKNOWN},

    // OUTCOME_UNKNOWN is resolved only by reconciliation, which supplies proof
    // for whichever resolution it chooses.
    {MovementState::OUTCOME_UNKNOWN, MovementState::COMMITTED},
    {MovementState::OUTCOME_UNKNOWN, MovementState::FAILED},
    {MovementState::OUTCOME_UNKNOWN, MovementState::CANCELLED},
    {MovementState::OUTCOME_UNKNOWN, MovementState::SUPERSEDED},
};

}  // namespace

const char* to_string(MovementState state) noexcept {
  switch (state) {
    case MovementState::PLANNED:
      return "PLANNED";
    case MovementState::AUTHORIZED:
      return "AUTHORIZED";
    case MovementState::TRANSFERRING:
      return "TRANSFERRING";
    case MovementState::BYTES_ARRIVED:
      return "BYTES_ARRIVED";
    case MovementState::VERIFIED:
      return "VERIFIED";
    case MovementState::COMMITTED:
      return "COMMITTED";
    case MovementState::CANCELLED:
      return "CANCELLED";
    case MovementState::FAILED:
      return "FAILED";
    case MovementState::OUTCOME_UNKNOWN:
      return "OUTCOME_UNKNOWN";
    case MovementState::SUPERSEDED:
      return "SUPERSEDED";
  }
  return "UNRECOGNIZED_MOVEMENT_STATE";
}

bool movement_state_from_string(std::string_view text, MovementState& out) noexcept {
  constexpr MovementState kAll[] = {
      MovementState::PLANNED,        MovementState::AUTHORIZED,      MovementState::TRANSFERRING,
      MovementState::BYTES_ARRIVED,  MovementState::VERIFIED,        MovementState::COMMITTED,
      MovementState::CANCELLED,      MovementState::FAILED,          MovementState::OUTCOME_UNKNOWN,
      MovementState::SUPERSEDED};
  for (const MovementState state : kAll) {
    if (text == to_string(state)) {
      out = state;
      return true;
    }
  }
  return false;
}

bool is_terminal(MovementState state) noexcept {
  switch (state) {
    case MovementState::COMMITTED:
    case MovementState::CANCELLED:
    case MovementState::FAILED:
    case MovementState::SUPERSEDED:
      return true;
    default:
      return false;
  }
}

bool is_active(MovementState state) noexcept {
  switch (state) {
    case MovementState::PLANNED:
    case MovementState::AUTHORIZED:
    case MovementState::TRANSFERRING:
    case MovementState::BYTES_ARRIVED:
    case MovementState::VERIFIED:
    case MovementState::OUTCOME_UNKNOWN:
      return true;
    default:
      return false;
  }
}

bool is_committed(MovementState state) noexcept { return state == MovementState::COMMITTED; }

Status check_transition(MovementState from, MovementState to) {
  if (is_terminal(from)) {
    return Status(ReasonCode::ALREADY_TERMINAL,
                  std::string("movement is already terminal in state ") + to_string(from));
  }
  for (const Transition& transition : kTransitions) {
    if (transition.from == from && transition.to == to) return Status::success();
  }
  return Status(ReasonCode::ILLEGAL_TRANSITION, std::string("cannot move from ") + to_string(from) +
                                                    " to " + to_string(to));
}

const char* describe_transitions(MovementState from) noexcept {
  switch (from) {
    case MovementState::PLANNED:
      return "AUTHORIZED, CANCELLED, FAILED, SUPERSEDED";
    case MovementState::AUTHORIZED:
      return "TRANSFERRING, CANCELLED, FAILED, SUPERSEDED, OUTCOME_UNKNOWN";
    case MovementState::TRANSFERRING:
      return "BYTES_ARRIVED, CANCELLED, FAILED, SUPERSEDED, OUTCOME_UNKNOWN";
    case MovementState::BYTES_ARRIVED:
      return "VERIFIED, TRANSFERRING (retry), CANCELLED, FAILED, SUPERSEDED, OUTCOME_UNKNOWN";
    case MovementState::VERIFIED:
      return "COMMITTED, CANCELLED, FAILED, SUPERSEDED, OUTCOME_UNKNOWN";
    case MovementState::OUTCOME_UNKNOWN:
      return "COMMITTED, FAILED, CANCELLED, SUPERSEDED";
    case MovementState::COMMITTED:
    case MovementState::CANCELLED:
    case MovementState::FAILED:
    case MovementState::SUPERSEDED:
      return "none: terminal";
  }
  return "unrecognized";
}

Status MovementRecord::validate() const {
  if (id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "movement id must not be zero");
  }
  if (!generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "movement generation must be non-zero");
  }
  const Status object_status = object.validate();
  if (!object_status.ok()) return object_status;

  if (source.empty() || destination.empty()) {
    return Status(ReasonCode::INVALID_ID, "movement must name a source and a destination");
  }
  if (source == destination) {
    return Status(ReasonCode::SELF_MOVEMENT, "source and destination endpoints are the same");
  }
  if (!source_incarnation.is_set() || !destination_incarnation.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION, "movement must bind both endpoint incarnations");
  }
  if (source_incarnation.endpoint() != source) {
    return Status(ReasonCode::STALE_INCARNATION, "source incarnation names a different endpoint");
  }
  if (destination_incarnation.endpoint() != destination) {
    return Status(ReasonCode::STALE_INCARNATION,
                  "destination incarnation names a different endpoint");
  }
  if (!topology_generation.is_set() || !policy_generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION,
                  "movement must record the topology and policy generations it was decided under");
  }
  if (attempt_count > kMaxAttemptsHardLimit) {
    return Status(ReasonCode::ATTEMPT_EXHAUSTED, "movement records more attempts than are permitted");
  }
  if (chunks_verified > object.chunk_count) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "movement claims more verified chunks than exist");
  }
  if (is_committed(state) && commit_marker_digest.is_zero()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "a committed movement must record the digest of its commit marker");
  }
  if (last_detail.size() > kMaxDetailBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "movement detail exceeds the text bound");
  }
  return Status::success();
}

void MovementRecord::encode(CanonicalEncoder& encoder) const {
  id.encode(encoder);
  encoder.u64(generation.value());
  object.encode(encoder);
  encoder.text(source.value());
  encoder.text(destination.value());
  encoder.text(source_incarnation.endpoint().value());
  source_incarnation.boot().encode(encoder);
  encoder.u64(source_incarnation.epoch().value());
  encoder.text(destination_incarnation.endpoint().value());
  destination_incarnation.boot().encode(encoder);
  encoder.u64(destination_incarnation.epoch().value());
  encoder.u64(compatibility_generation.value());
  encoder.digest(compatibility_evidence);
  encoder.u64(topology_generation.value());
  encoder.u64(policy_generation.value());
  encoder.u8(static_cast<std::uint8_t>(state));
  encoder.u16(static_cast<std::uint16_t>(last_reason));
  encoder.text(last_detail);
  attempt.encode(encoder);
  encoder.u32(attempt_count);
  encoder.u64(bytes_transferred);
  encoder.u32(chunks_verified);
  encoder.digest(source_verified_digest);
  encoder.digest(destination_verified_digest);
  encoder.digest(commit_marker_digest);
  encoder.i64(created_unix_millis);
  encoder.i64(updated_unix_millis);
  encoder.boolean(repeatable);
  encoder.boolean(cancel_requested);
  provenance.encode(encoder);
}

Result<MovementRecord> MovementRecord::decode(CanonicalDecoder& decoder) {
  MovementRecord record;

  const auto id = MovementId::decode(decoder);
  if (!id.ok()) return id.status();
  record.id = id.value();

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  record.generation = MovementGeneration(generation.value());

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  record.object = object.value();

  const auto source = decoder.text(kMaxEndpointIdBytes);
  if (!source.ok()) return source.status();
  const auto source_id = EndpointId::parse(source.value());
  if (!source_id.ok()) return source_id.status();
  record.source = source_id.value();

  const auto destination = decoder.text(kMaxEndpointIdBytes);
  if (!destination.ok()) return destination.status();
  const auto destination_id = EndpointId::parse(destination.value());
  if (!destination_id.ok()) return destination_id.status();
  record.destination = destination_id.value();

  const auto source_endpoint = decoder.text(kMaxEndpointIdBytes);
  if (!source_endpoint.ok()) return source_endpoint.status();
  const auto source_boot = BootId::decode(decoder);
  if (!source_boot.ok()) return source_boot.status();
  const auto source_epoch = decoder.u64();
  if (!source_epoch.ok()) return source_epoch.status();

  const auto destination_endpoint = decoder.text(kMaxEndpointIdBytes);
  if (!destination_endpoint.ok()) return destination_endpoint.status();
  const auto destination_boot = BootId::decode(decoder);
  if (!destination_boot.ok()) return destination_boot.status();
  const auto destination_epoch = decoder.u64();
  if (!destination_epoch.ok()) return destination_epoch.status();

  const auto source_parsed = EndpointId::parse(source_endpoint.value());
  if (!source_parsed.ok()) return source_parsed.status();
  const auto destination_parsed = EndpointId::parse(destination_endpoint.value());
  if (!destination_parsed.ok()) return destination_parsed.status();

  const auto source_incarnation =
      SourceIncarnation::make(source_parsed.value(), source_boot.value(),
                              IncarnationEpoch(source_epoch.value()));
  if (!source_incarnation.ok()) return source_incarnation.status();
  record.source_incarnation = source_incarnation.value();

  const auto destination_incarnation = DestinationIncarnation::make(
      destination_parsed.value(), destination_boot.value(),
      IncarnationEpoch(destination_epoch.value()));
  if (!destination_incarnation.ok()) return destination_incarnation.status();
  record.destination_incarnation = destination_incarnation.value();

  const auto compatibility_generation = decoder.u64();
  if (!compatibility_generation.ok()) return compatibility_generation.status();
  record.compatibility_generation = CompatibilityGeneration(compatibility_generation.value());

  const auto compatibility_evidence = decoder.digest();
  if (!compatibility_evidence.ok()) return compatibility_evidence.status();
  record.compatibility_evidence = compatibility_evidence.value();

  const auto topology_generation = decoder.u64();
  if (!topology_generation.ok()) return topology_generation.status();
  record.topology_generation = TopologyGeneration(topology_generation.value());

  const auto policy_generation = decoder.u64();
  if (!policy_generation.ok()) return policy_generation.status();
  record.policy_generation = PolicyGeneration(policy_generation.value());

  const auto state = decoder.u8();
  if (!state.ok()) return state.status();
  if (state.value() > static_cast<std::uint8_t>(MovementState::SUPERSEDED)) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "recorded movement state is not recognized");
  }
  record.state = static_cast<MovementState>(state.value());

  const auto reason = decoder.u16();
  if (!reason.ok()) return reason.status();
  record.last_reason = static_cast<ReasonCode>(reason.value());

  const auto detail = decoder.text(kMaxDetailBytes);
  if (!detail.ok()) return detail.status();
  record.last_detail = std::string(detail.value());

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  record.attempt = attempt.value();

  const auto attempt_count = decoder.u32();
  if (!attempt_count.ok()) return attempt_count.status();
  record.attempt_count = attempt_count.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  record.bytes_transferred = bytes.value();

  const auto chunks = decoder.u32();
  if (!chunks.ok()) return chunks.status();
  record.chunks_verified = chunks.value();

  const auto source_digest = decoder.digest();
  if (!source_digest.ok()) return source_digest.status();
  record.source_verified_digest = source_digest.value();

  const auto destination_digest = decoder.digest();
  if (!destination_digest.ok()) return destination_digest.status();
  record.destination_verified_digest = destination_digest.value();

  const auto marker = decoder.digest();
  if (!marker.ok()) return marker.status();
  record.commit_marker_digest = marker.value();

  const auto created = decoder.i64();
  if (!created.ok()) return created.status();
  record.created_unix_millis = created.value();

  const auto updated = decoder.i64();
  if (!updated.ok()) return updated.status();
  record.updated_unix_millis = updated.value();

  const auto repeatable = decoder.boolean();
  if (!repeatable.ok()) return repeatable.status();
  record.repeatable = repeatable.value();

  const auto cancel_requested = decoder.boolean();
  if (!cancel_requested.ok()) return cancel_requested.status();
  record.cancel_requested = cancel_requested.value();

  const auto provenance = ProvenanceChain::decode(decoder);
  if (!provenance.ok()) return provenance.status();
  record.provenance = provenance.value();

  const Status status = record.validate();
  if (!status.ok()) return status;
  return record;
}

Digest MovementRecord::record_digest() const {
  CanonicalEncoder encoder("SMF-MOVEMENT-RECORD-v1");
  encode(encoder);
  return canonical_digest(encoder);
}

Status apply_transition(MovementRecord& record, MovementState next, MovementDecision decision,
                        ProvenanceEventKind kind, Millis now) {
  const Status legality = check_transition(record.state, next);
  if (!legality.ok()) {
    record.last_reason = legality.code();
    record.last_detail = legality.message();
    (void)record.provenance.append(ProvenanceEventKind::STALE_REJECTED, record.state, record.generation,
                                   legality.code(), now, legality.message());
    return legality;
  }

  const auto advanced = record.generation.next();
  if (!advanced.ok()) return advanced.status();
  record.generation = advanced.value();

  record.state = next;
  record.last_reason = decision.code;
  record.last_detail = decision.detail;
  record.updated_unix_millis = now;

  ProvenanceEvent event;
  event.sequence = record.provenance.next_sequence();
  event.unix_millis = now;
  event.kind = kind;
  event.state = next;
  event.movement_generation = record.generation;
  event.reason = decision.code;
  event.detail = decision.detail;
  return record.provenance.append(std::move(event));
}

Status record_attempt_started(MovementRecord& record, TransferAttemptId attempt, Millis now) {
  if (is_terminal(record.state)) {
    return Status(ReasonCode::ALREADY_TERMINAL, "movement is already terminal");
  }
  const auto advanced = record.generation.next();
  if (!advanced.ok()) return advanced.status();
  record.generation = advanced.value();
  record.attempt = attempt;
  record.attempt_count += 1;
  record.updated_unix_millis = now;

  ProvenanceEvent event;
  event.sequence = record.provenance.next_sequence();
  event.unix_millis = now;
  event.kind = ProvenanceEventKind::ATTEMPT_STARTED;
  event.state = record.state;
  event.movement_generation = record.generation;
  event.reason = ReasonCode::OK;
  event.attempt = attempt;
  event.detail = "attempt " + std::to_string(record.attempt_count);
  return record.provenance.append(std::move(event));
}

MovementDecision evaluate_supersession(const MovementRecord& record,
                                       const StateObjectDescriptor& current) {
  if (!current.same_object(record.object)) {
    return MovementDecision::deny(ReasonCode::STALE_STATE_GENERATION,
                                  "source announced a different state object");
  }
  if (current.generation > record.object.generation) {
    return MovementDecision::deny(ReasonCode::MOVEMENT_SUPERSEDED,
                                  "source state generation advanced from " +
                                      std::to_string(record.object.generation.value()) + " to " +
                                      std::to_string(current.generation.value()));
  }
  if (current.content_digest != record.object.content_digest) {
    return MovementDecision::deny(ReasonCode::STALE_STATE_GENERATION,
                                  "source content digest changed for the same generation");
  }
  return MovementDecision::allow();
}

std::string summarize(const MovementRecord& record) {
  std::string out = record.id.hex().substr(0, 12);
  out += " ";
  out += to_string(record.state);
  out += " gen=";
  out += std::to_string(record.object.generation.value());
  out += " ";
  out += record.source.value();
  out += "->";
  out += record.destination.value();
  out += " attempts=";
  out += std::to_string(record.attempt_count);
  out += " bytes=";
  out += std::to_string(record.bytes_transferred);
  out += " reason=";
  out += to_string(record.last_reason);
  return out;
}

}  // namespace smf
