// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The movement transaction state machine, its deterministic reason codes, and
// the rule that a destination is not authoritative because bytes exist there.

#include <cstdio>
#include <string>

#include "smf/ids.hpp"
#include "smf/movement.hpp"

namespace {

[[nodiscard]] bool advance(smf::MovementRecord& record, smf::MovementState next,
                           const char* why) {
  const smf::Status status = smf::apply_transition(
      record, next, smf::MovementDecision::allow(smf::ReasonCode::OK, why),
      smf::ProvenanceEventKind::PROGRESS, smf::system_clock().unix_millis());
  if (!status.ok()) {
    std::printf("  refused: %s\n", status.to_string().c_str());
    return false;
  }
  std::printf("  -> %-15s movement generation %llu\n", smf::to_string(record.state),
              static_cast<unsigned long long>(record.generation.value()));
  return true;
}

}  // namespace

int main() {
  smf::IdIssuer issuer;
  const auto object_id = smf::derive_state_object_id(smf::StateKind::CHECKPOINT, "run-42/step-900");
  if (!object_id.ok()) return 1;

  smf::MovementRecord record;
  record.id = issuer.new_movement_id();
  record.generation = smf::MovementGeneration(1);
  record.object = smf::StateObjectDescriptor::create(
                      smf::StateKind::CHECKPOINT, "run-42/step-900", smf::StateGeneration(7),
                      smf::sha256("checkpoint"), 8U << 20, 1U << 20,
                      smf::system_clock().unix_millis(), "smf-example")
                      .value();
  record.source = smf::EndpointId::parse("source-1").value();
  record.destination = smf::EndpointId::parse("dest-1").value();
  record.source_incarnation =
      smf::SourceIncarnation::make(record.source, issuer.new_boot_id(), smf::IncarnationEpoch(3))
          .value();
  record.destination_incarnation = smf::DestinationIncarnation::make(
                                       record.destination, issuer.new_boot_id(),
                                       smf::IncarnationEpoch(9))
                                       .value();
  record.topology_generation = smf::TopologyGeneration(4);
  record.policy_generation = smf::PolicyGeneration(1);
  record.created_unix_millis = smf::system_clock().unix_millis();
  record.updated_unix_millis = record.created_unix_millis;
  record.provenance.set_bound(32);

  std::printf("movement %s\n", record.id.hex().c_str());
  std::printf("  state %s\n", smf::to_string(record.state));

  (void)advance(record, smf::MovementState::AUTHORIZED, "authorized by the coordinator");
  (void)advance(record, smf::MovementState::TRANSFERRING, "attempt dispatched");
  (void)advance(record, smf::MovementState::BYTES_ARRIVED,
                "the destination reports verified bytes");

  std::printf("bytes exist at the destination, but the movement is %s: not authority yet\n",
              smf::to_string(record.state));

  // Committing without a verified digest is refused by the record's own rules.
  smf::MovementRecord premature = record;
  premature.state = smf::MovementState::COMMITTED;
  const smf::Status invalid = premature.validate();
  std::printf("committing without a marker digest: %s\n", invalid.to_string().c_str());

  (void)advance(record, smf::MovementState::VERIFIED,
                "the coordinator re-hashed the stored bytes");
  record.commit_marker_digest = smf::sha256("marker");
  (void)advance(record, smf::MovementState::COMMITTED,
                "the destination wrote its commit marker");

  std::printf("terminal: %s\n", record.is_terminal() ? "yes" : "no");
  std::printf("a further transition is refused: ");
  (void)advance(record, smf::MovementState::FAILED, "too late");

  std::printf("\nprovenance (%zu events)\n", record.provenance.size());
  for (const smf::ProvenanceEvent& event : record.provenance.events()) {
    std::printf("  %2llu %-14s %-15s %s\n", static_cast<unsigned long long>(event.sequence),
                smf::to_string(event.kind), smf::to_string(event.state), event.detail.c_str());
  }
  return 0;
}
