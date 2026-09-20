// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Downstream consumer. It uses only installed headers and the exported target,
// and it checks behaviour that a consumer would actually depend on.

#include <cstdio>
#include <string>

#include <smf/chunk_plan.hpp>
#include <smf/digest.hpp>
#include <smf/movement.hpp>
#include <smf/state_object.hpp>
#include <smf/version.hpp>

int main() {
  std::printf("linked against State Movement Fabric %s (protocol %u)\n",
              std::string(smf::kVersionString).c_str(),
              static_cast<unsigned>(smf::kProtocolVersion));

  const auto object_id = smf::derive_state_object_id(smf::StateKind::MODEL, "consumer/demo");
  if (!object_id.ok()) {
    std::fprintf(stderr, "%s\n", object_id.status().to_string().c_str());
    return 1;
  }

  const std::string payload(64 * 1024, 'c');
  const auto descriptor = smf::StateObjectDescriptor::create(
      smf::StateKind::MODEL, "consumer/demo", smf::StateGeneration(1),
      smf::sha256(payload), payload.size(), 16 * 1024, smf::system_clock().unix_millis(),
      "consumer");
  if (!descriptor.ok()) {
    std::fprintf(stderr, "%s\n", descriptor.status().to_string().c_str());
    return 1;
  }

  const auto plan = smf::ChunkPlan::create(descriptor.value());
  if (!plan.ok()) {
    std::fprintf(stderr, "%s\n", plan.status().to_string().c_str());
    return 1;
  }
  if (plan.value().chunk_count() != 4) {
    std::fprintf(stderr, "unexpected segmentation: %u chunks\n", plan.value().chunk_count());
    return 1;
  }

  // Deterministic denial: a transition out of a terminal state must be refused
  // with a stable code rather than silently accepted.
  const smf::Status refused =
      smf::check_transition(smf::MovementState::COMMITTED, smf::MovementState::TRANSFERRING);
  if (refused.ok() || refused.code() != smf::ReasonCode::ALREADY_TERMINAL) {
    std::fprintf(stderr, "expected ALREADY_TERMINAL, got %s\n", refused.to_string().c_str());
    return 1;
  }

  std::printf("state object %s with %u chunks; terminal transitions refused as %s\n",
              object_id.value().hex().substr(0, 16).c_str(), plan.value().chunk_count(),
              smf::to_string(refused.code()));
  return 0;
}
