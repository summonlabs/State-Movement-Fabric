// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical state identity, content binding, and segmentation. This example
// exercises the deterministic core only: no network, no processes.

#include <cstdio>
#include <string>

#include "smf/chunk_plan.hpp"
#include "smf/state_object.hpp"

int main() {
  const auto object_id = smf::derive_state_object_id(smf::StateKind::KV, "llama3/layer-17/kv");
  if (!object_id.ok()) {
    std::fprintf(stderr, "%s\n", object_id.status().to_string().c_str());
    return 1;
  }

  // A one-megabyte payload with a known digest, so the descriptor binds real
  // content rather than a placeholder.
  const std::string payload(1U << 20, 's');
  const smf::Digest content = smf::sha256(payload);

  const auto descriptor = smf::StateObjectDescriptor::create(
      smf::StateKind::KV, "llama3/layer-17/kv", smf::StateGeneration(4), content, payload.size(),
      256U << 10, smf::system_clock().unix_millis(), "smf-example");
  if (!descriptor.ok()) {
    std::fprintf(stderr, "%s\n", descriptor.status().to_string().c_str());
    return 1;
  }

  std::printf("object id   %s\n", descriptor.value().object_id.hex().c_str());
  std::printf("state       %s\n", smf::describe(descriptor.value()).c_str());
  std::printf("content     %s\n", descriptor.value().content_digest.hex().c_str());

  const auto plan = smf::ChunkPlan::create(descriptor.value());
  if (!plan.ok()) {
    std::fprintf(stderr, "%s\n", plan.status().to_string().c_str());
    return 1;
  }
  std::printf("segmentation %u chunks of %llu bytes\n", plan.value().chunk_count(),
              static_cast<unsigned long long>(plan.value().chunk_bytes()));

  for (std::uint32_t index = 0; index < plan.value().chunk_count(); ++index) {
    const auto offset = plan.value().offset_of(index);
    const auto length = plan.value().length_of(index);
    if (!offset.ok() || !length.ok()) return 1;
    const smf::ByteView slice(smf::as_bytes(payload).data() + offset.value(),
                              static_cast<std::size_t>(length.value()));
    const auto digest = plan.value().chunk_digest_of(index, slice);
    if (!digest.ok()) return 1;
    std::printf("  chunk %u offset %llu length %llu digest %s\n", index,
                static_cast<unsigned long long>(offset.value()),
                static_cast<unsigned long long>(length.value()),
                digest.value().hex().substr(0, 16).c_str());
  }

  // A generation bump is a different version of the same object, not a new
  // object: the identity is stable and the generation is not.
  const auto next = smf::StateObjectDescriptor::create(
      smf::StateKind::KV, "llama3/layer-17/kv", smf::StateGeneration(5), smf::sha256("newer"),
      5, 4096, smf::system_clock().unix_millis(), "smf-example");
  if (!next.ok()) return 1;
  std::printf("generation 5 is the same object: %s\n",
              next.value().same_object(descriptor.value()) ? "yes" : "no");
  std::printf("generation 5 is the same version: %s\n",
              next.value().same_version(descriptor.value()) ? "yes" : "no");
  return 0;
}
