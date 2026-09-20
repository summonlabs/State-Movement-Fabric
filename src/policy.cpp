// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/policy.hpp"

namespace smf {

Status MovementPolicy::validate() const {
  if (max_attempts == 0 || max_attempts > kMaxAttemptsHardLimit) {
    return Status(ReasonCode::INVALID_POLICY, "max_attempts must be between 1 and the hard limit");
  }
  if (max_inflight_chunks == 0 || max_inflight_chunks > 1024) {
    return Status(ReasonCode::INVALID_POLICY, "max_inflight_chunks must be between 1 and 1024");
  }
  if (min_chunk_bytes < kMinChunkBytes || min_chunk_bytes > kMaxChunkBytes) {
    return Status(ReasonCode::INVALID_POLICY, "min_chunk_bytes is outside the supported range");
  }
  if (max_chunk_bytes < min_chunk_bytes || max_chunk_bytes > kMaxChunkBytes) {
    return Status(ReasonCode::INVALID_POLICY, "max_chunk_bytes is outside the supported range");
  }
  if (max_object_bytes == 0 || max_object_bytes > kMaxObjectBytes) {
    return Status(ReasonCode::INVALID_POLICY, "max_object_bytes is outside the supported range");
  }
  if (max_movement_bytes == 0 || max_movement_bytes > kMaxObjectBytes) {
    return Status(ReasonCode::INVALID_POLICY, "max_movement_bytes is outside the supported range");
  }
  if (max_endpoints == 0 || max_endpoints > kMaxEndpoints) {
    return Status(ReasonCode::INVALID_POLICY, "max_endpoints is outside the supported range");
  }
  if (max_sessions == 0 || max_sessions > 8192) {
    return Status(ReasonCode::INVALID_POLICY, "max_sessions is outside the supported range");
  }
  if (max_movements_in_flight == 0 || max_movements_in_flight > 100000) {
    return Status(ReasonCode::INVALID_POLICY, "max_movements_in_flight is outside the supported range");
  }
  if (max_provenance_events == 0 || max_provenance_events > kMaxProvenanceEvents) {
    return Status(ReasonCode::INVALID_POLICY, "max_provenance_events is outside the supported range");
  }
  if (max_history_records == 0 || max_history_records > 10000000U) {
    return Status(ReasonCode::INVALID_POLICY, "max_history_records is outside the supported range");
  }
  if (max_store_bytes < (1ULL << 20)) {
    return Status(ReasonCode::INVALID_POLICY, "max_store_bytes is implausibly small");
  }
  if (max_staging_bytes_per_endpoint < max_chunk_bytes) {
    return Status(ReasonCode::INVALID_POLICY,
                  "staging budget must be able to hold at least one chunk");
  }
  if (verify_sample_chunks_count == 0 || verify_sample_chunks_count > 64) {
    return Status(ReasonCode::INVALID_POLICY, "verify_sample_chunks_count is outside the supported range");
  }
  if (io_budget_millis == 0 || io_budget_millis > 3600000U) {
    return Status(ReasonCode::INVALID_POLICY, "io_budget_millis is outside the supported range");
  }
  if (transfer_budget_millis == 0 || transfer_budget_millis > 86400000U) {
    return Status(ReasonCode::INVALID_POLICY, "transfer_budget_millis is outside the supported range");
  }
  return Status::success();
}

void MovementPolicy::encode(CanonicalEncoder& encoder) const {
  encoder.u32(max_attempts);
  encoder.u32(max_inflight_chunks);
  encoder.u64(min_chunk_bytes);
  encoder.u64(max_chunk_bytes);
  encoder.u64(max_object_bytes);
  encoder.u64(max_movement_bytes);
  encoder.u32(max_endpoints);
  encoder.u32(max_sessions);
  encoder.u32(max_movements_in_flight);
  encoder.u32(max_provenance_events);
  encoder.u32(max_history_records);
  encoder.u64(max_store_bytes);
  encoder.u64(max_staging_bytes_per_endpoint);
  encoder.boolean(allow_resume);
  encoder.boolean(require_compatibility_evidence);
  encoder.boolean(allow_unknown_kind);
  encoder.boolean(verify_sample_chunks);
  encoder.u32(verify_sample_chunks_count);
  encoder.u32(io_budget_millis);
  encoder.u32(transfer_budget_millis);
}

Result<MovementPolicy> MovementPolicy::decode(CanonicalDecoder& decoder) {
  MovementPolicy policy;

  const auto max_attempts = decoder.u32();
  if (!max_attempts.ok()) return max_attempts.status();
  policy.max_attempts = max_attempts.value();

  const auto inflight = decoder.u32();
  if (!inflight.ok()) return inflight.status();
  policy.max_inflight_chunks = inflight.value();

  const auto min_chunk = decoder.u64();
  if (!min_chunk.ok()) return min_chunk.status();
  policy.min_chunk_bytes = min_chunk.value();

  const auto max_chunk = decoder.u64();
  if (!max_chunk.ok()) return max_chunk.status();
  policy.max_chunk_bytes = max_chunk.value();

  const auto max_object = decoder.u64();
  if (!max_object.ok()) return max_object.status();
  policy.max_object_bytes = max_object.value();

  const auto max_movement = decoder.u64();
  if (!max_movement.ok()) return max_movement.status();
  policy.max_movement_bytes = max_movement.value();

  const auto max_endpoints = decoder.u32();
  if (!max_endpoints.ok()) return max_endpoints.status();
  policy.max_endpoints = max_endpoints.value();

  const auto max_sessions = decoder.u32();
  if (!max_sessions.ok()) return max_sessions.status();
  policy.max_sessions = max_sessions.value();

  const auto max_in_flight = decoder.u32();
  if (!max_in_flight.ok()) return max_in_flight.status();
  policy.max_movements_in_flight = max_in_flight.value();

  const auto max_provenance = decoder.u32();
  if (!max_provenance.ok()) return max_provenance.status();
  policy.max_provenance_events = max_provenance.value();

  const auto max_history = decoder.u32();
  if (!max_history.ok()) return max_history.status();
  policy.max_history_records = max_history.value();

  const auto max_store = decoder.u64();
  if (!max_store.ok()) return max_store.status();
  policy.max_store_bytes = max_store.value();

  const auto max_staging = decoder.u64();
  if (!max_staging.ok()) return max_staging.status();
  policy.max_staging_bytes_per_endpoint = max_staging.value();

  const auto allow_resume = decoder.boolean();
  if (!allow_resume.ok()) return allow_resume.status();
  policy.allow_resume = allow_resume.value();

  const auto require_compat = decoder.boolean();
  if (!require_compat.ok()) return require_compat.status();
  policy.require_compatibility_evidence = require_compat.value();

  const auto allow_unknown = decoder.boolean();
  if (!allow_unknown.ok()) return allow_unknown.status();
  policy.allow_unknown_kind = allow_unknown.value();

  const auto verify_sample = decoder.boolean();
  if (!verify_sample.ok()) return verify_sample.status();
  policy.verify_sample_chunks = verify_sample.value();

  const auto verify_count = decoder.u32();
  if (!verify_count.ok()) return verify_count.status();
  policy.verify_sample_chunks_count = verify_count.value();

  const auto io_budget = decoder.u32();
  if (!io_budget.ok()) return io_budget.status();
  policy.io_budget_millis = io_budget.value();

  const auto transfer_budget = decoder.u32();
  if (!transfer_budget.ok()) return transfer_budget.status();
  policy.transfer_budget_millis = transfer_budget.value();

  const Status status = policy.validate();
  if (!status.ok()) return status;
  return policy;
}

bool MovementPolicy::operator==(const MovementPolicy& other) const {
  CanonicalEncoder left;
  encode(left);
  CanonicalEncoder right;
  other.encode(right);
  return left.bytes() == right.bytes();
}

Status PolicySet::validate() const {
  if (!generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "policy generation must be non-zero");
  }
  return policy.validate();
}

Digest PolicySet::digest() const {
  CanonicalEncoder encoder("SMF-POLICY-SET-v1");
  encode(encoder);
  return canonical_digest(encoder);
}

void PolicySet::encode(CanonicalEncoder& encoder) const {
  encoder.u64(generation.value());
  policy.encode(encoder);
}

Result<PolicySet> PolicySet::decode(CanonicalDecoder& decoder) {
  PolicySet set;

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  set.generation = PolicyGeneration(generation.value());

  const auto policy = MovementPolicy::decode(decoder);
  if (!policy.ok()) return policy.status();
  set.policy = policy.value();

  const Status status = set.validate();
  if (!status.ok()) return status;
  return set;
}

}  // namespace smf
