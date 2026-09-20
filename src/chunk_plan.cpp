// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/chunk_plan.hpp"

#include <algorithm>
#include <set>

#include "smf/codec.hpp"

namespace smf {

Result<ChunkPlan> ChunkPlan::create(const StateObjectDescriptor& descriptor) {
  const Status status = descriptor.validate();
  if (!status.ok()) return status;
  return ChunkPlan(descriptor);
}

Result<std::uint64_t> ChunkPlan::offset_of(std::uint32_t index) const {
  return descriptor_.chunk_offset(index);
}

Result<std::uint64_t> ChunkPlan::length_of(std::uint32_t index) const {
  return descriptor_.chunk_length(index);
}

Result<Digest> ChunkPlan::chunk_digest_of(std::uint32_t index, ByteView payload) const {
  const auto offset = descriptor_.chunk_offset(index);
  if (!offset.ok()) return offset.status();
  const auto length = descriptor_.chunk_length(index);
  if (!length.ok()) return length.status();
  if (payload.size() != length.value()) {
    return Status(ReasonCode::BYTE_COUNT_MISMATCH,
                  "chunk payload length does not match the planned chunk length");
  }
  return compute_chunk_digest(descriptor_.object_id, descriptor_.generation, index, offset.value(),
                              length.value(), payload);
}

bool ChunkPlan::same_segmentation(const ChunkPlan& other) const noexcept {
  return descriptor_.same_version(other.descriptor_);
}

Status ChunkPlan::enforce_policy_bounds(std::uint64_t min_chunk_bytes, std::uint64_t max_chunk_bytes,
                                        std::uint64_t max_object_bytes) const {
  if (descriptor_.chunk_bytes < min_chunk_bytes || descriptor_.chunk_bytes > max_chunk_bytes) {
    return Status(ReasonCode::POLICY_VIOLATION,
                  "object chunk size is outside the policy bounds for this coordinator");
  }
  if (descriptor_.total_bytes > max_object_bytes) {
    return Status(ReasonCode::POLICY_VIOLATION,
                  "object exceeds the maximum size this coordinator will move");
  }
  return Status::success();
}

void ChunkPlan::encode(CanonicalEncoder& encoder) const { descriptor_.encode(encoder); }

Result<ChunkPlan> ChunkPlan::decode(CanonicalDecoder& decoder) {
  const auto descriptor = StateObjectDescriptor::decode(decoder);
  if (!descriptor.ok()) return descriptor.status();
  return ChunkPlan(descriptor.value());
}

void ResumeState::encode(CanonicalEncoder& encoder) const {
  descriptor.encode(encoder);
  encoder.u32(verified_chunks);
  encoder.u64(verified_bytes);
  encoder.digest(rolling_digest);
}

Result<ResumeState> ResumeState::decode(CanonicalDecoder& decoder) {
  ResumeState state;

  const auto descriptor = StateObjectDescriptor::decode(decoder);
  if (!descriptor.ok()) return descriptor.status();
  state.descriptor = descriptor.value();

  const auto chunks = decoder.u32();
  if (!chunks.ok()) return chunks.status();
  state.verified_chunks = chunks.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  state.verified_bytes = bytes.value();

  const auto digest = decoder.digest();
  if (!digest.ok()) return digest.status();
  state.rolling_digest = digest.value();

  if (state.verified_chunks > state.descriptor.chunk_count) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "resume state claims more chunks than the object has");
  }

  std::uint64_t expected_bytes = 0;
  for (std::uint32_t index = 0; index < state.verified_chunks; ++index) {
    const auto length = state.descriptor.chunk_length(index);
    if (!length.ok()) return length.status();
    std::uint64_t next = 0;
    if (!checked_add(expected_bytes, length.value(), next)) {
      return Status(ReasonCode::SIZE_OVERFLOW, "resume state byte accounting overflowed");
    }
    expected_bytes = next;
  }
  if (expected_bytes != state.verified_bytes) {
    return Status(ReasonCode::STORE_RECORD_INVALID,
                  "resume state byte count is inconsistent with its verified chunk prefix");
  }
  return state;
}

Status check_resume_compatible(const StateObjectDescriptor& planned,
                               const StateObjectDescriptor& staged) {
  if (!planned.same_object(staged)) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE,
                  "staged state belongs to a different state object");
  }
  if (planned.generation != staged.generation) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE,
                  "staged state belongs to a different state generation");
  }
  if (planned.content_digest != staged.content_digest) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE,
                  "staged state was produced from different content");
  }
  if (planned.chunk_bytes != staged.chunk_bytes) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE, "staged state used a different chunk size");
  }
  if (planned.chunk_count != staged.chunk_count) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE, "staged state used a different segmentation");
  }
  if (planned.total_bytes != staged.total_bytes) {
    return Status(ReasonCode::RESUME_INCOMPATIBLE, "staged state has a different total size");
  }
  return Status::success();
}

std::vector<std::uint32_t> verification_sample(const MovementId& movement_id,
                                               std::uint32_t chunk_count,
                                               std::uint32_t sample_count) {
  std::vector<std::uint32_t> sample;
  if (chunk_count == 0 || sample_count == 0) return sample;
  if (sample_count >= chunk_count) {
    sample.resize(chunk_count);
    for (std::uint32_t i = 0; i < chunk_count; ++i) sample[i] = i;
    return sample;
  }

  // Deterministic derivation from the movement identity, then deduplicated and
  // sorted so that the probe sequence is reproducible.
  const Digest seed = sha256(movement_id.view());
  std::set<std::uint32_t> unique;
  std::uint64_t mixer = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    mixer |= static_cast<std::uint64_t>(seed.bytes()[i]) << (8U * i);
  }
  std::uint32_t attempts = 0;
  while (unique.size() < sample_count && attempts < sample_count * 16U) {
    ++attempts;
    mixer += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = mixer;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31U);
    unique.insert(static_cast<std::uint32_t>(z % chunk_count));
  }
  sample.assign(unique.begin(), unique.end());
  return sample;
}

}  // namespace smf
