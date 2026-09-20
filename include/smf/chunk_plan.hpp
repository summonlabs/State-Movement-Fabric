// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Segmentation and resumption arithmetic. Resume is only permitted when the
// destination's staged state is compatible with the exact object version the
// movement is authorized to move: same identity, same generation, same content
// digest, same chunk size, same chunk count. Anything else restarts from zero
// rather than splicing two different byte streams together.

#ifndef SMF_CHUNK_PLAN_HPP
#define SMF_CHUNK_PLAN_HPP

#include <cstdint>

#include "smf/ids.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"

namespace smf {

class ChunkPlan {
 public:
  ChunkPlan() = default;
  explicit ChunkPlan(StateObjectDescriptor descriptor) : descriptor_(std::move(descriptor)) {}

  [[nodiscard]] static Result<ChunkPlan> create(const StateObjectDescriptor& descriptor);

  [[nodiscard]] const StateObjectDescriptor& descriptor() const noexcept { return descriptor_; }
  [[nodiscard]] std::uint32_t chunk_count() const noexcept { return descriptor_.chunk_count; }
  [[nodiscard]] std::uint64_t chunk_bytes() const noexcept { return descriptor_.chunk_bytes; }
  [[nodiscard]] std::uint64_t total_bytes() const noexcept { return descriptor_.total_bytes; }

  [[nodiscard]] Result<std::uint64_t> offset_of(std::uint32_t index) const;
  [[nodiscard]] Result<std::uint64_t> length_of(std::uint32_t index) const;
  [[nodiscard]] Result<Digest> chunk_digest_of(std::uint32_t index, ByteView payload) const;

  // True when both plans describe the same segmentation of the same version.
  [[nodiscard]] bool same_segmentation(const ChunkPlan& other) const noexcept;

  // Enforces the chunk size against policy bounds.
  [[nodiscard]] Status enforce_policy_bounds(std::uint64_t min_chunk_bytes,
                                             std::uint64_t max_chunk_bytes,
                                             std::uint64_t max_object_bytes) const;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ChunkPlan> decode(CanonicalDecoder& decoder);

 private:
  StateObjectDescriptor descriptor_;
};

// Contiguous verified prefix of a staged transfer. Chunks are accepted strictly
// in order, so "verified" is always a prefix and never a set with holes.
struct ResumeState {
  StateObjectDescriptor descriptor;
  std::uint32_t verified_chunks = 0;
  std::uint64_t verified_bytes = 0;
  Digest rolling_digest;

  [[nodiscard]] bool complete() const noexcept {
    return verified_chunks == descriptor.chunk_count && verified_bytes == descriptor.total_bytes;
  }
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ResumeState> decode(CanonicalDecoder& decoder);
};

// Compatibility rule for resuming a partially transferred object.
[[nodiscard]] Status check_resume_compatible(const StateObjectDescriptor& planned,
                                              const StateObjectDescriptor& staged);

// The chunk indices a coordinator will sample when it independently verifies a
// destination. Derived from the movement identity so that a destination cannot
// precompute the sample without holding the bytes, but reproducible so that a
// denial can be explained.
[[nodiscard]] std::vector<std::uint32_t> verification_sample(const MovementId& movement_id,
                                                             std::uint32_t chunk_count,
                                                             std::uint32_t sample_count);

}  // namespace smf

#endif  // SMF_CHUNK_PLAN_HPP
