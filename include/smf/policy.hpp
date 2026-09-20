// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Policy is the bounded envelope inside which the runtime will act. Every
// externally supplied size, count, and budget that reaches an allocation, a
// loop, or a retry decision is validated here first.

#ifndef SMF_POLICY_HPP
#define SMF_POLICY_HPP

#include <cstdint>

#include "smf/codec.hpp"
#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/status.hpp"

namespace smf {

struct MovementPolicy {
  // Retry envelope. An attempt is one transfer session; retries never exceed
  // this count regardless of how transient the failure looks.
  std::uint32_t max_attempts = 3;

  // Flow control. The source never has more than this many unacknowledged
  // chunks outstanding, and never buffers more than one chunk per slot.
  std::uint32_t max_inflight_chunks = 8;

  // Payload bounds.
  std::uint64_t min_chunk_bytes = 4096;
  std::uint64_t max_chunk_bytes = 1ULL << 20;   // 1 MiB
  std::uint64_t max_object_bytes = 64ULL << 30; // 64 GiB
  std::uint64_t max_movement_bytes = 64ULL << 30;

  // Resource bounds.
  std::uint32_t max_endpoints = 256;
  std::uint32_t max_sessions = 256;
  std::uint32_t max_movements_in_flight = 1024;
  std::uint32_t max_provenance_events = 64;
  std::uint32_t max_history_records = 200000;
  std::uint64_t max_store_bytes = 256ULL << 20;  // 256 MiB
  std::uint64_t max_staging_bytes_per_endpoint = 8ULL << 30;

  // Behaviour switches.
  bool allow_resume = true;
  bool require_compatibility_evidence = true;
  bool allow_unknown_kind = true;
  bool verify_sample_chunks = true;
  std::uint32_t verify_sample_chunks_count = 4;

  // Budgets, in milliseconds, for a single IO operation and a single transfer
  // attempt. These bound waiting; they never bound how long a proof may run.
  std::uint32_t io_budget_millis = 30000;
  std::uint32_t transfer_budget_millis = 600000;

  [[nodiscard]] Status validate() const;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementPolicy> decode(CanonicalDecoder& decoder);

  [[nodiscard]] bool operator==(const MovementPolicy& other) const;
};

struct PolicySet {
  PolicyGeneration generation;
  MovementPolicy policy;

  [[nodiscard]] Status validate() const;
  [[nodiscard]] Digest digest() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<PolicySet> decode(CanonicalDecoder& decoder);
};

}  // namespace smf

#endif  // SMF_POLICY_HPP
