// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A state object version: what the fabric believes exists, how big it is, how
// it is segmented, and what its content hashes to. This is the only description
// of state that the movement transaction ever relies on; the fabric never
// interprets the bytes themselves.

#ifndef SMF_STATE_OBJECT_HPP
#define SMF_STATE_OBJECT_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "smf/codec.hpp"
#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"

namespace smf {

struct StateObjectDescriptor {
  StateObjectId object_id;
  StateKind kind = StateKind::UNKNOWN;
  std::string name;
  StateGeneration generation;
  Digest content_digest;
  std::uint64_t total_bytes = 0;
  std::uint64_t chunk_bytes = 0;
  std::uint32_t chunk_count = 0;
  Millis created_unix_millis = 0;
  std::string producer;
  // Whether reproducing these exact bytes at the destination is safe to repeat
  // after an ambiguous outcome. False marks a movement whose commit performs an
  // effect that must not be replayed blindly.
  bool repeatable = true;

  [[nodiscard]] static Result<StateObjectDescriptor> create(StateKind kind, std::string name,
                                                            StateGeneration generation,
                                                            Digest content_digest,
                                                            std::uint64_t total_bytes,
                                                            std::uint64_t chunk_bytes,
                                                            Millis created_unix_millis,
                                                            std::string producer);

  // Full structural validation. Every mutation path in the runtime goes through
  // this before a descriptor can be used for authority.
  [[nodiscard]] Status validate() const;

  // Identity plus generation plus content binding. Two descriptors that match
  // describe the same immutable bytes.
  [[nodiscard]] bool same_version(const StateObjectDescriptor& other) const;

  [[nodiscard]] bool same_object(const StateObjectDescriptor& other) const {
    return object_id == other.object_id;
  }

  // The exact length of a chunk, computed with checked arithmetic.
  [[nodiscard]] Result<std::uint64_t> chunk_length(std::uint32_t index) const;
  [[nodiscard]] Result<std::uint64_t> chunk_offset(std::uint32_t index) const;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<StateObjectDescriptor> decode(CanonicalDecoder& decoder);

  // Canonical digest of the descriptor itself, used by announcements so that a
  // peer can prove which descriptor it is holding.
  [[nodiscard]] Digest descriptor_digest() const;
};

// Human-readable one-line summary used by the CLI and by denial messages.
[[nodiscard]] std::string describe(const StateObjectDescriptor& descriptor);

}  // namespace smf

#endif  // SMF_STATE_OBJECT_HPP
