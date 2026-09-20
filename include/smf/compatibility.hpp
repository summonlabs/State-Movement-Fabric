// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Compatibility evidence interface.
//
// The fabric does not decide whether a KV cache is usable by a particular
// runtime. It decides whether *evidence* exists, whether that evidence is
// current, and whether it applies to this exact object version at this exact
// destination. Missing evidence is UNKNOWN, and UNKNOWN is never promoted to
// SUPPORTED by the absence of a negative.

#ifndef SMF_COMPATIBILITY_HPP
#define SMF_COMPATIBILITY_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "smf/codec.hpp"
#include "smf/ids.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"

namespace smf {

enum class CompatibilityVerdict : std::uint8_t {
  UNKNOWN = 0,
  SUPPORTED = 1,
  UNSUPPORTED = 2,
};

[[nodiscard]] const char* to_string(CompatibilityVerdict verdict) noexcept;
[[nodiscard]] bool compatibility_verdict_from_string(std::string_view text,
                                                     CompatibilityVerdict& out) noexcept;

struct CompatibilityEvidence {
  CompatibilityGeneration generation;
  StateObjectId object_id;
  StateGeneration state_generation;
  Digest content_digest;
  EndpointId destination;
  CompatibilityVerdict verdict = CompatibilityVerdict::UNKNOWN;
  std::string contract;
  std::map<std::string, std::string> attributes;
  Millis observed_unix_millis = 0;
  Digest evidence_digest;

  [[nodiscard]] Status validate() const;

  // Compares only the version and destination binding, ignoring the verdict, so
  // that a caller can distinguish "wrong subject" from "negative verdict".
  [[nodiscard]] bool applies_to(const StateObjectDescriptor& descriptor,
                                const EndpointId& destination_id) const;
};

class CompatibilityProvider {
 public:
  CompatibilityProvider() = default;
  CompatibilityProvider(const CompatibilityProvider&) = delete;
  CompatibilityProvider& operator=(const CompatibilityProvider&) = delete;
  virtual ~CompatibilityProvider() = default;

  // Returns evidence for the given object version at the given destination.
  // Implementations must return NO_EVIDENCE rather than inventing a verdict
  // when they do not know.
  [[nodiscard]] virtual Result<CompatibilityEvidence> query(
      const StateObjectDescriptor& descriptor, const EndpointId& destination) = 0;

  [[nodiscard]] virtual CompatibilityGeneration generation() const = 0;
};

// Registry of explicitly published evidence. Nothing is inferred: a version and
// destination with no recorded evidence reports UNKNOWN.
class CompatibilityRegistry final : public CompatibilityProvider {
 public:
  CompatibilityRegistry() = default;

  // Publishing replaces any previous evidence for the same object version and
  // destination and advances the compatibility generation.
  [[nodiscard]] Status publish(CompatibilityEvidence evidence, Millis now_unix_millis);

  // Withdraws evidence. Withdrawal is not the same as publishing UNSUPPORTED:
  // the subject returns to "no evidence".
  [[nodiscard]] Status withdraw(const StateObjectId& object_id, StateGeneration generation,
                                const EndpointId& destination);

  [[nodiscard]] Result<CompatibilityEvidence> query(const StateObjectDescriptor& descriptor,
                                                    const EndpointId& destination) override;
  [[nodiscard]] CompatibilityGeneration generation() const override;

  [[nodiscard]] std::size_t size() const;

 private:
  struct Key {
    StateObjectId object_id;
    StateGeneration generation;
    EndpointId destination;
    friend bool operator<(const Key& a, const Key& b) {
      if (a.object_id != b.object_id) return a.object_id < b.object_id;
      if (a.generation != b.generation) return a.generation < b.generation;
      return a.destination < b.destination;
    }
  };

  mutable std::mutex mutex_;
  std::map<Key, CompatibilityEvidence> evidence_;
  CompatibilityGeneration generation_{1};
};

}  // namespace smf

#endif  // SMF_COMPATIBILITY_HPP
