// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/compatibility.hpp"

#include "smf/limits.hpp"

namespace smf {

const char* to_string(CompatibilityVerdict verdict) noexcept {
  switch (verdict) {
    case CompatibilityVerdict::UNKNOWN:
      return "UNKNOWN";
    case CompatibilityVerdict::SUPPORTED:
      return "SUPPORTED";
    case CompatibilityVerdict::UNSUPPORTED:
      return "UNSUPPORTED";
  }
  return "UNRECOGNIZED_COMPATIBILITY_VERDICT";
}

bool compatibility_verdict_from_string(std::string_view text, CompatibilityVerdict& out) noexcept {
  if (text == "UNKNOWN") {
    out = CompatibilityVerdict::UNKNOWN;
    return true;
  }
  if (text == "SUPPORTED") {
    out = CompatibilityVerdict::SUPPORTED;
    return true;
  }
  if (text == "UNSUPPORTED") {
    out = CompatibilityVerdict::UNSUPPORTED;
    return true;
  }
  return false;
}

Status CompatibilityEvidence::validate() const {
  if (!generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "compatibility generation must be non-zero");
  }
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "compatibility evidence must name a state object");
  }
  if (!state_generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "compatibility evidence must name a generation");
  }
  if (content_digest.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, "compatibility evidence must bind a content digest");
  }
  if (destination.empty()) {
    return Status(ReasonCode::INVALID_ID, "compatibility evidence must name a destination");
  }
  if (contract.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "compatibility evidence must name a contract");
  }
  if (contract.size() > kMaxTextBytes || !is_valid_utf8(as_bytes(contract))) {
    return Status(ReasonCode::INVALID_ARGUMENT, "compatibility contract string is not usable");
  }
  if (attributes.size() > kMaxEvidenceAttributes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "compatibility evidence carries too many attributes");
  }
  for (const auto& entry : attributes) {
    if (entry.first.empty() || entry.first.size() > kMaxTextBytes ||
        !is_valid_utf8(as_bytes(entry.first))) {
      return Status(ReasonCode::INVALID_ARGUMENT, "compatibility attribute key is not usable");
    }
    if (entry.second.size() > kMaxTextBytes || !is_valid_utf8(as_bytes(entry.second))) {
      return Status(ReasonCode::INVALID_ARGUMENT, "compatibility attribute value is not usable");
    }
  }
  if (observed_unix_millis <= 0) {
    return Status(ReasonCode::INVALID_ARGUMENT, "compatibility evidence needs an observation time");
  }
  return Status::success();
}

bool CompatibilityEvidence::applies_to(const StateObjectDescriptor& descriptor,
                                       const EndpointId& destination_id) const {
  return object_id == descriptor.object_id && state_generation == descriptor.generation &&
         content_digest == descriptor.content_digest && destination == destination_id;
}

Status CompatibilityRegistry::publish(CompatibilityEvidence evidence, Millis now_unix_millis) {
  CanonicalEncoder encoder("SMF-COMPATIBILITY-EVIDENCE-v1");
  encoder.digest(Digest(evidence.object_id.bytes()));
  encoder.u64(evidence.state_generation.value());
  encoder.digest(evidence.content_digest);
  encoder.text(evidence.destination.value());
  encoder.u8(static_cast<std::uint8_t>(evidence.verdict));
  encoder.text(evidence.contract);
  encoder.u32(static_cast<std::uint32_t>(evidence.attributes.size()));
  for (const auto& entry : evidence.attributes) {
    encoder.text(entry.first);
    encoder.text(entry.second);
  }
  evidence.evidence_digest = canonical_digest(encoder);
  if (evidence.observed_unix_millis <= 0) {
    evidence.observed_unix_millis = now_unix_millis;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // The registry stamps the generation it is publishing under, so the evidence
  // is complete before it is validated.
  evidence.generation = generation_;

  const Status status = evidence.validate();
  if (!status.ok()) return status;

  const Key key{evidence.object_id, evidence.state_generation, evidence.destination};
  evidence_.insert_or_assign(key, evidence);
  const auto advanced = generation_.next();
  if (advanced.ok()) generation_ = advanced.value();
  return Status::success();
}

Status CompatibilityRegistry::withdraw(const StateObjectId& object_id, StateGeneration generation,
                                       const EndpointId& destination) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Key key{object_id, generation, destination};
  const auto removed = evidence_.erase(key);
  if (removed == 0) {
    return Status(ReasonCode::NOT_FOUND, "no compatibility evidence is recorded for that subject");
  }
  const auto advanced = generation_.next();
  if (advanced.ok()) generation_ = advanced.value();
  return Status::success();
}

Result<CompatibilityEvidence> CompatibilityRegistry::query(const StateObjectDescriptor& descriptor,
                                                           const EndpointId& destination) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Key key{descriptor.object_id, descriptor.generation, destination};
  const auto found = evidence_.find(key);
  if (found == evidence_.end()) {
    return Status(ReasonCode::NO_EVIDENCE,
                  "no compatibility evidence has been published for this object version at this "
                  "destination; the verdict is unknown, not positive");
  }
  return found->second;
}

CompatibilityGeneration CompatibilityRegistry::generation() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return generation_;
}

std::size_t CompatibilityRegistry::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return evidence_.size();
}

}  // namespace smf
