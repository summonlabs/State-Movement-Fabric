// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf-endpoint-cuda.hpp"

#include <cstdlib>
#include <cstdio>
#include <string>

#include "cuda_publish.hpp"
#include "smf/logging.hpp"

namespace smf::app {
namespace {

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) {
  if (text.empty()) return false;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
    value = (value * 10U) + static_cast<std::uint64_t>(c - '0');
  }
  out = value;
  return true;
}

}  // namespace

smf::Status publish_cuda_spec(const std::string& specification, smf::EndpointAgent& agent,
                              bool repeatable) {
  // KIND:NAME:GENERATION:BYTES:SEED
  std::vector<std::string> parts;
  std::string current;
  for (const char c : specification) {
    if (c == ':') {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts.push_back(current);
  if (parts.size() != 5) {
    return smf::Status(smf::ReasonCode::INVALID_ARGUMENT,
                       "--publish-cuda expects KIND:NAME:GENERATION:BYTES:SEED");
  }

  smf::StateKind kind = smf::StateKind::UNKNOWN;
  if (!smf::state_kind_from_string(parts[0], kind)) {
    return smf::Status(smf::ReasonCode::INVALID_STATE_KIND, "unrecognized state kind");
  }
  std::uint64_t generation = 0;
  std::uint64_t bytes = 0;
  std::uint64_t seed = 0;
  if (!parse_u64(parts[2], generation) || !parse_u64(parts[3], bytes) ||
      !parse_u64(parts[4], seed)) {
    return smf::Status(smf::ReasonCode::INVALID_ARGUMENT,
                       "generation, bytes, and seed must be unsigned integers");
  }

  const auto report = publish_from_cuda_device(agent, kind, parts[1],
                                               smf::StateGeneration(generation), bytes, seed,
                                               repeatable);
  if (!report.ok()) return report.status();

  // The report line is the machine-readable evidence a caller needs: the device
  // that was used, the bytes staged, the free-memory baseline before and after,
  // and the digest of exactly what was published.
  std::printf(
      "CUDA-PUBLISH device=\"%s\" runtime=%s bytes=%llu free_before=%llu free_after=%llu "
      "total=%llu digest=%s object=\"%s\"\n",
      report.value().device_name.c_str(), report.value().runtime_version.c_str(),
      static_cast<unsigned long long>(report.value().device_bytes),
      static_cast<unsigned long long>(report.value().device_free_before),
      static_cast<unsigned long long>(report.value().device_free_after),
      static_cast<unsigned long long>(report.value().device_total),
      report.value().content_digest.hex().c_str(), report.value().object.c_str());
  std::fflush(stdout);

  const auto object_id = smf::derive_state_object_id(kind, parts[1]);
  if (!object_id.ok()) return object_id.status();
  const auto marker =
      agent.object_store().read_commit_marker(object_id.value(), smf::StateGeneration(generation));
  if (!marker.ok()) return marker.status();
  SMF_RETURN_IF_ERROR(agent.announce(marker.value().object));
  smf::log_message(smf::LogLevel::INFO, "endpoint",
                   "announced " + smf::describe(marker.value().object));
  return smf::Status::success();
}

}  // namespace smf::app
