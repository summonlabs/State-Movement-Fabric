// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Device-memory publication path. This is the only place in the repository that
// touches an accelerator, and it exists to prove one thing: state that lives in
// real device memory can be carried into the fabric's ordinary host-side state
// object path and moved by the normal machinery.
//
// It is deliberately not part of the core library. Devices are a source of
// state, not a property of the movement transaction, and no GPUDirect, RDMA, or
// peer-to-peer behaviour is implemented or claimed here.

#ifndef SMF_APPS_CUDA_PUBLISH_HPP
#define SMF_APPS_CUDA_PUBLISH_HPP

#include <cstdint>
#include <string>

#include "smf/endpoint_agent.hpp"
#include "smf/status.hpp"

namespace smf::app {

struct CudaPublishReport {
  bool available = false;
  std::string device_name;
  std::string runtime_version;
  std::uint64_t device_bytes = 0;
  std::uint64_t device_free_before = 0;
  std::uint64_t device_free_after = 0;
  std::uint64_t device_total = 0;
  Digest content_digest;
  std::string object;
};

// True when this build was compiled with CUDA and at least one device is usable.
[[nodiscard]] bool cuda_available() noexcept;

// The CUDA runtime version this build was compiled against, or "unsupported".
[[nodiscard]] std::string cuda_runtime_version() noexcept;

// Allocates real device memory, fills it with a deterministic pattern on the
// device, copies it to the host, publishes those exact bytes as a state object
// version, frees the allocation, and reports the device free-memory baseline
// before and after so a caller can prove the allocation was returned.
//
// When the build has no CUDA support the call fails with UNSUPPORTED and does
// not pretend otherwise.
[[nodiscard]] Result<CudaPublishReport> publish_from_cuda_device(EndpointAgent& agent,
                                                                StateKind kind, const std::string& name,
                                                                StateGeneration generation,
                                                                std::uint64_t bytes,
                                                                std::uint64_t seed,
                                                                bool repeatable);

}  // namespace smf::app

#endif  // SMF_APPS_CUDA_PUBLISH_HPP
