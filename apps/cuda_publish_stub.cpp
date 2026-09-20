// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The no-CUDA build of the device publication path. It refuses, explicitly.

#include "cuda_publish.hpp"

namespace smf::app {

bool cuda_available() noexcept { return false; }

std::string cuda_runtime_version() noexcept { return "unsupported"; }

Result<CudaPublishReport> publish_from_cuda_device(EndpointAgent&, StateKind, const std::string&,
                                                   StateGeneration, std::uint64_t, std::uint64_t,
                                                   bool) {
  return Status(ReasonCode::UNSUPPORTED,
                "this build has no CUDA support; reconfigure with -DSMF_ENABLE_CUDA=ON");
}

}  // namespace smf::app
