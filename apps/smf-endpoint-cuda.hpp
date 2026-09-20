// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Declaration shared between the endpoint executable and its device-memory
// publication module.

#ifndef SMF_APPS_SMF_ENDPOINT_CUDA_HPP
#define SMF_APPS_SMF_ENDPOINT_CUDA_HPP

#include <string>

#include "smf/endpoint_agent.hpp"
#include "smf/status.hpp"

namespace smf::app {

// Publishes a deterministic device-memory payload and announces it. The
// specification is KIND:NAME:GENERATION:BYTES:SEED.
[[nodiscard]] smf::Status publish_cuda_spec(const std::string& specification,
                                            smf::EndpointAgent& agent, bool repeatable);

}  // namespace smf::app

#endif  // SMF_APPS_SMF_ENDPOINT_CUDA_HPP
