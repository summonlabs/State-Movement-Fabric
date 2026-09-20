# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# The device-memory proof. It is registered only when the tree was configured
# with -DSMF_ENABLE_CUDA=ON and a usable toolkit was found.
#
# The driver itself is ordinary host C++ that links the CUDA runtime directly:
# the only accelerated code in the tree is the endpoint's fill kernel, so the
# proof driver does not need the CUDA language enabled.

add_executable(smf_cuda_device_state test_cuda_device_state.cpp)
smf_apply_target_defaults(smf_cuda_device_state)
target_link_libraries(smf_cuda_device_state PRIVATE smf_test_support CUDA::cudart)

add_test(NAME smf_cuda_device_state COMMAND smf_cuda_device_state)
set_tests_properties(smf_cuda_device_state PROPERTIES LABELS cuda)
