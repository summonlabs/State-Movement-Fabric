# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

add_library(smf_app_support STATIC args.cpp)
smf_apply_target_defaults(smf_app_support)
target_link_libraries(smf_app_support PUBLIC smf::core)
target_include_directories(smf_app_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(smf_coordinator smf-coordinator.cpp)
smf_apply_target_defaults(smf_coordinator)
target_link_libraries(smf_coordinator PRIVATE smf_app_support)

add_executable(smf_endpoint smf-endpoint.cpp smf-endpoint-cuda.cpp)
smf_apply_target_defaults(smf_endpoint)
target_link_libraries(smf_endpoint PRIVATE smf_app_support)

if(SMF_ENABLE_CUDA)
  # The device publication path is the only accelerated code in the tree. It is
  # compiled with the CUDA language enabled and linked against the runtime.
  target_sources(smf_endpoint PRIVATE cuda_publish.cu)
  target_link_libraries(smf_endpoint PRIVATE CUDA::cudart)
  target_compile_definitions(smf_endpoint PRIVATE SMF_HAS_CUDA=1)
  set_source_files_properties(cuda_publish.cu PROPERTIES LANGUAGE CUDA)
else()
  target_sources(smf_endpoint PRIVATE cuda_publish_stub.cpp)
endif()

add_executable(smf smf.cpp)
smf_apply_target_defaults(smf)
target_link_libraries(smf PRIVATE smf_app_support)

install(TARGETS smf_coordinator smf_endpoint smf
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
