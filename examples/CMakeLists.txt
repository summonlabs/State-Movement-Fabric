# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

add_executable(smf_example_identity state_identity.cpp)
smf_apply_target_defaults(smf_example_identity)
target_link_libraries(smf_example_identity PRIVATE smf::core)

add_executable(smf_example_movement movement_lifecycle.cpp)
smf_apply_target_defaults(smf_example_movement)
target_link_libraries(smf_example_movement PRIVATE smf::core)

add_executable(smf_example_transport framed_transport.cpp)
smf_apply_target_defaults(smf_example_transport)
target_link_libraries(smf_example_transport PRIVATE smf::core)

install(TARGETS smf_example_identity smf_example_movement smf_example_transport
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
