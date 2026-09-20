# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# Every proof suite is registered through smf_add_test(), which deliberately
# attaches no timeout property: a hanging proof is a defect to diagnose.

add_library(smf_test_support STATIC
  support/smf_test.cpp
  support/smf_test_main.cpp
  support/smf_test_process.cpp)
add_library(smf::test_support ALIAS smf_test_support)
smf_apply_target_defaults(smf_test_support)
target_link_libraries(smf_test_support PUBLIC smf::core)
target_include_directories(smf_test_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/support")
if(MSVC)
  target_compile_options(smf_test_support PRIVATE /bigobj)
endif()

# Proof executables that drive real child processes need to know where the
# sibling executables were produced. This is resolved through a generator
# expression, never through a checked-in machine-specific path.
if(TARGET smf_coordinator)
  target_compile_definitions(smf_test_support PUBLIC
    SMF_TEST_BIN_DIR="$<TARGET_FILE_DIR:smf_coordinator>")
else()
  target_compile_definitions(smf_test_support PUBLIC SMF_TEST_BIN_DIR="")
endif()

add_subdirectory(unit)
add_subdirectory(protocol)

if(TARGET smf_coordinator AND TARGET smf_endpoint)
  add_subdirectory(multiprocess)
endif()
