# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# State Movement Fabric - top-level build.
#
# The tree is intentionally dependency-free: only the C++20 standard library,
# the platform socket library, and the platform thread library are used. Proof
# suites use the in-tree harness under tests/support.

cmake_minimum_required(VERSION 3.20...3.28)

project(StateMovementFabric
  VERSION 1.0.1
  DESCRIPTION "Vendor-neutral C++20 runtime for governing cross-network movement of reusable AI state"
  HOMEPAGE_URL "https://github.com/summonlabs/State-Movement-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(SMFHelpers)

option(SMF_BUILD_APPS "Build the coordinator, endpoint, and command-line executables" ON)
option(SMF_BUILD_TESTS "Build the State Movement Fabric proof suites" ON)
option(SMF_BUILD_EXAMPLES "Build the examples" ON)
option(SMF_ENABLE_CUDA "Build the optional CUDA device-memory conveyor example and proof" OFF)
option(SMF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
set(SMF_SANITIZE "" CACHE STRING "Sanitizer configuration: empty, address, or undefined")
set(SMF_TEST_SEED "" CACHE STRING "Fixed seed for the seeded property suites (empty uses the built-in default)")

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD ${SMF_CXX_STANDARD})
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

if(MSVC)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin")
endif()

if(SMF_ENABLE_CUDA)
  # CUDA is used only by the device-memory proof surface and the endpoint's
  # device publication path. The core library has no accelerator dependency.
  enable_language(CUDA)
  find_package(CUDAToolkit REQUIRED)
  # The device publication unit includes the public headers, so it must speak
  # the same C++20 the rest of the tree does.
  set(CMAKE_CUDA_STANDARD 20)
  set(CMAKE_CUDA_STANDARD_REQUIRED ON)
  set(CMAKE_CUDA_EXTENSIONS OFF)
  if(NOT CMAKE_CUDA_ARCHITECTURES)
    # Target the architecture of the device actually installed in this machine
    # rather than a list of older ones, which also keeps nvcc quiet about
    # deprecated offline targets.
    set(CMAKE_CUDA_ARCHITECTURES native)
  endif()
  message(STATUS "State Movement Fabric: CUDA proofs enabled (CUDAToolkit ${CUDAToolkit_VERSION})")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(SMF_CORE_SOURCES
  src/bytes.cpp
  src/status.cpp
  src/digest.cpp
  src/time.cpp
  src/codec.cpp
  src/ids.cpp
  src/framing.cpp
  src/session.cpp
  src/transport.cpp
  src/state_object.cpp
  src/compatibility.cpp
  src/topology.cpp
  src/policy.cpp
  src/chunk_plan.cpp
  src/movement.cpp
  src/provenance.cpp
  src/file_utils.cpp
  src/movement_store.cpp
  src/object_store.cpp
  src/wire.cpp
  src/fault_injection.cpp
  src/endpoint_agent.cpp
  src/coordinator.cpp
  src/logging.cpp
)

add_library(smf_core STATIC ${SMF_CORE_SOURCES})
add_library(smf::core ALIAS smf_core)
# The exported name is smf::core, so a downstream consumer links the same target
# name it would use inside this tree.
set_target_properties(smf_core PROPERTIES EXPORT_NAME core)
smf_apply_target_defaults(smf_core)

target_include_directories(smf_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(smf_core PUBLIC Threads::Threads)
if(WIN32)
  # ws2_32 provides the socket API; bcrypt provides the operating-system random
  # number generator used for incarnations, identifiers, and session nonces.
  target_link_libraries(smf_core PUBLIC ws2_32 bcrypt)
endif()

target_compile_definitions(smf_core PRIVATE
  SMF_BUILDING_LIBRARY=1
  SMF_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  SMF_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  SMF_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  SMF_VERSION_STRING="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(smf_core PRIVATE /bigobj)
endif()

if(SMF_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(SMF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(SMF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Install and export
# ---------------------------------------------------------------------------
install(TARGETS smf_core
  EXPORT SMFTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(DIRECTORY include/smf
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT SMFTargets
  FILE SMFTargets.cmake
  NAMESPACE smf::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SMF")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SMFConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SMFConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SMF")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SMFConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/SMFConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/SMFConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SMF")

install(FILES LICENSE NOTICE README.md
  DESTINATION "${CMAKE_INSTALL_DATADIR}/state-movement-fabric"
  OPTIONAL)
