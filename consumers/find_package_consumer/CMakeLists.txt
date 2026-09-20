# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# An independent downstream consumer. It is deliberately not part of this
# project's build: it exists to prove that an installed package is usable by a
# project that shares no build tree with the library.

cmake_minimum_required(VERSION 3.20...3.28)
project(smf_downstream_consumer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SMF 1.0 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE smf::core)
