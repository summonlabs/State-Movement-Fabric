# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# Shared build policy for the State Movement Fabric tree. Every first-party
# target routes through smf_apply_target_defaults() so that the warning policy,
# the C++ standard, and the sanitizer configuration cannot drift between targets.

include_guard(GLOBAL)

set(SMF_CXX_STANDARD 20)

function(smf_apply_target_defaults target)
  target_compile_features(${target} PUBLIC cxx_std_20)

  if(MSVC)
    # These options are host-compiler options. They are attached per language so
    # that a CUDA translation unit in the same target never receives them raw:
    # nvcc forwards unknown flags to the host compiler only through -Xcompiler.
    target_compile_options(${target} PRIVATE
      $<$<COMPILE_LANGUAGE:CXX>:/W4>
      $<$<COMPILE_LANGUAGE:CXX>:/permissive->
      $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
      $<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>
      $<$<COMPILE_LANGUAGE:CXX>:/Zc:ternary>
      $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
      $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
      $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/utf-8>
      $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/permissive->
      $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/Zc:__cplusplus>)
    if(SMF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/WX>)
    endif()
    target_compile_definitions(${target} PRIVATE
      _CRT_SECURE_NO_WARNINGS
      NOMINMAX
      WIN32_LEAN_AND_MEAN)
  else()
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wshadow
      -Wconversion
      -Wsign-conversion
      -Wnon-virtual-dtor
      -Wold-style-cast
      -Wcast-align
      -Wunused
      -Woverloaded-virtual
      -Wnull-dereference
      -Wdouble-promotion
      -Wformat=2)
    if(SMF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    target_compile_definitions(${target} PRIVATE NOMINMAX)
  endif()

  if(SMF_SANITIZE STREQUAL "address")
    if(MSVC)
      # The sanitizer needs debug information to attribute a report to a source
      # location, and the linker needs a matching program database.
      target_compile_options(${target} PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/fsanitize=address>
        $<$<COMPILE_LANGUAGE:CXX>:/Zi>
        $<$<COMPILE_LANGUAGE:CXX>:/Od>)
      # /DEBUG gives the sanitizer a line table to attribute a report to.
      target_link_options(${target} PRIVATE /INCREMENTAL:NO /DEBUG)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  elseif(SMF_SANITIZE STREQUAL "undefined")
    if(NOT MSVC)
      target_compile_options(${target} PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=undefined)
    endif()
  elseif(NOT SMF_SANITIZE STREQUAL "")
    message(FATAL_ERROR "SMF_SANITIZE='${SMF_SANITIZE}' is not supported (use '', 'address', or 'undefined')")
  endif()
endfunction()

# smf_add_test(<target> SOURCES ... [LABELS ...] [ARGV ...])
#
# Tests are registered without any timeout property: a hanging proof is a defect
# to diagnose, not something to mask with a watchdog.
function(smf_add_test target)
  cmake_parse_arguments(SMF_TEST "" "" "SOURCES;LABELS;ARGV" ${ARGN})
  if(NOT SMF_TEST_SOURCES)
    message(FATAL_ERROR "smf_add_test(${target}) requires SOURCES")
  endif()
  add_executable(${target} ${SMF_TEST_SOURCES})
  smf_apply_target_defaults(${target})
  target_link_libraries(${target} PRIVATE smf_test_support)
  add_test(NAME ${target} COMMAND ${target} ${SMF_TEST_ARGV})
  if(SMF_TEST_LABELS)
    set_tests_properties(${target} PROPERTIES LABELS "${SMF_TEST_LABELS}")
  endif()
  set_tests_properties(${target} PROPERTIES SKIP_RETURN_CODE 77)
endfunction()
