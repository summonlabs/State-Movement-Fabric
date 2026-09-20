# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# These proofs run real operating-system processes and move real bytes over
# loopback TCP. They require the executables to have been built.

smf_add_test(smf_multiprocess_movement SOURCES test_movement_processes.cpp LABELS multiprocess)
