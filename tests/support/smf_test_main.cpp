// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every proof executable links smf_test_support, which supplies its entry point.

#include "smf_test.hpp"

int main(int argc, char** argv) { return smftest::run_all(argc, argv); }
