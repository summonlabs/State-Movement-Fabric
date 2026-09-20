// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Command-line parsing shared by the three executables. It is deliberately
// strict: an unknown flag or a malformed value is a startup failure, never a
// silently ignored argument.

#ifndef SMF_APPS_ARGS_HPP
#define SMF_APPS_ARGS_HPP

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "smf/session.hpp"
#include "smf/status.hpp"
#include "smf/transport.hpp"

namespace smf::app {

struct Arguments {
  std::vector<std::string> positional;
  std::map<std::string, std::string> options;

  [[nodiscard]] bool has(std::string_view name) const { return options.count(std::string(name)) != 0; }

  [[nodiscard]] std::string get(std::string_view name, std::string fallback = {}) const {
    const auto found = options.find(std::string(name));
    return found == options.end() ? std::move(fallback) : found->second;
  }

  [[nodiscard]] Result<std::uint64_t> number(std::string_view name, std::uint64_t fallback) const;
};

// Parses "--name value" pairs and bare positionals. "--flag" with no following
// value is recorded with an empty value.
[[nodiscard]] Result<Arguments> parse_args(int argc, char** argv);

// Reads the shared secret from --key, falling back to the SMF_SHARED_KEY
// environment variable so that a key does not have to appear in a command line.
[[nodiscard]] Result<Bytes> resolve_shared_secret(const Arguments& args);

void print_usage(const char* program, const char* usage);

}  // namespace smf::app

#endif  // SMF_APPS_ARGS_HPP
