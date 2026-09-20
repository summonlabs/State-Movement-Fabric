// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "args.hpp"

#include <cstdlib>
#include <cstdio>

namespace smf::app {

Result<std::uint64_t> Arguments::number(std::string_view name, std::uint64_t fallback) const {
  const auto found = options.find(std::string(name));
  if (found == options.end() || found->second.empty()) return fallback;
  std::uint64_t value = 0;
  for (const char c : found->second) {
    if (c < '0' || c > '9') {
      return Status(ReasonCode::INVALID_ARGUMENT,
                    "option --" + std::string(name) + " must be a non-negative integer");
    }
    if (value > (UINT64_MAX - static_cast<std::uint64_t>(c - '0')) / 10ULL) {
      return Status(ReasonCode::SIZE_OVERFLOW, "option --" + std::string(name) + " is too large");
    }
    value = (value * 10ULL) + static_cast<std::uint64_t>(c - '0');
  }
  return value;
}

Result<Arguments> parse_args(int argc, char** argv) {
  Arguments parsed;
  int index = 1;
  while (index < argc) {
    const std::string token = argv[index];
    if (token.rfind("--", 0) != 0) {
      parsed.positional.push_back(token);
      ++index;
      continue;
    }
    const std::string name = token.substr(2);
    if (name.empty()) {
      return Status(ReasonCode::INVALID_ARGUMENT, "empty option name");
    }
    if (index + 1 < argc && std::string(argv[index + 1]).rfind("--", 0) != 0) {
      parsed.options[name] = argv[index + 1];
      index += 2;
    } else {
      parsed.options[name] = std::string();
      ++index;
    }
  }
  return parsed;
}

Result<Bytes> resolve_shared_secret(const Arguments& args) {
  std::string text = args.get("key");
  if (text.empty()) {
    const char* from_environment = std::getenv("SMF_SHARED_KEY");
    if (from_environment != nullptr) text = from_environment;
  }
  if (text.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT,
                  "a shared secret is required: pass --key <64 hex characters> or set "
                  "SMF_SHARED_KEY");
  }
  return parse_shared_secret(text);
}

void print_usage(const char* program, const char* usage) {
  std::fprintf(stderr, "%s\n\n%s\n", program, usage);
}

}  // namespace smf::app
