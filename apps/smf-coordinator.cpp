// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// smf-coordinator: the authority process.

#include <cstdio>
#include <cstdlib>
#include <string>

#include "args.hpp"
#include "smf/coordinator.hpp"
#include "smf/fault_injection.hpp"
#include "smf/logging.hpp"

namespace {

constexpr const char* kUsage =
    "usage: smf-coordinator --state <dir> --key <hex> [options]\n"
    "\n"
    "  --state <dir>            durable state directory (required)\n"
    "  --key <hex>              32-byte shared secret as 64 hex characters\n"
    "  --listen <host:port>     endpoint listener (default 127.0.0.1:0)\n"
    "  --admin <host:port>      operator listener (default 127.0.0.1:0)\n"
    "  --announce <file>        write the bound addresses as JSON when ready\n"
    "  --log-level <level>      TRACE, DEBUG, INFO, WARN, ERROR, OFF\n"
    "  --fault-inject <spec>    enable documented fault injection points\n"
    "  --max-attempts <n>       retry ceiling (default 3)\n"
    "  --chunk-bytes <n>        maximum chunk size (default 1048576)\n"
    "  --verify-samples <n>     chunks the coordinator re-hashes itself (default 3)\n"
    "  --workers <n>            movement workers (default 4)\n"
    "  --sync <true|false>      flush durable writes (default true)\n";

}  // namespace

int main(int argc, char** argv) {
  const auto parsed = smf::app::parse_args(argc, argv);
  if (!parsed.ok()) {
    std::fprintf(stderr, "%s\n", parsed.status().to_string().c_str());
    smf::app::print_usage("smf-coordinator", kUsage);
    return 2;
  }
  const smf::app::Arguments& args = parsed.value();

  if (args.has("help")) {
    smf::app::print_usage("smf-coordinator", kUsage);
    return 0;
  }

  const std::string state = args.get("state");
  if (state.empty()) {
    std::fprintf(stderr, "--state is required\n");
    smf::app::print_usage("smf-coordinator", kUsage);
    return 2;
  }

  const auto secret = smf::app::resolve_shared_secret(args);
  if (!secret.ok()) {
    std::fprintf(stderr, "%s\n", secret.status().to_string().c_str());
    return 2;
  }

  const auto fault = smf::FaultInjector::instance().configure(args.get("fault-inject"));
  if (!fault.ok()) {
    std::fprintf(stderr, "%s\n", fault.to_string().c_str());
    return 2;
  }

  smf::LogLevel level = smf::LogLevel::INFO;
  if (args.has("log-level") && !smf::log_level_from_string(args.get("log-level"), level)) {
    std::fprintf(stderr, "unrecognized log level\n");
    return 2;
  }
  smf::set_log_level(level);
  smf::set_log_sink(smf::make_stderr_sink());

  smf::CoordinatorConfig config;
  config.endpoint_id = smf::EndpointId::parse(args.get("id", "coordinator")).value();
  config.state_directory = state;
  config.shared_secret = secret.value();
  config.sync_store = args.get("sync", "true") != "false";
  config.worker_threads = static_cast<std::uint32_t>(args.number("workers", 4).value());
  config.verify_sample_chunks =
      static_cast<std::uint32_t>(args.number("verify-samples", 3).value());

  if (args.has("listen")) {
    const auto address = smf::SocketAddress::parse(args.get("listen"));
    if (!address.ok()) {
      std::fprintf(stderr, "%s\n", address.status().to_string().c_str());
      return 2;
    }
    config.endpoint_listen = address.value();
  }
  if (args.has("admin")) {
    const auto address = smf::SocketAddress::parse(args.get("admin"));
    if (!address.ok()) {
      std::fprintf(stderr, "%s\n", address.status().to_string().c_str());
      return 2;
    }
    config.admin_listen = address.value();
  }

  config.policy.max_attempts = static_cast<std::uint32_t>(args.number("max-attempts", 3).value());
  config.policy.max_chunk_bytes = args.number("chunk-bytes", 1U << 20).value();

  auto started = smf::Coordinator::start(config);
  if (!started.ok()) {
    std::fprintf(stderr, "coordinator failed to start: %s\n",
                 started.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  // Publishing the bound addresses is how a supervisor learns the ephemeral
  // ports without guessing them.
  const std::string announce = args.get("announce");
  if (!announce.empty()) {
    const std::string json = "{\"endpoint\":\"" + coordinator->endpoint_address().to_string() +
                             "\",\"admin\":\"" + coordinator->admin_address().to_string() +
                             "\",\"epoch\":" +
                             std::to_string(coordinator->incarnation().epoch().value()) + "}\n";
    if (std::FILE* file = std::fopen(announce.c_str(), "wb")) {
      std::fwrite(json.data(), 1, json.size(), file);
      std::fclose(file);
    } else {
      std::fprintf(stderr, "could not write the announcement file\n");
      return 1;
    }
  } else {
    std::printf("coordinator endpoint=%s admin=%s epoch=%llu\n",
                coordinator->endpoint_address().to_string().c_str(),
                coordinator->admin_address().to_string().c_str(),
                static_cast<unsigned long long>(coordinator->incarnation().epoch().value()));
    std::fflush(stdout);
  }

  coordinator->run();
  const smf::Status stopped = coordinator->stop();
  if (!stopped.ok()) {
    std::fprintf(stderr, "shutdown reported: %s\n", stopped.to_string().c_str());
    return 1;
  }
  return 0;
}
