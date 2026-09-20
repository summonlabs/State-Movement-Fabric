// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// smf-endpoint: a process that holds state objects and moves them under
// coordinator authority.

#include <cstdio>
#include <string>

#include "args.hpp"
#include "smf/endpoint_agent.hpp"
#include "smf/fault_injection.hpp"
#include "smf/logging.hpp"

namespace {

constexpr const char* kUsage =
    "usage: smf-endpoint --id <name> --coordinator <host:port> --store <dir> --key <hex> [options]\n"
    "\n"
    "  --id <name>              endpoint identity (required)\n"
    "  --coordinator <addr>     coordinator endpoint listener (required)\n"
    "  --store <dir>            local object store directory (required)\n"
    "  --key <hex>              32-byte shared secret as 64 hex characters\n"
    "  --data <host:port>       data listener (default 127.0.0.1:0)\n"
    "  --publish <spec>         publish a file: kind:name:generation:path\n"
    "  --no-resume              refuse to resume a partially received object\n"
    "  --log-level <level>      TRACE, DEBUG, INFO, WARN, ERROR, OFF\n"
    "  --fault-inject <spec>    enable documented fault injection points\n"
    "  --announce <file>        write the bound addresses as JSON when ready\n";

[[nodiscard]] smf::Result<smf::StateObjectDescriptor> publish_spec_to_file(
    const std::string& spec, smf::EndpointAgent& agent) {
  // kind:name:generation:path
  const std::size_t first = spec.find(':');
  const std::size_t second = first == std::string::npos ? std::string::npos : spec.find(':', first + 1);
  const std::size_t third =
      second == std::string::npos ? std::string::npos : spec.find(':', second + 1);
  if (first == std::string::npos || second == std::string::npos || third == std::string::npos) {
    return smf::Status(smf::ReasonCode::INVALID_ARGUMENT,
                       "--publish expects kind:name:generation:path");
  }
  smf::StateKind kind = smf::StateKind::UNKNOWN;
  if (!smf::state_kind_from_string(spec.substr(0, first), kind)) {
    return smf::Status(smf::ReasonCode::INVALID_STATE_KIND, "unrecognized state kind");
  }
  const std::string name = spec.substr(first + 1, second - first - 1);
  std::uint64_t generation = 0;
  for (const char c : spec.substr(second + 1, third - second - 1)) {
    if (c < '0' || c > '9') {
      return smf::Status(smf::ReasonCode::INVALID_GENERATION, "generation must be numeric");
    }
    generation = (generation * 10U) + static_cast<std::uint64_t>(c - '0');
  }
  const std::string path = spec.substr(third + 1);

  const auto status = agent.publish_file(kind, name, smf::StateGeneration(generation), path,
                                         "smf-endpoint", true);
  if (!status.ok()) return status;

  const auto object_id = smf::derive_state_object_id(kind, name);
  if (!object_id.ok()) return object_id.status();
  smf::ObjectStore& store = agent.object_store();
  const auto size = store.object_size(object_id.value(), smf::StateGeneration(generation));
  if (!size.ok()) return size.status();
  const auto digest = store.digest_object(object_id.value(), smf::StateGeneration(generation));
  if (!digest.ok()) return digest.status();

  // The endpoint announces what it holds. The chunk size must match what the
  // publish path used, so it is read back from the marker rather than guessed.
  const auto marker = store.read_commit_marker(object_id.value(), smf::StateGeneration(generation));
  if (!marker.ok()) return marker.status();
  SMF_RETURN_IF_ERROR(agent.announce(marker.value().object));
  return marker.value().object;
}

}  // namespace

int main(int argc, char** argv) {
  const auto parsed = smf::app::parse_args(argc, argv);
  if (!parsed.ok()) {
    std::fprintf(stderr, "%s\n", parsed.status().to_string().c_str());
    return 2;
  }
  const smf::app::Arguments& args = parsed.value();

  if (args.has("help")) {
    smf::app::print_usage("smf-endpoint", kUsage);
    return 0;
  }

  const std::string id = args.get("id");
  const std::string coordinator = args.get("coordinator");
  const std::string store = args.get("store");
  if (id.empty() || coordinator.empty() || store.empty()) {
    std::fprintf(stderr, "--id, --coordinator, and --store are required\n");
    smf::app::print_usage("smf-endpoint", kUsage);
    return 2;
  }

  const auto endpoint_id = smf::EndpointId::parse(id);
  if (!endpoint_id.ok()) {
    std::fprintf(stderr, "%s\n", endpoint_id.status().to_string().c_str());
    return 2;
  }
  const auto coordinator_address = smf::SocketAddress::parse(coordinator);
  if (!coordinator_address.ok()) {
    std::fprintf(stderr, "%s\n", coordinator_address.status().to_string().c_str());
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

  smf::EndpointAgentConfig config;
  config.endpoint_id = endpoint_id.value();
  config.store_root = store;
  config.shared_secret = secret.value();
  config.coordinator_address = coordinator_address.value();
  config.allow_resume = !args.has("no-resume");
  if (args.has("data")) {
    const auto address = smf::SocketAddress::parse(args.get("data"));
    if (!address.ok()) {
      std::fprintf(stderr, "%s\n", address.status().to_string().c_str());
      return 2;
    }
    config.data_listen = address.value();
  }
  config.policy.max_chunk_bytes = args.number("chunk-bytes", 1U << 20).value();

  auto started = smf::EndpointAgent::start(config);
  if (!started.ok()) {
    std::fprintf(stderr, "endpoint failed to start: %s\n", started.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<smf::EndpointAgent> agent = std::move(started).value();

  const smf::Status connected = agent->connect_to_coordinator();
  if (!connected.ok()) {
    std::fprintf(stderr, "registration failed: %s\n", connected.to_string().c_str());
    return 1;
  }

  const std::string publish = args.get("publish");
  if (!publish.empty()) {
    const auto published = publish_spec_to_file(publish, *agent);
    if (!published.ok()) {
      std::fprintf(stderr, "publish failed: %s\n", published.status().to_string().c_str());
      return 1;
    }
    std::printf("published %s\n", smf::describe(published.value()).c_str());
  }

  const std::string announce = args.get("announce");
  if (!announce.empty()) {
    const std::string json = "{\"data\":\"" + agent->data_address().to_string() + "\",\"epoch\":" +
                             std::to_string(agent->incarnation().epoch().value()) + "}\n";
    if (std::FILE* file = std::fopen(announce.c_str(), "wb")) {
      std::fwrite(json.data(), 1, json.size(), file);
      std::fclose(file);
    } else {
      std::fprintf(stderr, "could not write the announcement file\n");
      return 1;
    }
  } else {
    std::printf("endpoint %s data=%s epoch=%llu\n", id.c_str(),
                agent->data_address().to_string().c_str(),
                static_cast<unsigned long long>(agent->incarnation().epoch().value()));
    std::fflush(stdout);
  }

  agent->run();
  const smf::Status stopped = agent->stop();
  if (!stopped.ok()) {
    std::fprintf(stderr, "shutdown reported: %s\n", stopped.to_string().c_str());
    return 1;
  }
  return 0;
}
