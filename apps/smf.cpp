// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// smf: the operator command line. It speaks the coordinator's admin channel as
// an authenticated operator session, and it prints reason codes rather than
// verdicts it did not receive.

#include <cstdio>
#include <string>
#include <vector>

#include "args.hpp"
#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/logging.hpp"
#include "smf/session.hpp"
#include "smf/status.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"

namespace {

constexpr const char* kUsage =
    "usage: smf <command> --coordinator <host:port> --key <hex> [options]\n"
    "\n"
    "commands:\n"
    "  submit      --source <id> --destination <id> (--object <hex> | --kind <k> --name <n>)\n"
    "              --generation <n>\n"
    "  status      --movement <hex>\n"
    "  list        [--limit <n>] [--offset <n>]\n"
    "  cancel      --movement <hex>\n"
    "  reconcile   --movement <hex>\n"
    "  provenance  --movement <hex>\n"
    "  topology\n"
    "  policy\n"
    "  shutdown\n";

class AdminClient {
 public:
  explicit AdminClient(smf::FrameStream stream) : stream_(std::move(stream)) {}

  [[nodiscard]] smf::Status handshake(const smf::EndpointId& as, const smf::Bytes& secret) {
    smf::IdIssuer issuer;
    smf::PeerIdentity identity;
    identity.endpoint = as;
    identity.boot = issuer.new_boot_id();
    identity.epoch = smf::IncarnationEpoch(1);
    identity.role = smf::SessionRole::ADMIN;
    identity.contract = std::string(smf::kPeerContract);
    identity.capability_digest = smf::sha256(std::string_view("smf-cli"));

    const auto request = smf::make_hello_request(smf::as_bytes(secret), identity, issuer);
    if (!request.ok()) return request.status();
    {
      smf::CanonicalEncoder encoder;
      request.value().encode(encoder);
      SMF_RETURN_IF_ERROR(stream_.send(smf::MessageType::HELLO, encoder.view()));
    }
    const auto frame = stream_.receive();
    if (!frame.ok()) return frame.status();
    if (frame.value().header.type != smf::MessageType::HELLO_ACK) {
      return smf::Status(smf::ReasonCode::PROTOCOL_HANDSHAKE_FAILED,
                         "the coordinator refused the operator session");
    }
    const auto response = smf::decode_message<smf::HelloResponse>(frame.value());
    if (!response.ok()) return response.status();
    const auto key = smf::verify_hello_response(smf::as_bytes(secret), request.value(),
                                                response.value());
    if (!key.ok()) return key.status();
    stream_.codec().set_session_key(key.value().view());
    return smf::Status::success();
  }

  template <class Request, class Response>
  [[nodiscard]] smf::Result<Response> call(const Request& request) {
    SMF_RETURN_IF_ERROR(smf::send_message(stream_, request));
    auto frame = stream_.receive();
    if (!frame.ok()) return frame.status();
    if (frame.value().header.type == smf::MessageType::ERROR) {
      const auto error = smf::decode_message<smf::ErrorMessage>(frame.value());
      if (error.ok()) return smf::Status(error.value().code, error.value().detail);
      return smf::Status(smf::ReasonCode::PROTOCOL_MALFORMED, "the coordinator sent a bad error");
    }
    if (frame.value().header.type != smf::MessageTypeFor<Response>::value) {
      return smf::Status(smf::ReasonCode::PROTOCOL_UNKNOWN_MESSAGE,
                         std::string("expected ") +
                             smf::to_string(smf::MessageTypeFor<Response>::value) + ", received " +
                             smf::to_string(frame.value().header.type));
    }
    return smf::decode_message<Response>(frame.value());
  }

  [[nodiscard]] smf::FrameStream& stream() { return stream_; }

 private:
  smf::FrameStream stream_;
};

void print_record(const smf::MovementRecord& record) {
  std::printf("movement %s\n", record.id.hex().c_str());
  std::printf("  state            %s\n", smf::to_string(record.state));
  std::printf("  object           %s\n", smf::describe(record.object).c_str());
  std::printf("  source           %s epoch %llu\n", record.source.value().c_str(),
              static_cast<unsigned long long>(record.source_incarnation.epoch().value()));
  std::printf("  destination      %s epoch %llu\n", record.destination.value().c_str(),
              static_cast<unsigned long long>(record.destination_incarnation.epoch().value()));
  std::printf("  movement gen     %llu\n",
              static_cast<unsigned long long>(record.generation.value()));
  std::printf("  attempts         %u\n", record.attempt_count);
  std::printf("  bytes            %llu\n",
              static_cast<unsigned long long>(record.bytes_transferred));
  std::printf("  last reason      %s\n", smf::to_string(record.last_reason));
  if (!record.last_detail.empty()) {
    std::printf("  detail           %s\n", record.last_detail.c_str());
  }
  std::printf("  marker digest    %s\n",
              record.commit_marker_digest.is_zero() ? "(none)"
                                                    : record.commit_marker_digest.hex().c_str());
  std::printf("  topology gen     %llu\n",
              static_cast<unsigned long long>(record.topology_generation.value()));
  std::printf("  policy gen       %llu\n",
              static_cast<unsigned long long>(record.policy_generation.value()));
  std::printf("  repeatable       %s\n", record.repeatable ? "yes" : "no");
}

}  // namespace

int main(int argc, char** argv) {
  const auto parsed = smf::app::parse_args(argc, argv);
  if (!parsed.ok()) {
    std::fprintf(stderr, "%s\n", parsed.status().to_string().c_str());
    return 2;
  }
  const smf::app::Arguments& args = parsed.value();
  if (args.positional.empty() || args.has("help")) {
    smf::app::print_usage("smf", kUsage);
    return args.positional.empty() ? 2 : 0;
  }
  const std::string command = args.positional.front();

  const auto address = smf::SocketAddress::parse(args.get("coordinator", "127.0.0.1:9600"));
  if (!address.ok()) {
    std::fprintf(stderr, "%s\n", address.status().to_string().c_str());
    return 2;
  }
  const auto secret = smf::app::resolve_shared_secret(args);
  if (!secret.ok()) {
    std::fprintf(stderr, "%s\n", secret.status().to_string().c_str());
    return 2;
  }

  const auto connection = smf::TcpConnection::connect(address.value(), 10000);
  if (!connection.ok()) {
    std::fprintf(stderr, "cannot reach the coordinator: %s\n",
                 connection.status().to_string().c_str());
    return 1;
  }
  smf::TcpConnection socket = connection.value();
  smf::FrameStream stream(std::move(socket), 30000, 1U << 20);
  AdminClient client(std::move(stream));

  const auto operator_id = smf::EndpointId::parse(args.get("as", "smf-cli"));
  if (!operator_id.ok()) {
    std::fprintf(stderr, "%s\n", operator_id.status().to_string().c_str());
    return 2;
  }
  const smf::Status handshaken = client.handshake(operator_id.value(), secret.value());
  if (!handshaken.ok()) {
    std::fprintf(stderr, "operator session failed: %s\n", handshaken.to_string().c_str());
    return 1;
  }

  const auto movement_id = [&]() -> smf::Result<smf::MovementId> {
    const std::string text = args.get("movement");
    if (text.empty()) {
      return smf::Status(smf::ReasonCode::INVALID_ARGUMENT, "--movement is required");
    }
    return smf::MovementId::from_hex(text);
  };

  if (command == "submit") {
    smf::SubmitMovement request;
    const std::string object_text = args.get("object");
    if (!object_text.empty()) {
      const auto object = smf::StateObjectId::from_hex(object_text);
      if (!object.ok()) {
        std::fprintf(stderr, "%s\n", object.status().to_string().c_str());
        return 2;
      }
      request.object_id = object.value();
    } else {
      smf::StateKind kind = smf::StateKind::UNKNOWN;
      if (!smf::state_kind_from_string(args.get("kind"), kind)) {
        std::fprintf(stderr, "--kind is required when --object is not given\n");
        return 2;
      }
      const auto derived = smf::derive_state_object_id(kind, args.get("name"));
      if (!derived.ok()) {
        std::fprintf(stderr, "%s\n", derived.status().to_string().c_str());
        return 2;
      }
      request.object_id = derived.value();
    }
    request.object_generation = smf::StateGeneration(args.number("generation", 1).value());
    const auto source = smf::EndpointId::parse(args.get("source"));
    const auto destination = smf::EndpointId::parse(args.get("destination"));
    if (!source.ok() || !destination.ok()) {
      std::fprintf(stderr, "--source and --destination are required\n");
      return 2;
    }
    request.source = source.value();
    request.destination = destination.value();

    const auto answer = client.call<smf::SubmitMovement, smf::MovementAccepted>(request);
    if (!answer.ok()) {
      std::printf("REFUSED %s\n", answer.status().to_string().c_str());
      return 1;
    }
    std::printf("accepted movement %s state=%s\n", answer.value().movement_id.hex().c_str(),
                smf::to_string(answer.value().state));
    if (!answer.value().detail.empty()) {
      std::printf("note: %s\n", answer.value().detail.c_str());
    }
    return 0;
  }

  if (command == "status") {
    const auto id = movement_id();
    if (!id.ok()) {
      std::fprintf(stderr, "%s\n", id.status().to_string().c_str());
      return 2;
    }
    smf::QueryMovement request;
    request.movement_id = id.value();
    const auto answer = client.call<smf::QueryMovement, smf::MovementStatus>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    print_record(answer.value().record);
    return 0;
  }

  if (command == "list") {
    smf::ListMovements request;
    request.limit = static_cast<std::uint32_t>(args.number("limit", 20).value());
    request.offset = static_cast<std::uint32_t>(args.number("offset", 0).value());
    const auto answer = client.call<smf::ListMovements, smf::MovementList>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    for (const smf::MovementSummary& summary : answer.value().movements) {
      std::printf("%s %-15s gen=%llu %s -> %s attempts=%u bytes=%llu reason=%s\n",
                  summary.movement_id.hex().substr(0, 12).c_str(), smf::to_string(summary.state),
                  static_cast<unsigned long long>(summary.object_generation.value()),
                  summary.source.value().c_str(), summary.destination.value().c_str(),
                  summary.attempt_count,
                  static_cast<unsigned long long>(summary.bytes_transferred),
                  smf::to_string(summary.last_reason));
    }
    return 0;
  }

  if (command == "cancel" || command == "reconcile") {
    const auto id = movement_id();
    if (!id.ok()) {
      std::fprintf(stderr, "%s\n", id.status().to_string().c_str());
      return 2;
    }
    smf::Result<smf::MovementStatus> answer =
        command == "cancel"
            ? [&]() {
                smf::CancelMovement request;
                request.movement_id = id.value();
                return client.call<smf::CancelMovement, smf::MovementStatus>(request);
              }()
            : [&]() {
                smf::ReconcileMovement request;
                request.movement_id = id.value();
                return client.call<smf::ReconcileMovement, smf::MovementStatus>(request);
              }();
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    print_record(answer.value().record);
    return 0;
  }

  if (command == "provenance") {
    const auto id = movement_id();
    if (!id.ok()) {
      std::fprintf(stderr, "%s\n", id.status().to_string().c_str());
      return 2;
    }
    smf::ProvenanceRequest request;
    request.movement_id = id.value();
    const auto answer = client.call<smf::ProvenanceRequest, smf::ProvenanceReport>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    for (const smf::ProvenanceEvent& event : answer.value().events) {
      std::printf("%4llu %-14s %-15s gen=%-4llu %-32s %s\n",
                  static_cast<unsigned long long>(event.sequence), smf::to_string(event.kind),
                  smf::to_string(event.state),
                  static_cast<unsigned long long>(event.movement_generation.value()),
                  smf::to_string(event.reason), event.detail.c_str());
    }
    return 0;
  }

  if (command == "topology") {
    smf::TopologyRequest request;
    const auto answer = client.call<smf::TopologyRequest, smf::TopologyReport>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    std::printf("topology generation %llu, coordinator %s epoch %llu\n",
                static_cast<unsigned long long>(answer.value().topology_generation.value()),
                answer.value().coordinator.endpoint().value().c_str(),
                static_cast<unsigned long long>(answer.value().coordinator.epoch().value()));
    for (const smf::EndpointRegistration& endpoint : answer.value().endpoints) {
      std::printf("  %-20s %-8s epoch=%-4llu data=%s contract=%s\n", endpoint.endpoint.value().c_str(),
                  endpoint.live ? "live" : "dead",
                  static_cast<unsigned long long>(endpoint.incarnation.epoch().value()),
                  endpoint.data_address.to_string().c_str(), endpoint.contract.c_str());
    }
    return 0;
  }

  if (command == "policy") {
    smf::PolicyRequest request;
    const auto answer = client.call<smf::PolicyRequest, smf::PolicyReport>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    std::printf("policy generation %llu digest %s\n",
                static_cast<unsigned long long>(answer.value().policy.generation.value()),
                answer.value().policy_digest.hex().substr(0, 16).c_str());
    const smf::MovementPolicy& policy = answer.value().policy.policy;
    std::printf("  max_attempts            %u\n", policy.max_attempts);
    std::printf("  max_inflight_chunks     %u\n", policy.max_inflight_chunks);
    std::printf("  chunk bytes             %llu..%llu\n",
                static_cast<unsigned long long>(policy.min_chunk_bytes),
                static_cast<unsigned long long>(policy.max_chunk_bytes));
    std::printf("  max object bytes        %llu\n",
                static_cast<unsigned long long>(policy.max_object_bytes));
    std::printf("  allow_resume            %s\n", policy.allow_resume ? "yes" : "no");
    std::printf("  require compatibility   %s\n",
                policy.require_compatibility_evidence ? "yes" : "no");
    return 0;
  }

  if (command == "shutdown") {
    smf::ShutdownRequest request;
    const auto answer = client.call<smf::ShutdownRequest, smf::ShutdownAck>(request);
    if (!answer.ok()) {
      std::printf("ERROR %s\n", answer.status().to_string().c_str());
      return 1;
    }
    std::printf("coordinator acknowledged shutdown: %s\n",
                smf::to_string(answer.value().code));
    return 0;
  }

  std::fprintf(stderr, "unknown command '%s'\n", command.c_str());
  smf::app::print_usage("smf", kUsage);
  return 2;
}
