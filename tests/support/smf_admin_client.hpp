// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal operator client used by the distributed proofs. It speaks the same
// authenticated admin protocol as the smf command line.

#ifndef SMF_TEST_ADMIN_CLIENT_HPP
#define SMF_TEST_ADMIN_CLIENT_HPP

#include <string>
#include <utility>

#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/session.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"

namespace smftest {

class AdminClient {
 public:
  AdminClient() = default;

  [[nodiscard]] smf::Status connect(const smf::SocketAddress& address, const smf::Bytes& secret,
                                    const smf::EndpointId& as, smf::Millis budget = 10000) {
    auto connection = smf::TcpConnection::connect(address, budget);
    if (!connection.ok()) return connection.status();
    stream_ = std::make_unique<smf::FrameStream>(std::move(connection).value(), budget, 1U << 20);

    smf::IdIssuer issuer;
    smf::PeerIdentity identity;
    identity.endpoint = as;
    identity.boot = issuer.new_boot_id();
    identity.epoch = smf::IncarnationEpoch(1);
    identity.role = smf::SessionRole::ADMIN;
    identity.contract = std::string(smf::kPeerContract);
    identity.capability_digest = smf::sha256(std::string_view("smf-test-admin"));

    const auto request = smf::make_hello_request(smf::as_bytes(secret), identity, issuer);
    if (!request.ok()) return request.status();
    {
      smf::CanonicalEncoder encoder;
      request.value().encode(encoder);
      SMF_RETURN_IF_ERROR(stream_->send(smf::MessageType::HELLO, encoder.view()));
    }
    const auto frame = stream_->receive();
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
    stream_->codec().set_session_key(key.value().view());
    return smf::Status::success();
  }

  template <class Request, class Response>
  [[nodiscard]] smf::Result<Response> call(const Request& request) {
    SMF_RETURN_IF_ERROR(smf::send_message(*stream_, request));
    auto frame = stream_->receive();
    if (!frame.ok()) return frame.status();
    if (frame.value().header.type == smf::MessageType::ERROR) {
      const auto error = smf::decode_message<smf::ErrorMessage>(frame.value());
      if (error.ok()) return smf::Status(error.value().code, error.value().detail);
      return smf::Status(smf::ReasonCode::PROTOCOL_MALFORMED, "the coordinator sent a bad error");
    }
    if (frame.value().header.type != smf::MessageTypeFor<Response>::value) {
      return smf::Status(smf::ReasonCode::PROTOCOL_UNKNOWN_MESSAGE, "unexpected response type");
    }
    return smf::decode_message<Response>(frame.value());
  }

  void close() { stream_.reset(); }

 private:
  std::unique_ptr<smf::FrameStream> stream_;
};

}  // namespace smftest

#endif  // SMF_TEST_ADMIN_CLIENT_HPP
