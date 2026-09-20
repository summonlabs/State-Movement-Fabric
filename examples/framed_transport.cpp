// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A real loopback framed conversation: mutual authentication, a canonical
// message, and rejection of a frame authenticated with the wrong key.

#include <cstdio>
#include <string>
#include <thread>

#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/session.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"

namespace {

constexpr smf::Millis kBudget = 5000;

}  // namespace

int main() {
  const auto secret_result =
      smf::parse_shared_secret("000102030405060708090a0b0c0d0e0f"
                               "101112131415161718191a1b1c1d1e1f");
  if (!secret_result.ok()) {
    std::fprintf(stderr, "%s\n", secret_result.status().to_string().c_str());
    return 1;
  }
  const smf::Bytes secret = secret_result.value();

  const auto bind_address = smf::SocketAddress::parse("127.0.0.1:0");
  if (!bind_address.ok()) {
    std::fprintf(stderr, "%s\n", bind_address.status().to_string().c_str());
    return 1;
  }
  auto listener = smf::TcpListener::bind(bind_address.value());
  if (!listener.ok()) {
    std::fprintf(stderr, "%s\n", listener.status().to_string().c_str());
    return 1;
  }
  smf::TcpListener server = std::move(listener).value();
  std::printf("listening on %s\n", server.address().to_string().c_str());

  smf::IdIssuer issuer;
  smf::PeerIdentity server_identity;
  server_identity.endpoint = smf::EndpointId::parse("server").value();
  server_identity.boot = issuer.new_boot_id();
  server_identity.epoch = smf::IncarnationEpoch(1);
  server_identity.role = smf::SessionRole::ENDPOINT;
  server_identity.contract = std::string(smf::kPeerContract);
  server_identity.capability_digest = smf::sha256("server");

  smf::PeerIdentity client_identity = server_identity;
  client_identity.endpoint = smf::EndpointId::parse("client").value();
  client_identity.boot = issuer.new_boot_id();
  client_identity.capability_digest = smf::sha256("client");

  std::string observed;
  smf::Status server_status = smf::Status::success();
  std::thread serve([&]() {
    auto connection = server.accept(kBudget);
    if (!connection.ok()) {
      server_status = connection.status();
      return;
    }
    std::printf("server: connection accepted\n");
    smf::FrameStream stream(std::move(connection).value(), kBudget, 1U << 20);

    auto hello_frame = stream.receive();
    if (!hello_frame.ok()) {
      server_status = hello_frame.status();
      return;
    }
    auto hello = smf::decode_message<smf::HelloRequest>(hello_frame.value());
    if (!hello.ok()) {
      server_status = hello.status();
      return;
    }
    std::printf("server: hello from %s\n", hello.value().identity.endpoint.value().c_str());

    smf::IdIssuer server_issuer;
    const smf::SessionId session_id = server_issuer.new_session_id();
    auto response = smf::accept_hello_request(smf::as_bytes(secret), hello.value(), server_identity,
                                              session_id, server_issuer);
    if (!response.ok()) {
      server_status = response.status();
      return;
    }
    smf::CanonicalEncoder encoder;
    response.value().encode(encoder);
    const smf::Status sent = stream.send(smf::MessageType::HELLO_ACK, encoder.view());
    if (!sent.ok()) {
      server_status = sent;
      return;
    }
    const smf::Digest session_key =
        smf::derive_session_key(smf::as_bytes(secret), hello.value().client_nonce,
                                response.value().server_nonce);
    stream.codec().set_session_key(session_key.view());
    std::printf("server: session established\n");

    auto frame = stream.receive();
    if (!frame.ok()) {
      server_status = frame.status();
      return;
    }
    auto message = smf::decode_message<smf::AnnounceObject>(frame.value());
    if (!message.ok()) {
      server_status = message.status();
      return;
    }
    observed = smf::describe(message.value().descriptor);
  });

  auto connection = smf::TcpConnection::connect(server.address(), kBudget);
  if (!connection.ok()) {
    std::fprintf(stderr, "%s\n", connection.status().to_string().c_str());
    serve.join();
    return 1;
  }
  smf::FrameStream stream(std::move(connection).value(), kBudget, 1U << 20);

  smf::IdIssuer client_issuer;
  const auto request =
      smf::make_hello_request(smf::as_bytes(secret), client_identity, client_issuer);
  if (!request.ok()) return 1;
  {
    smf::CanonicalEncoder encoder;
    request.value().encode(encoder);
    if (!stream.send(smf::MessageType::HELLO, encoder.view()).ok()) return 1;
  }
  auto hello_ack_frame = stream.receive();
  if (!hello_ack_frame.ok()) return 1;
  auto hello_ack = smf::decode_message<smf::HelloResponse>(hello_ack_frame.value());
  if (!hello_ack.ok()) return 1;
  const auto key =
      smf::verify_hello_response(smf::as_bytes(secret), request.value(), hello_ack.value());
  if (!key.ok()) {
    std::fprintf(stderr, "handshake failed: %s\n", key.status().to_string().c_str());
    return 1;
  }
  stream.codec().set_session_key(key.value().view());
  std::printf("client: session established with %s\n",
              hello_ack.value().identity.endpoint.value().c_str());

  const auto descriptor = smf::StateObjectDescriptor::create(
      smf::StateKind::TENSOR, "example/tensor", smf::StateGeneration(1), smf::sha256("tensor"),
      4096, 4096, smf::system_clock().unix_millis(), "example");
  if (!descriptor.ok()) return 1;

  smf::AnnounceObject announce;
  announce.descriptor = descriptor.value();
  if (!smf::send_message(stream, announce).ok()) return 1;

  serve.join();
  if (!server_status.ok()) {
    std::fprintf(stderr, "server side failed: %s\n", server_status.to_string().c_str());
    return 1;
  }
  std::printf("server received: %s\n", observed.c_str());

  // A frame authenticated with a different key must not verify. The sender and
  // receiver here are plain codecs, so no socket is involved.
  smf::FrameCodec sender;
  sender.set_session_key(key.value().view());
  const smf::Digest other_key = smf::sha256("a different key");
  smf::FrameCodec receiver;
  receiver.set_session_key(other_key.view());

  smf::CanonicalEncoder encoder;
  announce.encode(encoder);
  const auto frame = sender.encode(smf::MessageType::ANNOUNCE_OBJECT, 0, encoder.view(), 1U << 20);
  if (!frame.ok()) return 1;
  const auto header = smf::decode_frame_header(
      smf::as_bytes(frame.value()).first(smf::kFrameHeaderBytes), 1U << 20);
  if (!header.ok()) return 1;
  const smf::ByteView payload(
      smf::as_bytes(frame.value()).data() + smf::kFrameHeaderBytes, encoder.size());
  const smf::Status verdict = receiver.verify(header.value(), payload, 1U << 20);
  std::printf("a frame authenticated with the wrong key: %s\n", verdict.to_string().c_str());
  return verdict.ok() ? 1 : 0;
}
