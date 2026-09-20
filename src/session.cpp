// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/session.hpp"

#include "smf/limits.hpp"

namespace smf {
namespace {

constexpr std::size_t kMaxContractBytes = 64;

}  // namespace

const char* to_string(SessionRole role) noexcept {
  switch (role) {
    case SessionRole::ENDPOINT:
      return "ENDPOINT";
    case SessionRole::ADMIN:
      return "ADMIN";
  }
  return "UNRECOGNIZED_SESSION_ROLE";
}

bool session_role_from_string(std::string_view text, SessionRole& out) noexcept {
  if (text == "ENDPOINT") {
    out = SessionRole::ENDPOINT;
    return true;
  }
  if (text == "ADMIN") {
    out = SessionRole::ADMIN;
    return true;
  }
  return false;
}

Status PeerIdentity::validate() const {
  if (endpoint.empty()) {
    return Status(ReasonCode::INVALID_ID, "session identity requires an endpoint name");
  }
  if (boot.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "session identity requires a boot id");
  }
  if (!epoch.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "session identity requires a non-zero epoch");
  }
  if (contract.empty() || contract.size() > kMaxContractBytes) {
    return Status(ReasonCode::ENDPOINT_CONTRACT_MISMATCH,
                  "session identity requires a bounded contract string");
  }
  if (contract != kPeerContract) {
    return Status(ReasonCode::ENDPOINT_CONTRACT_MISMATCH,
                  "peer contract '" + contract + "' is not the contract this build speaks");
  }
  if (capability_digest.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, "session identity requires a capability digest");
  }
  return Status::success();
}

void PeerIdentity::encode(CanonicalEncoder& encoder) const {
  encoder.text(endpoint.value());
  boot.encode(encoder);
  encoder.u64(epoch.value());
  encoder.u8(static_cast<std::uint8_t>(role));
  encoder.text(contract);
  encoder.digest(capability_digest);
}

Result<PeerIdentity> PeerIdentity::decode(CanonicalDecoder& decoder) {
  PeerIdentity identity;

  const auto endpoint = decoder.text(kMaxEndpointIdBytes);
  if (!endpoint.ok()) return endpoint.status();
  const auto parsed = EndpointId::parse(endpoint.value());
  if (!parsed.ok()) return parsed.status();
  identity.endpoint = parsed.value();

  const auto boot = BootId::decode(decoder);
  if (!boot.ok()) return boot.status();
  identity.boot = boot.value();

  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  identity.epoch = IncarnationEpoch(epoch.value());

  const auto role = decoder.u8();
  if (!role.ok()) return role.status();
  if (role.value() != static_cast<std::uint8_t>(SessionRole::ENDPOINT) &&
      role.value() != static_cast<std::uint8_t>(SessionRole::ADMIN)) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION, "session role is not recognized");
  }
  identity.role = static_cast<SessionRole>(role.value());

  const auto contract = decoder.text(kMaxContractBytes);
  if (!contract.ok()) return contract.status();
  identity.contract = std::string(contract.value());

  const auto capability = decoder.digest();
  if (!capability.ok()) return capability.status();
  identity.capability_digest = capability.value();

  return identity;
}

void HelloRequest::encode(CanonicalEncoder& encoder) const {
  client_nonce.encode(encoder);
  identity.encode(encoder);
  encoder.digest(client_mac);
}

Result<HelloRequest> HelloRequest::decode(CanonicalDecoder& decoder) {
  HelloRequest request;

  const auto nonce = Nonce::decode(decoder);
  if (!nonce.ok()) return nonce.status();
  request.client_nonce = nonce.value();

  const auto identity = PeerIdentity::decode(decoder);
  if (!identity.ok()) return identity.status();
  request.identity = identity.value();

  const auto mac = decoder.digest();
  if (!mac.ok()) return mac.status();
  request.client_mac = mac.value();

  const Status status = request.validate();
  if (!status.ok()) return status;
  return request;
}

Status HelloRequest::validate() const {
  if (client_nonce.is_zero()) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "handshake nonce must not be zero");
  }
  if (client_mac.is_zero()) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "handshake MAC must not be zero");
  }
  return identity.validate();
}

void HelloResponse::encode(CanonicalEncoder& encoder) const {
  server_nonce.encode(encoder);
  session_id.encode(encoder);
  identity.encode(encoder);
  encoder.digest(server_mac);
}

Result<HelloResponse> HelloResponse::decode(CanonicalDecoder& decoder) {
  HelloResponse response;

  const auto nonce = Nonce::decode(decoder);
  if (!nonce.ok()) return nonce.status();
  response.server_nonce = nonce.value();

  const auto session = SessionId::decode(decoder);
  if (!session.ok()) return session.status();
  response.session_id = session.value();

  const auto identity = PeerIdentity::decode(decoder);
  if (!identity.ok()) return identity.status();
  response.identity = identity.value();

  const auto mac = decoder.digest();
  if (!mac.ok()) return mac.status();
  response.server_mac = mac.value();

  const Status status = response.validate();
  if (!status.ok()) return status;
  return response;
}

Status HelloResponse::validate() const {
  if (server_nonce.is_zero()) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "handshake nonce must not be zero");
  }
  if (session_id.is_zero()) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "session id must not be zero");
  }
  if (server_mac.is_zero()) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "handshake MAC must not be zero");
  }
  return identity.validate();
}

Digest compute_client_mac(ByteView secret, const Nonce& client_nonce, const PeerIdentity& identity) {
  CanonicalEncoder encoder("SMF-HELLO-CLIENT-v1");
  client_nonce.encode(encoder);
  identity.encode(encoder);
  return canonical_mac(secret, encoder);
}

Digest compute_server_mac(ByteView secret, const HelloRequest& request, const Nonce& server_nonce,
                          const SessionId& session_id, const PeerIdentity& identity) {
  CanonicalEncoder encoder("SMF-HELLO-SERVER-v1");
  request.client_nonce.encode(encoder);
  encoder.digest(request.client_mac);
  server_nonce.encode(encoder);
  session_id.encode(encoder);
  identity.encode(encoder);
  return canonical_mac(secret, encoder);
}

Digest derive_session_key(ByteView secret, const Nonce& client_nonce, const Nonce& server_nonce) {
  CanonicalEncoder encoder("SMF-SESSION-v1");
  client_nonce.encode(encoder);
  server_nonce.encode(encoder);
  return canonical_mac(secret, encoder);
}

Result<HelloRequest> make_hello_request(ByteView secret, PeerIdentity identity, IdIssuer& issuer) {
  HelloRequest request;
  request.client_nonce = issuer.new_nonce();
  request.identity = std::move(identity);
  request.client_mac = compute_client_mac(secret, request.client_nonce, request.identity);
  const Status status = request.validate();
  if (!status.ok()) return status;
  return request;
}

Result<HelloResponse> accept_hello_request(ByteView secret, const HelloRequest& request,
                                           PeerIdentity server_identity,
                                           const SessionId& session_id, IdIssuer& issuer) {
  const Status request_status = request.validate();
  if (!request_status.ok()) return request_status;

  const Digest expected = compute_client_mac(secret, request.client_nonce, request.identity);
  if (!constant_time_equal(expected.view(), request.client_mac.view())) {
    return Status(ReasonCode::PROTOCOL_AUTH_FAILED,
                  "the peer did not prove possession of the shared key");
  }

  HelloResponse response;
  response.server_nonce = issuer.new_nonce();
  response.session_id = session_id;
  response.identity = std::move(server_identity);
  response.server_mac = compute_server_mac(secret, request, response.server_nonce, session_id,
                                           response.identity);
  const Status response_status = response.validate();
  if (!response_status.ok()) return response_status;
  return response;
}

Result<Digest> verify_hello_response(ByteView secret, const HelloRequest& request,
                                     const HelloResponse& response) {
  const Status status = response.validate();
  if (!status.ok()) return status;

  const Digest expected = compute_server_mac(secret, request, response.server_nonce,
                                             response.session_id, response.identity);
  if (!constant_time_equal(expected.view(), response.server_mac.view())) {
    return Status(ReasonCode::PROTOCOL_AUTH_FAILED,
                  "the responder did not prove possession of the shared key");
  }
  return derive_session_key(secret, request.client_nonce, response.server_nonce);
}

Result<Bytes> parse_shared_secret(std::string_view text) {
  constexpr std::size_t kExpectedCharacters = Digest::kBytes * 2U;
  if (text.size() != kExpectedCharacters) {
    return Status(ReasonCode::INVALID_ARGUMENT,
                  "the shared secret must be 64 hexadecimal characters (32 bytes)");
  }
  Bytes raw;
  if (!from_hex(text, raw) || raw.size() != Digest::kBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "the shared secret is not valid hexadecimal");
  }
  return raw;
}

}  // namespace smf
