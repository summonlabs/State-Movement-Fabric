// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Authenticated session establishment.
//
// The coordinator, the endpoints, and the local operator channel share a
// pre-shared key. A session is established with a two-message handshake in
// which both sides prove knowledge of the key, both contribute a nonce, and the
// resulting session key is derived from both nonces. Identity is taken from the
// authenticated envelope: a peer's claimed endpoint id, boot id, epoch, role,
// and contract are all covered by the client MAC, so they cannot be edited in
// flight or spoofed by a caller that only knows the wire format.

#ifndef SMF_SESSION_HPP
#define SMF_SESSION_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "smf/codec.hpp"
#include "smf/digest.hpp"
#include "smf/ids.hpp"
#include "smf/status.hpp"

namespace smf {

enum class SessionRole : std::uint8_t {
  ENDPOINT = 1,
  ADMIN = 2,
};

[[nodiscard]] const char* to_string(SessionRole role) noexcept;
[[nodiscard]] bool session_role_from_string(std::string_view text, SessionRole& out) noexcept;

struct PeerIdentity {
  EndpointId endpoint;
  BootId boot;
  IncarnationEpoch epoch;
  SessionRole role = SessionRole::ENDPOINT;
  std::string contract;
  Digest capability_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<PeerIdentity> decode(CanonicalDecoder& decoder);
};

struct HelloRequest {
  Nonce client_nonce;
  PeerIdentity identity;
  Digest client_mac;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<HelloRequest> decode(CanonicalDecoder& decoder);
  [[nodiscard]] Status validate() const;
};

struct HelloResponse {
  Nonce server_nonce;
  SessionId session_id;
  PeerIdentity identity;
  Digest server_mac;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<HelloResponse> decode(CanonicalDecoder& decoder);
  [[nodiscard]] Status validate() const;
};

// MAC over the whole client claim, so that identity cannot be separated from
// the proof of key possession.
[[nodiscard]] Digest compute_client_mac(ByteView secret, const Nonce& client_nonce,
                                        const PeerIdentity& identity);

// MAC over both nonces, the client MAC, the session id, and the server claim.
[[nodiscard]] Digest compute_server_mac(ByteView secret, const HelloRequest& request,
                                        const Nonce& server_nonce, const SessionId& session_id,
                                        const PeerIdentity& identity);

// Session key derived from both nonces. The secret is never used directly as a
// session key.
[[nodiscard]] Digest derive_session_key(ByteView secret, const Nonce& client_nonce,
                                        const Nonce& server_nonce);

// Client side: builds a request with a fresh nonce and the client MAC.
[[nodiscard]] Result<HelloRequest> make_hello_request(ByteView secret, PeerIdentity identity,
                                                      IdIssuer& issuer);

// Server side: authenticates the request and produces the response. The server
// must not act on anything the client said until this returns OK.
[[nodiscard]] Result<HelloResponse> accept_hello_request(ByteView secret, const HelloRequest& request,
                                                         PeerIdentity server_identity,
                                                         const SessionId& session_id, IdIssuer& issuer);

// Client side: verifies the server's proof and returns the negotiated key.
[[nodiscard]] Result<Digest> verify_hello_response(ByteView secret, const HelloRequest& request,
                                                   const HelloResponse& response);

// Parses a key supplied on the command line or in the environment. Keys are
// lowercase or uppercase hexadecimal of exactly 64 characters (32 bytes).
[[nodiscard]] Result<Bytes> parse_shared_secret(std::string_view text);

}  // namespace smf

#endif  // SMF_SESSION_HPP
