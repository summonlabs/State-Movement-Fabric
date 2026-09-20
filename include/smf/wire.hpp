// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The wire protocol messages.
//
// Every message is a plain struct that encodes through the one canonical
// primitive in the system (smf/codec.hpp). The rules are uniform, and they are
// what makes a payload safe to decode from an untrusted peer:
//
//   * encode() writes a domain string as its FIRST field, so a payload can never
//     be reinterpreted as a different message type;
//   * decode() creates no encoder: it reads the domain string first and rejects
//     a payload whose domain differs with PROTOCOL_CANONICAL_VIOLATION;
//   * every text field is read with an explicit bound, every blob with an
//     explicit bound, and every collection count through decoder.count(bound)
//     BEFORE the loop that consumes it;
//   * every decode() ends by calling validate() and returns its failure, so a
//     decoded message is never partially populated and never merely "usable";
//   * trailing bytes are the caller's business: decode_message<T>() below
//     rejects them with PROTOCOL_TRAILING_GARBAGE.
//
// Nested fabric types (StateObjectDescriptor, MovementRecord, PolicySet,
// ProvenanceEvent) keep their own codecs and are composed verbatim, so the
// bytes of a stored record and of a transmitted record cannot drift apart.
// EndpointRegistration has no codec of its own; this module owns its wire
// layout and keeps it here rather than in the topology module.
//
// Every struct is default-constructed into a safe, "unset" value: generations
// are zero, digest fields are zero, and validate() rejects both.

#ifndef SMF_WIRE_HPP
#define SMF_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "smf/codec.hpp"
#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/movement.hpp"
#include "smf/policy.hpp"
#include "smf/provenance.hpp"
#include "smf/session.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"
#include "smf/topology.hpp"
#include "smf/transport.hpp"

namespace smf {

// ---------------------------------------------------------------------------
// Wire bounds
// ---------------------------------------------------------------------------
//
// Structural bounds that live in smf/limits.hpp (kMaxTextBytes,
// kMaxDetailBytes, kMaxEndpointIdBytes, kMaxProvenanceEvents, kMaxEndpoints)
// are used directly. The constants below are the ones this protocol needs and
// that no other layer owns.

// A socket address host: a dotted quad, an IPv6 literal, or a DNS name.
inline constexpr std::size_t kMaxWireHostBytes = 255;

// A peer contract string ("smf.peer.v1"). Bounded far below kMaxTextBytes so
// that a contract can never be used to smuggle a bulk payload into a
// registration.
inline constexpr std::size_t kMaxWireContractBytes = 128;

// The largest chunk payload a DataChunk or VerifyResponse may carry. It matches
// the default frame payload ceiling, so a maximal chunk always fits in one
// frame.
inline constexpr std::size_t kMaxWireChunkBytes = 1U << 20;

// The domain string is short and fixed; anything longer is not one of ours.
inline constexpr std::size_t kMaxWireDomainBytes = 64;

// The largest page a ListMovements request may ask for. A MovementList reply
// can never exceed kMaxMovementSummaries in any case.
inline constexpr std::uint32_t kMaxWireListLimit = 1024;

// Bound on one MovementList payload. A reply larger than this is refused rather
// than truncated.
inline constexpr std::size_t kMaxMovementSummaries = 256;

// Decode limits used by decode_message<T>(). The input ceiling is the frame
// payload ceiling: a message can never be larger than the frame that carried
// it.
inline constexpr DecodeLimits kWireDecodeLimits{
    static_cast<std::size_t>(kMaxWireChunkBytes),
    static_cast<std::size_t>(kMaxTextBytes),
    static_cast<std::size_t>(kMaxFramePayloadBytes)};

// ---------------------------------------------------------------------------
// Peer identity hint (registration)
// ---------------------------------------------------------------------------

// A claimed peer identity. It is a claim, not a fact: the authenticated session
// envelope is what makes it true, and role is the SessionRole byte rather than
// the enum so that the wire layout does not depend on the enum's width.
struct PeerIdentityHint {
  static constexpr std::string_view kDomain = "SMF-MSG-PEER-IDENTITY-HINT-v1";

  EndpointId endpoint;
  BootId boot;
  IncarnationEpoch epoch;
  std::uint8_t role = static_cast<std::uint8_t>(SessionRole::ENDPOINT);
  std::string contract;
  Digest capability_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<PeerIdentityHint> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Transfer grant
// ---------------------------------------------------------------------------

// Whether reproducing the effect of a committed movement is safe to repeat.
enum class EffectClass : std::uint8_t {
  REPEATABLE = 0,
  NON_REPEATABLE = 1,
};

// The authority to move one object version, in one direction, once.
//
// The signature covers every preceding field and nothing else, so a grant can
// be verified without a second encoding path: encode_unsigned() is the exact
// byte string that compute_signature() MACs, under the domain
// "SMF-TRANSFER-GRANT-v1". The struct writes no domain of its own in encode();
// it is a value type, exactly like StateObjectDescriptor, and the domain lives
// in compute_signature() alone.
struct TransferGrant {
  static constexpr std::string_view kSignatureDomain = "SMF-TRANSFER-GRANT-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;

  StateObjectDescriptor object;

  EndpointId source;
  SourceIncarnation source_incarnation;
  EndpointId destination;
  DestinationIncarnation destination_incarnation;

  PolicyGeneration policy_generation;

  Nonce grant_nonce;

  std::uint64_t max_bytes = 0;
  std::uint32_t max_chunks = 0;
  Millis issued_unix_millis = 0;

  EffectClass effect_class = EffectClass::REPEATABLE;

  // HMAC over every preceding field.
  Digest signature;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;  // every field, signature included
  [[nodiscard]] static Result<TransferGrant> decode(CanonicalDecoder& decoder);
  void encode_unsigned(CanonicalEncoder& encoder) const;  // every field except the signature

  // HMAC-SHA-256 over a domain-separated encoding of encode_unsigned().
  [[nodiscard]] Digest compute_signature(ByteView key) const;

  [[nodiscard]] Status sign(ByteView key);
  [[nodiscard]] Status verify_signature(ByteView key) const;  // constant-time compare
};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// An endpoint registering itself with the coordinator.
struct RegisterRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-REGISTER-REQUEST-v1";

  PeerIdentityHint identity;
  SocketAddress service_address;
  SocketAddress data_address;
  Digest inventory_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<RegisterRequest> decode(CanonicalDecoder& decoder);
};

// The coordinator's answer: the generations every later decision is bound to,
// and the resource envelope the endpoint must stay inside.
struct RegisterAck {
  static constexpr std::string_view kDomain = "SMF-MSG-REGISTER-ACK-v1";

  TopologyGeneration topology_generation;
  PolicyGeneration policy_generation;
  EndpointIncarnation coordinator;
  Digest policy_digest;
  std::uint32_t max_inflight_chunks = 0;
  std::uint64_t max_chunk_bytes = 0;
  std::uint64_t max_object_bytes = 0;
  std::uint32_t io_budget_millis = 0;
  std::uint32_t transfer_budget_millis = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<RegisterAck> decode(CanonicalDecoder& decoder);
};

// A source telling the coordinator which object version it holds.
struct AnnounceObject {
  static constexpr std::string_view kDomain = "SMF-MSG-ANNOUNCE-OBJECT-v1";

  StateObjectDescriptor descriptor;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<AnnounceObject> decode(CanonicalDecoder& decoder);
};

struct AnnounceAck {
  static constexpr std::string_view kDomain = "SMF-MSG-ANNOUNCE-ACK-v1";

  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<AnnounceAck> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Authority and attempt lifecycle
// ---------------------------------------------------------------------------

// The coordinator delegating one transfer to a source.
struct GrantTransfer {
  static constexpr std::string_view kDomain = "SMF-MSG-GRANT-TRANSFER-v1";

  TransferGrant grant;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<GrantTransfer> decode(CanonicalDecoder& decoder);
};

// The source acknowledging receipt of a grant, echoing the grant nonce so the
// acknowledgement cannot be replayed against a different grant.
struct GrantAck {
  static constexpr std::string_view kDomain = "SMF-MSG-GRANT-ACK-v1";

  Digest nonce;
  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<GrantAck> decode(CanonicalDecoder& decoder);
};

// The coordinator telling a source to start one attempt.
struct ExecuteMovement {
  static constexpr std::string_view kDomain = "SMF-MSG-EXECUTE-MOVEMENT-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;
  Digest nonce;
  EndpointId source;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ExecuteMovement> decode(CanonicalDecoder& decoder);
};

// The source's report of how an attempt ended.
struct AttemptResult {
  static constexpr std::string_view kDomain = "SMF-MSG-ATTEMPT-RESULT-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;
  MovementState state = MovementState::PLANNED;
  ReasonCode code = ReasonCode::OK;
  std::string detail;
  Digest verified_digest;
  std::uint64_t bytes = 0;
  std::uint32_t chunks = 0;
  Digest marker_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<AttemptResult> decode(CanonicalDecoder& decoder);
};

struct CancelRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-CANCEL-REQUEST-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CancelRequest> decode(CanonicalDecoder& decoder);
};

struct CancelAck {
  static constexpr std::string_view kDomain = "SMF-MSG-CANCEL-ACK-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CancelAck> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Commit, verify, authority, cleanup (destination side)
// ---------------------------------------------------------------------------

struct CommitRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-COMMIT-REQUEST-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;
  StateObjectDescriptor object;
  // The endpoint the object moved from. The destination records it in the
  // commit marker, so provenance is not lost when the coordinator is gone.
  EndpointId source;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CommitRequest> decode(CanonicalDecoder& decoder);
};

struct CommitResult {
  static constexpr std::string_view kDomain = "SMF-MSG-COMMIT-RESULT-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  ReasonCode code = ReasonCode::OK;
  Digest marker_digest;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CommitResult> decode(CanonicalDecoder& decoder);
};

struct VerifyRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-VERIFY-REQUEST-v1";

  MovementId movement_id;
  MovementGeneration movement_generation;
  StateObjectId object_id;
  StateGeneration object_generation;
  bool full_digest_requested = false;
  // Which chunk of the object is being sampled, and how large a chunk this
  // version uses. Both are supplied by the coordinator so the destination never
  // infers the segmentation from its own policy.
  std::uint32_t chunk_index = 0;
  std::uint64_t chunk_bytes = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<VerifyRequest> decode(CanonicalDecoder& decoder);
};

struct VerifyResponse {
  static constexpr std::string_view kDomain = "SMF-MSG-VERIFY-RESPONSE-v1";

  MovementId movement_id;
  StateObjectId object_id;
  StateGeneration object_generation;
  ReasonCode code = ReasonCode::OK;
  Digest stored_digest;
  std::uint64_t stored_bytes = 0;
  std::uint32_t stored_chunks = 0;
  std::uint32_t chunk_index = 0;
  Digest chunk_digest;
  Bytes chunk_payload;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<VerifyResponse> decode(CanonicalDecoder& decoder);
};

struct AuthorityQuery {
  static constexpr std::string_view kDomain = "SMF-MSG-AUTHORITY-QUERY-v1";

  MovementId movement_id;
  StateObjectId object_id;
  StateGeneration object_generation;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<AuthorityQuery> decode(CanonicalDecoder& decoder);
};

// The destination's answer about what it durably holds. It carries four
// independent facts and one verdict, so a caller can never mistake "bytes are
// present" for "the movement is committed".
struct AuthorityReport {
  static constexpr std::string_view kDomain = "SMF-MSG-AUTHORITY-REPORT-v1";

  MovementId movement_id;
  ReasonCode code = ReasonCode::OK;
  bool bytes_present = false;
  bool verified = false;
  bool marker_present = false;
  bool authoritative = false;
  Digest marker_digest;
  std::uint64_t stored_bytes = 0;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<AuthorityReport> decode(CanonicalDecoder& decoder);
};

struct CleanupRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-CLEANUP-REQUEST-v1";

  MovementId movement_id;
  bool quarantine = false;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CleanupRequest> decode(CanonicalDecoder& decoder);
};

struct CleanupResult {
  static constexpr std::string_view kDomain = "SMF-MSG-CLEANUP-RESULT-v1";

  MovementId movement_id;
  ReasonCode code = ReasonCode::OK;
  std::uint64_t bytes_removed = 0;
  std::uint32_t entries_removed = 0;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CleanupResult> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Data plane
// ---------------------------------------------------------------------------

struct DataBegin {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-BEGIN-v1";

  Digest nonce;
  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;
  StateObjectDescriptor object;
  EndpointId destination;
  DestinationIncarnation destination_incarnation;

  // What the destination declares it already holds from a previous attempt. The
  // source either accepts it, in which case DataBeginAck echoes it, or refuses
  // it and answers with zero, which forces a clean transfer from the start.
  std::uint32_t resume_from_chunk = 0;
  std::uint64_t resume_from_offset = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataBegin> decode(CanonicalDecoder& decoder);
};

// Answers a DataBegin: whether the attempt may proceed and, when resuming,
// exactly where the destination already is.
struct DataBeginAck {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-BEGIN-ACK-v1";

  Digest nonce;
  ReasonCode code = ReasonCode::OK;
  std::uint32_t resume_from_chunk = 0;
  std::uint64_t resume_from_offset = 0;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataBeginAck> decode(CanonicalDecoder& decoder);
};

// One chunk of an object. chunk_length always equals the payload length: the
// chunk digest binds the two together, so a disagreement is a protocol error
// rather than something a receiver has to reconcile.
struct DataChunk {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-CHUNK-v1";

  MovementId movement_id;
  TransferAttemptId attempt;
  std::uint32_t chunk_index = 0;
  std::uint64_t chunk_offset = 0;
  std::uint64_t chunk_length = 0;
  Digest chunk_digest;
  Bytes payload;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataChunk> decode(CanonicalDecoder& decoder);
};

struct DataChunkAck {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-CHUNK-ACK-v1";

  MovementId movement_id;
  TransferAttemptId attempt;
  std::uint32_t highest_contiguous_index = 0;
  std::uint32_t duplicates_ignored = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataChunkAck> decode(CanonicalDecoder& decoder);
};

struct DataEnd {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-END-v1";

  MovementId movement_id;
  TransferAttemptId attempt;
  std::uint32_t total_chunks = 0;
  std::uint64_t total_bytes = 0;
  Digest content_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataEnd> decode(CanonicalDecoder& decoder);
};

struct DataResult {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-RESULT-v1";

  MovementId movement_id;
  TransferAttemptId attempt;
  ReasonCode code = ReasonCode::OK;
  Digest stored_digest;
  std::uint64_t stored_bytes = 0;
  std::uint32_t stored_chunks = 0;
  Digest marker_digest;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataResult> decode(CanonicalDecoder& decoder);
};

struct DataAbort {
  static constexpr std::string_view kDomain = "SMF-MSG-DATA-ABORT-v1";

  MovementId movement_id;
  TransferAttemptId attempt;
  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<DataAbort> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Movement administration
// ---------------------------------------------------------------------------

struct SubmitMovement {
  static constexpr std::string_view kDomain = "SMF-MSG-SUBMIT-MOVEMENT-v1";

  StateObjectId object_id;
  StateGeneration object_generation;
  EndpointId source;
  EndpointId destination;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<SubmitMovement> decode(CanonicalDecoder& decoder);
};

struct MovementAccepted {
  static constexpr std::string_view kDomain = "SMF-MSG-MOVEMENT-ACCEPTED-v1";

  MovementId movement_id;
  MovementState state = MovementState::PLANNED;
  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementAccepted> decode(CanonicalDecoder& decoder);
};

struct QueryMovement {
  static constexpr std::string_view kDomain = "SMF-MSG-QUERY-MOVEMENT-v1";

  MovementId movement_id;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<QueryMovement> decode(CanonicalDecoder& decoder);
};

struct MovementStatus {
  static constexpr std::string_view kDomain = "SMF-MSG-MOVEMENT-STATUS-v1";

  MovementRecord record;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementStatus> decode(CanonicalDecoder& decoder);
};

struct ListMovements {
  static constexpr std::string_view kDomain = "SMF-MSG-LIST-MOVEMENTS-v1";

  std::uint32_t limit = 0;
  std::uint32_t offset = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ListMovements> decode(CanonicalDecoder& decoder);
};

// One row of a movement list. It is not a standalone wire message; it is
// carried inside MovementList, and MessageTypeFor<MovementSummary> is therefore
// MessageType::INVALID.
struct MovementSummary {
  static constexpr std::string_view kDomain = "SMF-MSG-MOVEMENT-SUMMARY-v1";

  MovementId movement_id;
  MovementState state = MovementState::PLANNED;
  StateObjectId object_id;
  StateGeneration object_generation;
  EndpointId source;
  EndpointId destination;
  ReasonCode last_reason = ReasonCode::OK;
  std::uint32_t attempt_count = 0;
  std::uint64_t bytes_transferred = 0;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementSummary> decode(CanonicalDecoder& decoder);
};

struct MovementList {
  static constexpr std::string_view kDomain = "SMF-MSG-MOVEMENT-LIST-v1";

  std::vector<MovementSummary> movements;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<MovementList> decode(CanonicalDecoder& decoder);
};

struct CancelMovement {
  static constexpr std::string_view kDomain = "SMF-MSG-CANCEL-MOVEMENT-v1";

  MovementId movement_id;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CancelMovement> decode(CanonicalDecoder& decoder);
};

struct ReconcileMovement {
  static constexpr std::string_view kDomain = "SMF-MSG-RECONCILE-MOVEMENT-v1";

  MovementId movement_id;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ReconcileMovement> decode(CanonicalDecoder& decoder);
};

struct ProvenanceRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-PROVENANCE-REQUEST-v1";

  MovementId movement_id;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ProvenanceRequest> decode(CanonicalDecoder& decoder);
};

struct ProvenanceReport {
  static constexpr std::string_view kDomain = "SMF-MSG-PROVENANCE-REPORT-v1";

  MovementId movement_id;
  ReasonCode code = ReasonCode::OK;
  std::vector<ProvenanceEvent> events;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ProvenanceReport> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Read-only administrative queries
// ---------------------------------------------------------------------------

// Empty payload: the domain string is the whole message.
struct TopologyRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-TOPOLOGY-REQUEST-v1";

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<TopologyRequest> decode(CanonicalDecoder& decoder);
};

struct TopologyReport {
  static constexpr std::string_view kDomain = "SMF-MSG-TOPOLOGY-REPORT-v1";

  TopologyGeneration topology_generation;
  EndpointIncarnation coordinator;
  std::vector<EndpointRegistration> endpoints;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<TopologyReport> decode(CanonicalDecoder& decoder);
};

// Empty payload: the domain string is the whole message.
struct PolicyRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-POLICY-REQUEST-v1";

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<PolicyRequest> decode(CanonicalDecoder& decoder);
};

struct PolicyReport {
  static constexpr std::string_view kDomain = "SMF-MSG-POLICY-REPORT-v1";

  PolicySet policy;
  Digest policy_digest;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<PolicyReport> decode(CanonicalDecoder& decoder);
};

// Empty payload: the domain string is the whole message.
struct ShutdownRequest {
  static constexpr std::string_view kDomain = "SMF-MSG-SHUTDOWN-REQUEST-v1";

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ShutdownRequest> decode(CanonicalDecoder& decoder);
};

struct ShutdownAck {
  static constexpr std::string_view kDomain = "SMF-MSG-SHUTDOWN-ACK-v1";

  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ShutdownAck> decode(CanonicalDecoder& decoder);
};

struct ErrorMessage {
  static constexpr std::string_view kDomain = "SMF-MSG-ERROR-MESSAGE-v1";

  ReasonCode code = ReasonCode::OK;
  std::string detail;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<ErrorMessage> decode(CanonicalDecoder& decoder);
};

// ---------------------------------------------------------------------------
// Message type traits
// ---------------------------------------------------------------------------

// The frame message type that carries T. A type that is not a standalone wire
// message has no usable specialization and fails to compile when used with
// send_message() or receive_message().
template <class T>
struct MessageTypeFor;

template <>
struct MessageTypeFor<RegisterRequest> {
  static constexpr MessageType value = MessageType::REGISTER;
};
template <>
struct MessageTypeFor<RegisterAck> {
  static constexpr MessageType value = MessageType::REGISTER_ACK;
};
template <>
struct MessageTypeFor<AnnounceObject> {
  static constexpr MessageType value = MessageType::ANNOUNCE_OBJECT;
};
template <>
struct MessageTypeFor<AnnounceAck> {
  static constexpr MessageType value = MessageType::ANNOUNCE_ACK;
};
template <>
struct MessageTypeFor<GrantTransfer> {
  static constexpr MessageType value = MessageType::GRANT_TRANSFER;
};
template <>
struct MessageTypeFor<GrantAck> {
  static constexpr MessageType value = MessageType::GRANT_ACK;
};
template <>
struct MessageTypeFor<ExecuteMovement> {
  static constexpr MessageType value = MessageType::EXECUTE_MOVEMENT;
};
template <>
struct MessageTypeFor<AttemptResult> {
  static constexpr MessageType value = MessageType::ATTEMPT_RESULT;
};
template <>
struct MessageTypeFor<CancelRequest> {
  static constexpr MessageType value = MessageType::CANCEL;
};
template <>
struct MessageTypeFor<CancelAck> {
  static constexpr MessageType value = MessageType::CANCEL_ACK;
};
template <>
struct MessageTypeFor<CommitRequest> {
  static constexpr MessageType value = MessageType::COMMIT_REQUEST;
};
template <>
struct MessageTypeFor<CommitResult> {
  static constexpr MessageType value = MessageType::COMMIT_RESULT;
};
template <>
struct MessageTypeFor<VerifyRequest> {
  static constexpr MessageType value = MessageType::VERIFY_REQUEST;
};
template <>
struct MessageTypeFor<VerifyResponse> {
  static constexpr MessageType value = MessageType::VERIFY_RESPONSE;
};
template <>
struct MessageTypeFor<AuthorityQuery> {
  static constexpr MessageType value = MessageType::AUTHORITY_QUERY;
};
template <>
struct MessageTypeFor<AuthorityReport> {
  static constexpr MessageType value = MessageType::AUTHORITY_REPORT;
};
template <>
struct MessageTypeFor<CleanupRequest> {
  static constexpr MessageType value = MessageType::CLEANUP_REQUEST;
};
template <>
struct MessageTypeFor<CleanupResult> {
  static constexpr MessageType value = MessageType::CLEANUP_RESULT;
};
template <>
struct MessageTypeFor<DataBegin> {
  static constexpr MessageType value = MessageType::DATA_BEGIN;
};
template <>
struct MessageTypeFor<DataBeginAck> {
  static constexpr MessageType value = MessageType::DATA_BEGIN_ACK;
};
template <>
struct MessageTypeFor<DataChunk> {
  static constexpr MessageType value = MessageType::DATA_CHUNK;
};
template <>
struct MessageTypeFor<DataChunkAck> {
  static constexpr MessageType value = MessageType::DATA_CHUNK_ACK;
};
template <>
struct MessageTypeFor<DataEnd> {
  static constexpr MessageType value = MessageType::DATA_END;
};
template <>
struct MessageTypeFor<DataResult> {
  static constexpr MessageType value = MessageType::DATA_RESULT;
};
template <>
struct MessageTypeFor<DataAbort> {
  static constexpr MessageType value = MessageType::DATA_ABORT;
};
template <>
struct MessageTypeFor<SubmitMovement> {
  static constexpr MessageType value = MessageType::SUBMIT_MOVEMENT;
};
template <>
struct MessageTypeFor<MovementAccepted> {
  static constexpr MessageType value = MessageType::MOVEMENT_ACCEPTED;
};
template <>
struct MessageTypeFor<QueryMovement> {
  static constexpr MessageType value = MessageType::QUERY_MOVEMENT;
};
template <>
struct MessageTypeFor<MovementStatus> {
  static constexpr MessageType value = MessageType::MOVEMENT_STATUS;
};
template <>
struct MessageTypeFor<ListMovements> {
  static constexpr MessageType value = MessageType::LIST_MOVEMENTS;
};
// MovementSummary travels inside MovementList only.
template <>
struct MessageTypeFor<MovementSummary> {
  static constexpr MessageType value = MessageType::INVALID;
};
template <>
struct MessageTypeFor<MovementList> {
  static constexpr MessageType value = MessageType::MOVEMENT_LIST;
};
template <>
struct MessageTypeFor<CancelMovement> {
  static constexpr MessageType value = MessageType::CANCEL_MOVEMENT;
};
template <>
struct MessageTypeFor<ReconcileMovement> {
  static constexpr MessageType value = MessageType::RECONCILE_MOVEMENT;
};
template <>
struct MessageTypeFor<ProvenanceRequest> {
  static constexpr MessageType value = MessageType::PROVENANCE_REQUEST;
};
template <>
struct MessageTypeFor<ProvenanceReport> {
  static constexpr MessageType value = MessageType::PROVENANCE_REPORT;
};
template <>
struct MessageTypeFor<TopologyRequest> {
  static constexpr MessageType value = MessageType::TOPOLOGY_REQUEST;
};
template <>
struct MessageTypeFor<TopologyReport> {
  static constexpr MessageType value = MessageType::TOPOLOGY_REPORT;
};
template <>
struct MessageTypeFor<PolicyRequest> {
  static constexpr MessageType value = MessageType::POLICY_REQUEST;
};
template <>
struct MessageTypeFor<PolicyReport> {
  static constexpr MessageType value = MessageType::POLICY_REPORT;
};
template <>
struct MessageTypeFor<ShutdownRequest> {
  static constexpr MessageType value = MessageType::SHUTDOWN;
};
template <>
struct MessageTypeFor<ShutdownAck> {
  static constexpr MessageType value = MessageType::SHUTDOWN_ACK;
};
template <>
struct MessageTypeFor<ErrorMessage> {
  static constexpr MessageType value = MessageType::ERROR;
};

// ---------------------------------------------------------------------------
// Framed helpers
// ---------------------------------------------------------------------------

// Decodes T from a frame payload and insists that the payload was consumed
// exactly. The frame type is the caller's business here; receive_message()
// checks it.
//
// These are defined inline because they are templates: keeping the definition
// next to the declaration is what lets every translation unit use them without
// a hand-maintained list of explicit instantiations.
template <class T>
[[nodiscard]] Result<T> decode_message(const Frame& frame) {
  DecodeLimits limits;
  // The frame reader has already bounded the payload, so the decoder's own blob
  // bound only has to be generous enough for a chunk payload.
  limits.max_blob_bytes =
      frame.payload.size() > kMaxChunkBytes ? frame.payload.size() : static_cast<std::size_t>(kMaxChunkBytes);
  limits.max_text_bytes = kMaxObjectNameBytes;
  limits.max_input_bytes = frame.payload.size() + 1U;

  CanonicalDecoder decoder(smf::as_bytes(frame.payload), limits);
  auto message = T::decode(decoder);
  if (!message.ok()) return message.status();
  const Status consumed = decoder.require_end();
  if (!consumed.ok()) return consumed;
  return message;
}

// Validates, encodes, and sends T with the frame type MessageTypeFor<T>::value.
template <class T>
[[nodiscard]] Status send_message(FrameStream& stream, const T& message) {
  const Status valid = message.validate();
  if (!valid.ok()) return valid;
  CanonicalEncoder encoder;
  message.encode(encoder);
  return stream.send(MessageTypeFor<T>::value, encoder.view());
}

// Receives one frame, requires it to be MessageTypeFor<T>::value (otherwise
// PROTOCOL_UNKNOWN_MESSAGE), and decodes it.
template <class T>
[[nodiscard]] Result<T> receive_message(FrameStream& stream) {
  auto frame = stream.receive();
  if (!frame.ok()) return frame.status();
  if (frame.value().header.type != MessageTypeFor<T>::value) {
    return Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE,
                  std::string("expected ") + to_string(MessageTypeFor<T>::value) + ", received " +
                      to_string(frame.value().header.type));
  }
  return decode_message<T>(frame.value());
}

}  // namespace smf

#endif  // SMF_WIRE_HPP
