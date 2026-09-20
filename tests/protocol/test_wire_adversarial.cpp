// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Adversarial protocol proofs.
//
// Every wire message is round-tripped, then attacked: bad magic and version,
// zero and oversized lengths, truncation at every prefix, corrupt integrity
// fields, replayed and regressed sequence numbers, duplicate and forged grants,
// stale epochs, malformed identifiers, impossible enums, absurd counts, invalid
// Unicode, trailing garbage, and contradictory fields.
//
// The rule under test is that a decoder either produces a fully validated
// message or fails with a deterministic code, and never mutates authoritative
// state before the whole payload has been validated.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "smf/framing.hpp"
#include "smf/session.hpp"
#include "smf/wire.hpp"
#include "smf_fixture.hpp"
#include "smf_test.hpp"

using smf::ByteView;
using smf::Bytes;
using smf::Frame;
using smf::FrameCodec;
using smf::FrameHeader;
using smf::MessageType;
using smf::ReasonCode;

namespace {

constexpr std::uint32_t kMaxPayload = 1U << 20;

struct Fixture {
  MessageType type;
  std::string name;
  Bytes payload;
};

[[nodiscard]] smf::TransferGrant make_grant(const smf::StateObjectDescriptor& object,
                                            const Bytes& key) {
  smf::IdIssuer issuer;
  smf::TransferGrant grant;
  grant.movement_id = issuer.new_movement_id();
  grant.movement_generation = smf::MovementGeneration(1);
  grant.attempt = issuer.new_attempt_id();
  grant.object = object;
  grant.source = smf::EndpointId::parse("source-1").value();
  grant.source_incarnation =
      smf::SourceIncarnation::make(grant.source, issuer.new_boot_id(), smf::IncarnationEpoch(1))
          .value();
  grant.destination = smf::EndpointId::parse("dest-1").value();
  grant.destination_incarnation =
      smf::DestinationIncarnation::make(grant.destination, issuer.new_boot_id(),
                                        smf::IncarnationEpoch(1))
          .value();
  grant.policy_generation = smf::PolicyGeneration(1);
  grant.grant_nonce = issuer.new_nonce();
  grant.max_bytes = object.total_bytes;
  grant.max_chunks = object.chunk_count;
  grant.issued_unix_millis = smf::kEpoch2026;
  grant.effect_class = smf::EffectClass::REPEATABLE;
  (void)grant.sign(smf::as_bytes(key));
  return grant;
}

// One valid instance of every top-level message the protocol defines.
[[nodiscard]] std::vector<Fixture> all_fixtures(const Bytes& key) {
  std::vector<Fixture> out;
  const auto object =
      smftest::make_descriptor(smf::StateKind::KV, "adversarial/object", 3, 1U << 20, 256U << 10);
  const smf::MovementRecord record = smftest::make_record(object, "source-1", "dest-1");
  const smf::TransferGrant grant = make_grant(object, key);

  const auto add = [&out](const auto& message, const char* name) {
    smf::CanonicalEncoder encoder;
    message.encode(encoder);
    out.push_back(Fixture{smf::MessageTypeFor<std::decay_t<decltype(message)>>::value, name,
                          encoder.bytes()});
  };

  smf::IdIssuer issuer;
  const auto source = smf::EndpointId::parse("source-1").value();
  const auto destination = smf::EndpointId::parse("dest-1").value();

  smf::PeerIdentityHint hint;
  hint.endpoint = source;
  hint.boot = issuer.new_boot_id();
  hint.epoch = smf::IncarnationEpoch(1);
  hint.role = static_cast<std::uint8_t>(smf::SessionRole::ENDPOINT);
  hint.contract = std::string(smf::kPeerContract);
  hint.capability_digest = smf::sha256("capability");

  smf::RegisterRequest registration;
  registration.identity = hint;
  registration.service_address = smf::SocketAddress::parse("127.0.0.1:1000").value();
  registration.data_address = smf::SocketAddress::parse("127.0.0.1:1001").value();
  registration.inventory_digest = smf::sha256("inventory");
  add(registration, "RegisterRequest");

  smf::RegisterAck ack;
  ack.topology_generation = smf::TopologyGeneration(2);
  ack.policy_generation = smf::PolicyGeneration(1);
  ack.coordinator = smf::EndpointIncarnation::make(smf::EndpointId::parse("coordinator").value(),
                                                   issuer.new_boot_id(), smf::IncarnationEpoch(1))
                        .value();
  ack.policy_digest = smf::sha256("policy");
  ack.max_inflight_chunks = 8;
  ack.max_chunk_bytes = 1U << 20;
  ack.max_object_bytes = 1ULL << 30;
  ack.io_budget_millis = 30000;
  ack.transfer_budget_millis = 600000;
  add(ack, "RegisterAck");

  smf::AnnounceObject announce;
  announce.descriptor = object;
  add(announce, "AnnounceObject");

  smf::AnnounceAck announce_ack;
  announce_ack.code = ReasonCode::OK;
  announce_ack.detail = "announced";
  add(announce_ack, "AnnounceAck");

  smf::GrantTransfer grant_message;
  grant_message.grant = grant;
  add(grant_message, "GrantTransfer");

  smf::GrantAck grant_ack;
  grant_ack.nonce = smf::Digest(grant.grant_nonce.bytes());
  grant_ack.code = ReasonCode::OK;
  grant_ack.detail = "recorded";
  add(grant_ack, "GrantAck");

  smf::ExecuteMovement execute;
  execute.movement_id = grant.movement_id;
  execute.movement_generation = grant.movement_generation;
  execute.attempt = grant.attempt;
  execute.nonce = smf::Digest(grant.grant_nonce.bytes());
  execute.source = source;
  add(execute, "ExecuteMovement");

  smf::AttemptResult attempt;
  attempt.movement_id = grant.movement_id;
  attempt.movement_generation = grant.movement_generation;
  attempt.attempt = grant.attempt;
  attempt.state = smf::MovementState::BYTES_ARRIVED;
  attempt.code = ReasonCode::OK;
  attempt.detail = "arrived";
  attempt.verified_digest = object.content_digest;
  attempt.bytes = object.total_bytes;
  attempt.chunks = object.chunk_count;
  add(attempt, "AttemptResult");

  smf::CancelRequest cancel;
  cancel.movement_id = grant.movement_id;
  cancel.movement_generation = grant.movement_generation;
  add(cancel, "CancelRequest");

  smf::CancelAck cancel_ack;
  cancel_ack.movement_id = grant.movement_id;
  cancel_ack.movement_generation = grant.movement_generation;
  cancel_ack.code = ReasonCode::OK;
  cancel_ack.detail = "cancelled";
  add(cancel_ack, "CancelAck");

  smf::CommitRequest commit;
  commit.movement_id = grant.movement_id;
  commit.movement_generation = grant.movement_generation;
  commit.attempt = grant.attempt;
  commit.object = object;
  commit.source = source;
  add(commit, "CommitRequest");

  smf::CommitResult commit_result;
  commit_result.movement_id = grant.movement_id;
  commit_result.movement_generation = grant.movement_generation;
  commit_result.code = ReasonCode::OK;
  commit_result.marker_digest = smf::sha256("marker");
  commit_result.detail = "committed";
  add(commit_result, "CommitResult");

  smf::VerifyRequest verify;
  verify.movement_id = grant.movement_id;
  verify.movement_generation = grant.movement_generation;
  verify.object_id = object.object_id;
  verify.object_generation = object.generation;
  verify.full_digest_requested = false;
  verify.chunk_index = 1;
  verify.chunk_bytes = object.chunk_bytes;
  add(verify, "VerifyRequest");

  smf::VerifyResponse verify_response;
  verify_response.movement_id = grant.movement_id;
  verify_response.object_id = object.object_id;
  verify_response.object_generation = object.generation;
  verify_response.code = ReasonCode::OK;
  verify_response.stored_digest = object.content_digest;
  verify_response.stored_bytes = object.total_bytes;
  verify_response.chunk_index = 1;
  verify_response.chunk_digest = smf::sha256("chunk");
  verify_response.chunk_payload = smftest::pattern_bytes(11, 4096);
  add(verify_response, "VerifyResponse");

  smf::AuthorityQuery authority;
  authority.movement_id = grant.movement_id;
  authority.object_id = object.object_id;
  authority.object_generation = object.generation;
  add(authority, "AuthorityQuery");

  smf::AuthorityReport authority_report;
  authority_report.movement_id = grant.movement_id;
  authority_report.code = ReasonCode::OK;
  authority_report.bytes_present = true;
  authority_report.verified = true;
  authority_report.marker_present = true;
  authority_report.authoritative = true;
  authority_report.marker_digest = smf::sha256("marker");
  authority_report.stored_bytes = object.total_bytes;
  authority_report.detail = "authoritative";
  add(authority_report, "AuthorityReport");

  smf::CleanupRequest cleanup;
  cleanup.movement_id = grant.movement_id;
  cleanup.quarantine = true;
  add(cleanup, "CleanupRequest");

  smf::CleanupResult cleanup_result;
  cleanup_result.movement_id = grant.movement_id;
  cleanup_result.code = ReasonCode::OK;
  cleanup_result.bytes_removed = 4096;
  cleanup_result.entries_removed = 2;
  cleanup_result.detail = "removed";
  add(cleanup_result, "CleanupResult");

  smf::DataBegin begin;
  begin.nonce = smf::Digest(grant.grant_nonce.bytes());
  begin.movement_id = grant.movement_id;
  begin.movement_generation = grant.movement_generation;
  begin.attempt = grant.attempt;
  begin.object = object;
  begin.destination = destination;
  begin.destination_incarnation = grant.destination_incarnation;
  begin.resume_from_chunk = 2;
  begin.resume_from_offset = 2 * object.chunk_bytes;
  add(begin, "DataBegin");

  smf::DataBeginAck begin_ack;
  begin_ack.nonce = begin.nonce;
  begin_ack.code = ReasonCode::OK;
  begin_ack.resume_from_chunk = 2;
  begin_ack.resume_from_offset = begin.resume_from_offset;
  begin_ack.detail = "accepted";
  add(begin_ack, "DataBeginAck");

  smf::DataChunk chunk;
  chunk.movement_id = grant.movement_id;
  chunk.attempt = grant.attempt;
  chunk.chunk_index = 0;
  chunk.chunk_offset = 0;
  chunk.chunk_length = 4096;
  chunk.chunk_digest = smf::sha256("chunk");
  chunk.payload = smftest::pattern_bytes(12, 4096);
  add(chunk, "DataChunk");

  smf::DataChunkAck chunk_ack;
  chunk_ack.movement_id = grant.movement_id;
  chunk_ack.attempt = grant.attempt;
  chunk_ack.highest_contiguous_index = 3;
  chunk_ack.duplicates_ignored = 1;
  add(chunk_ack, "DataChunkAck");

  smf::DataEnd end;
  end.movement_id = grant.movement_id;
  end.attempt = grant.attempt;
  end.total_chunks = object.chunk_count;
  end.total_bytes = object.total_bytes;
  end.content_digest = object.content_digest;
  add(end, "DataEnd");

  smf::DataResult data_result;
  data_result.movement_id = grant.movement_id;
  data_result.attempt = grant.attempt;
  data_result.code = ReasonCode::OK;
  data_result.stored_digest = object.content_digest;
  data_result.stored_bytes = object.total_bytes;
  data_result.stored_chunks = object.chunk_count;
  data_result.detail = "stored";
  add(data_result, "DataResult");

  smf::DataAbort abort;
  abort.movement_id = grant.movement_id;
  abort.attempt = grant.attempt;
  abort.code = ReasonCode::CANCELLED_BY_OPERATOR;
  abort.detail = "cancelled";
  add(abort, "DataAbort");

  smf::SubmitMovement submit;
  submit.object_id = object.object_id;
  submit.object_generation = object.generation;
  submit.source = source;
  submit.destination = destination;
  add(submit, "SubmitMovement");

  smf::MovementAccepted accepted;
  accepted.movement_id = grant.movement_id;
  accepted.state = smf::MovementState::AUTHORIZED;
  accepted.code = ReasonCode::OK;
  accepted.detail = "accepted";
  add(accepted, "MovementAccepted");

  smf::QueryMovement query;
  query.movement_id = grant.movement_id;
  add(query, "QueryMovement");

  smf::MovementStatus status;
  status.record = record;
  add(status, "MovementStatus");

  smf::ListMovements list;
  list.limit = 10;
  list.offset = 5;
  add(list, "ListMovements");

  smf::MovementList movement_list;
  smf::MovementSummary summary;
  summary.movement_id = record.id;
  summary.state = record.state;
  summary.object_id = record.object.object_id;
  summary.object_generation = record.object.generation;
  summary.source = record.source;
  summary.destination = record.destination;
  summary.last_reason = ReasonCode::OK;
  summary.attempt_count = 1;
  summary.bytes_transferred = 4096;
  movement_list.movements.push_back(summary);
  add(movement_list, "MovementList");

  smf::CancelMovement cancel_movement;
  cancel_movement.movement_id = grant.movement_id;
  add(cancel_movement, "CancelMovement");

  smf::ReconcileMovement reconcile;
  reconcile.movement_id = grant.movement_id;
  add(reconcile, "ReconcileMovement");

  smf::ProvenanceRequest provenance;
  provenance.movement_id = grant.movement_id;
  add(provenance, "ProvenanceRequest");

  smf::ProvenanceReport provenance_report;
  provenance_report.movement_id = grant.movement_id;
  provenance_report.code = ReasonCode::OK;
  provenance_report.events = record.provenance.events();
  add(provenance_report, "ProvenanceReport");

  add(smf::TopologyRequest{}, "TopologyRequest");

  smf::TopologyReport topology;
  topology.topology_generation = smf::TopologyGeneration(2);
  topology.coordinator = ack.coordinator;
  smf::EndpointRegistration endpoint;
  endpoint.endpoint = source;
  endpoint.incarnation =
      smf::EndpointIncarnation::make(source, hint.boot, smf::IncarnationEpoch(1)).value();
  endpoint.service_address = registration.service_address;
  endpoint.data_address = registration.data_address;
  endpoint.contract = std::string(smf::kPeerContract);
  endpoint.capability_digest = hint.capability_digest;
  endpoint.registered_unix_millis = smf::kEpoch2026;
  endpoint.live = true;
  topology.endpoints.push_back(endpoint);
  add(topology, "TopologyReport");

  add(smf::PolicyRequest{}, "PolicyRequest");

  smf::PolicyReport policy;
  policy.policy.generation = smf::PolicyGeneration(1);
  policy.policy.policy = smf::MovementPolicy{};
  policy.policy_digest = smf::sha256("policy");
  add(policy, "PolicyReport");

  add(smf::ShutdownRequest{}, "ShutdownRequest");

  smf::ShutdownAck shutdown;
  shutdown.code = ReasonCode::OK;
  shutdown.detail = "shutting down";
  add(shutdown, "ShutdownAck");

  smf::ErrorMessage error;
  error.code = ReasonCode::INVALID_ARGUMENT;
  error.detail = "bad request";
  add(error, "ErrorMessage");

  return out;
}

// Decodes a payload as the message named by its frame type. This is what lets a
// single mutation loop cover every message without a per-message test.
[[nodiscard]] smf::Status decode_as(MessageType type, const Bytes& payload) {
  Frame frame;
  frame.header.type = type;
  frame.payload = payload;
  switch (type) {
    case MessageType::REGISTER: return smf::decode_message<smf::RegisterRequest>(frame).status();
    case MessageType::REGISTER_ACK: return smf::decode_message<smf::RegisterAck>(frame).status();
    case MessageType::ANNOUNCE_OBJECT: return smf::decode_message<smf::AnnounceObject>(frame).status();
    case MessageType::ANNOUNCE_ACK: return smf::decode_message<smf::AnnounceAck>(frame).status();
    case MessageType::GRANT_TRANSFER: return smf::decode_message<smf::GrantTransfer>(frame).status();
    case MessageType::GRANT_ACK: return smf::decode_message<smf::GrantAck>(frame).status();
    case MessageType::EXECUTE_MOVEMENT: return smf::decode_message<smf::ExecuteMovement>(frame).status();
    case MessageType::ATTEMPT_RESULT: return smf::decode_message<smf::AttemptResult>(frame).status();
    case MessageType::CANCEL: return smf::decode_message<smf::CancelRequest>(frame).status();
    case MessageType::CANCEL_ACK: return smf::decode_message<smf::CancelAck>(frame).status();
    case MessageType::COMMIT_REQUEST: return smf::decode_message<smf::CommitRequest>(frame).status();
    case MessageType::COMMIT_RESULT: return smf::decode_message<smf::CommitResult>(frame).status();
    case MessageType::VERIFY_REQUEST: return smf::decode_message<smf::VerifyRequest>(frame).status();
    case MessageType::VERIFY_RESPONSE: return smf::decode_message<smf::VerifyResponse>(frame).status();
    case MessageType::AUTHORITY_QUERY: return smf::decode_message<smf::AuthorityQuery>(frame).status();
    case MessageType::AUTHORITY_REPORT: return smf::decode_message<smf::AuthorityReport>(frame).status();
    case MessageType::CLEANUP_REQUEST: return smf::decode_message<smf::CleanupRequest>(frame).status();
    case MessageType::CLEANUP_RESULT: return smf::decode_message<smf::CleanupResult>(frame).status();
    case MessageType::DATA_BEGIN: return smf::decode_message<smf::DataBegin>(frame).status();
    case MessageType::DATA_BEGIN_ACK: return smf::decode_message<smf::DataBeginAck>(frame).status();
    case MessageType::DATA_CHUNK: return smf::decode_message<smf::DataChunk>(frame).status();
    case MessageType::DATA_CHUNK_ACK: return smf::decode_message<smf::DataChunkAck>(frame).status();
    case MessageType::DATA_END: return smf::decode_message<smf::DataEnd>(frame).status();
    case MessageType::DATA_RESULT: return smf::decode_message<smf::DataResult>(frame).status();
    case MessageType::DATA_ABORT: return smf::decode_message<smf::DataAbort>(frame).status();
    case MessageType::SUBMIT_MOVEMENT: return smf::decode_message<smf::SubmitMovement>(frame).status();
    case MessageType::MOVEMENT_ACCEPTED: return smf::decode_message<smf::MovementAccepted>(frame).status();
    case MessageType::QUERY_MOVEMENT: return smf::decode_message<smf::QueryMovement>(frame).status();
    case MessageType::MOVEMENT_STATUS: return smf::decode_message<smf::MovementStatus>(frame).status();
    case MessageType::LIST_MOVEMENTS: return smf::decode_message<smf::ListMovements>(frame).status();
    case MessageType::MOVEMENT_LIST: return smf::decode_message<smf::MovementList>(frame).status();
    case MessageType::CANCEL_MOVEMENT: return smf::decode_message<smf::CancelMovement>(frame).status();
    case MessageType::RECONCILE_MOVEMENT: return smf::decode_message<smf::ReconcileMovement>(frame).status();
    case MessageType::PROVENANCE_REQUEST: return smf::decode_message<smf::ProvenanceRequest>(frame).status();
    case MessageType::PROVENANCE_REPORT: return smf::decode_message<smf::ProvenanceReport>(frame).status();
    case MessageType::TOPOLOGY_REQUEST: return smf::decode_message<smf::TopologyRequest>(frame).status();
    case MessageType::TOPOLOGY_REPORT: return smf::decode_message<smf::TopologyReport>(frame).status();
    case MessageType::POLICY_REQUEST: return smf::decode_message<smf::PolicyRequest>(frame).status();
    case MessageType::POLICY_REPORT: return smf::decode_message<smf::PolicyReport>(frame).status();
    case MessageType::SHUTDOWN: return smf::decode_message<smf::ShutdownRequest>(frame).status();
    case MessageType::SHUTDOWN_ACK: return smf::decode_message<smf::ShutdownAck>(frame).status();
    case MessageType::ERROR: return smf::decode_message<smf::ErrorMessage>(frame).status();
    default:
      return smf::Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE, "no decoder for that frame type");
  }
}

[[nodiscard]] Bytes test_key() {
  return smf::parse_shared_secret(
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      .value();
}

}  // namespace

SMF_TEST(protocol, every_message_round_trips_byte_for_byte) {
  const std::vector<Fixture> fixtures = all_fixtures(test_key());
  SMF_CHECK(fixtures.size() >= 40);
  for (const Fixture& fixture : fixtures) {
    const smf::Status decoded = decode_as(fixture.type, fixture.payload);
    if (!decoded.ok()) {
      smftest::fail(__FILE__, __LINE__, fixture.name + " did not decode: " + decoded.to_string());
    }
  }
}

SMF_TEST(protocol, every_message_rejects_trailing_garbage) {
  const std::vector<Fixture> fixtures = all_fixtures(test_key());
  for (const Fixture& fixture : fixtures) {
    Bytes extended = fixture.payload;
    extended.push_back(0x00);
    const smf::Status decoded = decode_as(fixture.type, extended);
    if (decoded.ok()) {
      smftest::fail(__FILE__, __LINE__, fixture.name + " accepted a trailing byte");
    }
    if (decoded.code() != ReasonCode::PROTOCOL_TRAILING_GARBAGE) {
      smftest::fail(__FILE__, __LINE__,
                    fixture.name + " rejected trailing garbage with the wrong code: " +
                        decoded.to_string());
    }
  }
}

SMF_TEST(protocol, every_message_rejects_every_truncated_prefix) {
  const std::vector<Fixture> fixtures = all_fixtures(test_key());
  for (const Fixture& fixture : fixtures) {
    for (std::size_t length = 0; length < fixture.payload.size(); ++length) {
      const Bytes prefix(fixture.payload.begin(),
                         fixture.payload.begin() + static_cast<std::ptrdiff_t>(length));
      const smf::Status decoded = decode_as(fixture.type, prefix);
      if (decoded.ok()) {
        smftest::fail(__FILE__, __LINE__,
                      fixture.name + " decoded successfully from a " + std::to_string(length) +
                          "-byte prefix of a " + std::to_string(fixture.payload.size()) +
                          "-byte message");
      }
    }
  }
}

SMF_TEST(protocol, every_message_rejects_a_corrupt_domain_string) {
  const std::vector<Fixture> fixtures = all_fixtures(test_key());
  for (const Fixture& fixture : fixtures) {
    if (fixture.payload.size() < 40) continue;
    Bytes mutated = fixture.payload;
    // The first field is the length-prefixed domain string; flip a byte inside it.
    mutated[12] = static_cast<smf::Byte>(mutated[12] ^ 0x20U);
    const smf::Status decoded = decode_as(fixture.type, mutated);
    if (decoded.ok()) {
      smftest::fail(__FILE__, __LINE__, fixture.name + " accepted a corrupted domain string");
    }
    if (decoded.code() != ReasonCode::PROTOCOL_CANONICAL_VIOLATION) {
      smftest::fail(__FILE__, __LINE__,
                    fixture.name + " rejected a corrupted domain with the wrong code: " +
                        decoded.to_string());
    }
  }
}

SMF_TEST(protocol, every_message_survives_random_mutation_without_crashing) {
  const std::vector<Fixture> fixtures = all_fixtures(test_key());
  SMF_PROPERTY(120) {
    const Fixture& fixture = fixtures[ctx.rng.below(fixtures.size())];
    Bytes mutated = fixture.payload;
    const std::size_t mutations = 1 + ctx.rng.below(6);
    for (std::size_t i = 0; i < mutations; ++i) {
      const std::size_t at = ctx.rng.below(mutated.size());
      mutated[at] = static_cast<smf::Byte>(ctx.rng.next_u32() & 0xFFU);
    }
    // A mutated payload either fails with a code or decodes into a message that
    // re-validates and re-encodes. It must never crash or corrupt memory.
    const smf::Status decoded = decode_as(fixture.type, mutated);
    if (decoded.code() == ReasonCode::OK) {
      const smf::Status revalidated = decode_as(fixture.type, mutated);
      SMF_CHECK_OK(revalidated);
    }
  }
}

SMF_TEST(protocol, frame_header_rejects_bad_magic_and_version) {
  FrameHeader header;
  header.type = MessageType::HEARTBEAT;
  header.payload_length = 0;
  header.sequence = 1;
  Bytes raw(smf::kFrameHeaderBytes, smf::Byte{0});
  smf::encode_frame_header(header, smf::ByteSpan(raw.data(), raw.size()));
  SMF_CHECK_OK(smf::decode_frame_header(smf::as_bytes(raw), kMaxPayload));

  Bytes bad_magic = raw;
  bad_magic[0] = 'X';
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(bad_magic), kMaxPayload),
                 ReasonCode::PROTOCOL_MAGIC_MISMATCH);

  Bytes bad_version = raw;
  bad_version[4] = 99;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(bad_version), kMaxPayload),
                 ReasonCode::PROTOCOL_VERSION_MISMATCH);

  Bytes short_header(raw.begin(), raw.begin() + 20);
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(short_header), kMaxPayload),
                 ReasonCode::PROTOCOL_TRUNCATED);
}

SMF_TEST(protocol, frame_header_rejects_reserved_and_unknown_flags) {
  FrameHeader header;
  header.type = MessageType::HEARTBEAT;
  header.sequence = 1;
  Bytes raw(smf::kFrameHeaderBytes, smf::Byte{0});
  smf::encode_frame_header(header, smf::ByteSpan(raw.data(), raw.size()));

  Bytes reserved = raw;
  reserved[6] = 1;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(reserved), kMaxPayload),
                 ReasonCode::PROTOCOL_RESERVED_NONZERO);

  Bytes reserved2 = raw;
  reserved2[11] = 1;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(reserved2), kMaxPayload),
                 ReasonCode::PROTOCOL_RESERVED_NONZERO);

  Bytes flags = raw;
  flags[5] = 0x80U;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(flags), kMaxPayload),
                 ReasonCode::PROTOCOL_FLAGS_INVALID);

  Bytes zero_sequence = raw;
  for (std::size_t i = 16; i < 24; ++i) zero_sequence[i] = 0;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(zero_sequence), kMaxPayload),
                 ReasonCode::PROTOCOL_CANONICAL_VIOLATION);
}

SMF_TEST(protocol, frame_header_rejects_zero_and_oversized_lengths) {
  FrameHeader header;
  header.type = MessageType::DATA_CHUNK;
  header.sequence = 1;
  header.payload_length = 0;
  Bytes raw(smf::kFrameHeaderBytes, smf::Byte{0});
  smf::encode_frame_header(header, smf::ByteSpan(raw.data(), raw.size()));
  // A zero length is legal for messages that carry no fields.
  SMF_CHECK_OK(smf::decode_frame_header(smf::as_bytes(raw), kMaxPayload));

  Bytes huge = raw;
  for (std::size_t i = 0; i < 4; ++i) {
    huge[12 + i] = 0xFFU;
  }
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(huge), kMaxPayload),
                 ReasonCode::PROTOCOL_PAYLOAD_TOO_LARGE);

  header.payload_length = kMaxPayload + 1;
  smf::encode_frame_header(header, smf::ByteSpan(huge.data(), huge.size()));
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(huge), kMaxPayload),
                 ReasonCode::PROTOCOL_PAYLOAD_TOO_LARGE);
}

SMF_TEST(protocol, frame_header_rejects_unknown_message_type) {
  FrameHeader header;
  header.type = MessageType::HEARTBEAT;
  header.sequence = 1;
  Bytes raw(smf::kFrameHeaderBytes, smf::Byte{0});
  smf::encode_frame_header(header, smf::ByteSpan(raw.data(), raw.size()));
  raw[8] = 0xEEU;
  raw[9] = 0xEEU;
  SMF_CHECK_CODE(smf::decode_frame_header(smf::as_bytes(raw), kMaxPayload),
                 ReasonCode::PROTOCOL_UNKNOWN_MESSAGE);
}

SMF_TEST(protocol, frame_codec_requires_a_session_before_any_message) {
  const Bytes key = test_key();
  FrameCodec codec;
  smf::CanonicalEncoder encoder;
  const auto refused = codec.encode(MessageType::HEARTBEAT, 0, encoder.view(), kMaxPayload);
  SMF_CHECK(!refused.ok());
  SMF_CHECK_CODE(refused, ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED);

  // Handshake frames are only legal before the session is keyed.
  const auto hello = codec.encode(MessageType::HELLO, 0, encoder.view(), kMaxPayload);
  SMF_CHECK_OK(hello);
  codec.set_session_key(smf::as_bytes(key));
  const auto late_hello = codec.encode(MessageType::HELLO, 0, encoder.view(), kMaxPayload);
  SMF_CHECK(!late_hello.ok());
  SMF_CHECK_CODE(late_hello, ReasonCode::PROTOCOL_STATE_VIOLATION);
}

SMF_TEST(protocol, frame_codec_rejects_replayed_and_regressed_sequences) {
  const Bytes key = test_key();
  FrameCodec sender;
  FrameCodec receiver;
  sender.set_session_key(smf::as_bytes(key));
  receiver.set_session_key(smf::as_bytes(key));

  smf::CanonicalEncoder encoder;
  const auto first_result = sender.encode(MessageType::HEARTBEAT, 0, encoder.view(), kMaxPayload);
  SMF_REQUIRE(first_result.ok());
  const Bytes first = first_result.value();
  const auto second_result = sender.encode(MessageType::HEARTBEAT, 0, encoder.view(), kMaxPayload);
  SMF_REQUIRE(second_result.ok());
  const Bytes second = second_result.value();
  const auto third_result = sender.encode(MessageType::HEARTBEAT, 0, encoder.view(), kMaxPayload);
  SMF_REQUIRE(third_result.ok());
  const Bytes third = third_result.value();

  const auto header_of = [](const Bytes& frame) {
    return smf::decode_frame_header(smf::as_bytes(frame).first(smf::kFrameHeaderBytes), kMaxPayload)
        .value();
  };
  const auto payload_of = [](const Bytes& frame) {
    return smf::ByteView(smf::as_bytes(frame).data() + smf::kFrameHeaderBytes,
                         frame.size() - smf::kFrameHeaderBytes);
  };

  // The first frame is accepted; replaying it is refused as a replay.
  SMF_CHECK_OK(receiver.verify(header_of(first), payload_of(first), kMaxPayload));
  SMF_CHECK_CODE(receiver.verify(header_of(first), payload_of(first), kMaxPayload),
                 ReasonCode::PROTOCOL_SEQUENCE_REPLAY);

  // Skipping ahead is refused as a regression in ordering.
  SMF_CHECK_CODE(receiver.verify(header_of(third), payload_of(third), kMaxPayload),
                 ReasonCode::PROTOCOL_SEQUENCE_REGRESSION);
  SMF_CHECK_OK(receiver.verify(header_of(second), payload_of(second), kMaxPayload));
}

SMF_TEST(protocol, frame_codec_rejects_corrupt_integrity_and_wrong_keys) {
  const Bytes key = test_key();
  const smf::Digest other_digest = smf::sha256("a different key");
  const Bytes other(other_digest.view().begin(), other_digest.view().end());
  FrameCodec sender;
  sender.set_session_key(smf::as_bytes(key));

  smf::CanonicalEncoder encoder;
  encoder.u64(0x1122334455667788ULL);
  const auto frame_result = sender.encode(MessageType::HEARTBEAT, 0, encoder.view(), kMaxPayload);
  SMF_REQUIRE(frame_result.ok());
  const Bytes frame = frame_result.value();

  const auto header =
      smf::decode_frame_header(smf::as_bytes(frame).first(smf::kFrameHeaderBytes), kMaxPayload).value();
  const smf::ByteView payload(smf::as_bytes(frame).data() + smf::kFrameHeaderBytes,
                              frame.size() - smf::kFrameHeaderBytes);

  FrameCodec wrong;
  wrong.set_session_key(smf::as_bytes(other));
  SMF_CHECK_CODE(wrong.verify(header, payload, kMaxPayload), ReasonCode::PROTOCOL_AUTH_FAILED);

  FrameCodec right;
  right.set_session_key(smf::as_bytes(key));
  Bytes tampered(payload.begin(), payload.end());
  tampered[0] = static_cast<smf::Byte>(tampered[0] ^ 0x01U);
  SMF_CHECK_CODE(right.verify(header, smf::as_bytes(tampered), kMaxPayload),
                 ReasonCode::PROTOCOL_AUTH_FAILED);

  // A tag that was never computed over these bytes is refused too.
  Bytes tampered_tag(frame);
  tampered_tag[24] = static_cast<smf::Byte>(tampered_tag[24] ^ 0x80U);
  FrameCodec third;
  third.set_session_key(smf::as_bytes(key));
  const auto tampered_header =
      smf::decode_frame_header(smf::as_bytes(tampered_tag).first(smf::kFrameHeaderBytes), kMaxPayload)
          .value();
  SMF_CHECK_CODE(third.verify(tampered_header,
                              smf::ByteView(smf::as_bytes(tampered_tag).data() + smf::kFrameHeaderBytes,
                                            tampered_tag.size() - smf::kFrameHeaderBytes),
                              kMaxPayload),
                 ReasonCode::PROTOCOL_AUTH_FAILED);
}

SMF_TEST(protocol, transfer_grant_signature_binds_every_field) {
  const Bytes key = test_key();
  const auto object =
      smftest::make_descriptor(smf::StateKind::MODEL, "grant/object", 2, 1U << 20, 256U << 10);
  smf::TransferGrant grant = make_grant(object, key);
  SMF_CHECK_OK(grant.verify_signature(smf::as_bytes(key)));

  // A different key must not verify the same grant.
  const Bytes other = smf::parse_shared_secret(
                          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                          .value();
  SMF_CHECK_CODE(grant.verify_signature(smf::as_bytes(other)), ReasonCode::PROTOCOL_AUTH_FAILED);

  // Flipping any single byte of the signed region invalidates the signature.
  for (std::size_t attempt = 0; attempt < 6; ++attempt) {
    smf::TransferGrant tampered = make_grant(object, key);
    switch (attempt) {
      case 0:
        tampered.max_bytes += 1;
        break;
      case 1:
        tampered.max_chunks += 1;
        break;
      case 2:
        tampered.effect_class = smf::EffectClass::NON_REPEATABLE;
        break;
      case 3:
        tampered.grant_nonce = smf::IdIssuer().new_nonce();
        break;
      case 4:
        tampered.movement_generation = smf::MovementGeneration(9);
        break;
      default:
        tampered.policy_generation = smf::PolicyGeneration(9);
        break;
    }
    SMF_CHECK_CODE(tampered.verify_signature(smf::as_bytes(key)),
                   ReasonCode::PROTOCOL_AUTH_FAILED);
  }

  // A tampered signature itself is refused.
  smf::TransferGrant forged = make_grant(object, key);
  forged.signature = smf::sha256("forged");
  SMF_CHECK_CODE(forged.verify_signature(smf::as_bytes(key)), ReasonCode::PROTOCOL_AUTH_FAILED);

  // An unsigned grant is refused, not treated as trusted.
  smf::TransferGrant unsigned_grant = make_grant(object, key);
  unsigned_grant.signature = smf::Digest();
  SMF_CHECK_CODE(unsigned_grant.verify_signature(smf::as_bytes(key)), ReasonCode::INVALID_DIGEST);
  SMF_CHECK_CODE(unsigned_grant.validate(), ReasonCode::INVALID_DIGEST);
}

SMF_TEST(protocol, contradictory_grant_bindings_are_refused) {
  const Bytes key = test_key();
  const auto object =
      smftest::make_descriptor(smf::StateKind::KV, "contradiction/object", 1, 4096, 4096);

  // Source and destination naming the same endpoint.
  {
    smf::TransferGrant grant = make_grant(object, key);
    grant.destination = grant.source;
    grant.destination_incarnation =
        smf::DestinationIncarnation::make(grant.source, smf::IdIssuer().new_boot_id(),
                                          smf::IncarnationEpoch(1))
            .value();
    SMF_CHECK_CODE(grant.validate(), ReasonCode::SELF_MOVEMENT);
  }
  // An incarnation that names a different endpoint than the grant does.
  {
    smf::TransferGrant grant = make_grant(object, key);
    grant.destination_incarnation =
        smf::DestinationIncarnation::make(smf::EndpointId::parse("someone-else").value(),
                                          smf::IdIssuer().new_boot_id(),
                                          smf::IncarnationEpoch(1))
            .value();
    SMF_CHECK_CODE(grant.validate(), ReasonCode::STALE_INCARNATION);
  }
  // Zero budgets.
  {
    smf::TransferGrant grant = make_grant(object, key);
    grant.max_bytes = 0;
    SMF_CHECK_CODE(grant.validate(), ReasonCode::INVALID_SIZE);
  }
  // A nonce of zero is not an authority token.
  {
    smf::TransferGrant grant = make_grant(object, key);
    grant.grant_nonce = smf::Nonce();
    SMF_CHECK_CODE(grant.validate(), ReasonCode::INVALID_ID);
  }
}

SMF_TEST(protocol, data_chunk_length_must_equal_its_payload) {
  smf::DataChunk chunk;
  chunk.movement_id = smf::IdIssuer().new_movement_id();
  chunk.attempt = smf::IdIssuer().new_attempt_id();
  chunk.chunk_index = 0;
  chunk.chunk_offset = 0;
  chunk.chunk_length = 100;
  chunk.payload = smftest::pattern_bytes(3, 64);
  SMF_CHECK_CODE(chunk.validate(), ReasonCode::INVALID_SIZE);

  chunk.chunk_length = 64;
  SMF_CHECK_OK(chunk.validate());
}

SMF_TEST(protocol, chosen_plaintext_values_are_rejected_by_the_codec) {
  // A boolean that is neither zero nor one.
  {
    smf::CanonicalEncoder encoder("SMF-MSG-TOPOLOGY-REQUEST-v1");
    encoder.u8(0x02);
    Frame frame;
    frame.header.type = MessageType::TOPOLOGY_REQUEST;
    frame.payload = encoder.bytes();
    SMF_CHECK_CODE(smf::decode_message<smf::TopologyRequest>(frame),
                   ReasonCode::PROTOCOL_TRAILING_GARBAGE);
  }
  // An enumerated field outside its range, and an unknown reason code.
  {
    smf::CanonicalEncoder encoder("SMF-MSG-ATTEMPT-RESULT-v1");
    smf::IdIssuer issuer;
    issuer.new_movement_id().encode(encoder);
    encoder.u64(1);
    issuer.new_attempt_id().encode(encoder);
    encoder.u8(200);  // MovementState out of range
    Frame frame;
    frame.header.type = MessageType::ATTEMPT_RESULT;
    frame.payload = encoder.bytes();
    SMF_CHECK(!smf::decode_message<smf::AttemptResult>(frame).ok());
  }
  // An absurd collection count must be refused before anything is allocated.
  {
    smf::CanonicalEncoder encoder("SMF-MSG-MOVEMENT-LIST-v1");
    encoder.u32(0xFFFFFFFFU);
    Frame frame;
    frame.header.type = MessageType::MOVEMENT_LIST;
    frame.payload = encoder.bytes();
    const auto decoded = smf::decode_message<smf::MovementList>(frame);
    SMF_CHECK(!decoded.ok());
    SMF_CHECK(decoded.status().code() == ReasonCode::PROTOCOL_BOUNDS_EXCEEDED ||
              decoded.status().code() == ReasonCode::PROTOCOL_TRUNCATED);
  }
  // Invalid UTF-8 inside a text field.
  {
    smf::CanonicalEncoder encoder("SMF-MSG-ANNOUNCE-ACK-v1");
    encoder.u16(static_cast<std::uint16_t>(ReasonCode::OK));
    const smf::Byte invalid[] = {0xC0U, 0xAFU};
    encoder.blob(smf::ByteView(invalid, 2));
    Frame frame;
    frame.header.type = MessageType::ANNOUNCE_ACK;
    frame.payload = encoder.bytes();
    SMF_CHECK_CODE(smf::decode_message<smf::AnnounceAck>(frame), ReasonCode::INVALID_UTF8);
  }
}

SMF_TEST(protocol, duplicate_grant_nonce_is_single_use_by_construction) {
  // The grant nonce is 32 random bytes; two independently issued grants must
  // never collide, and a replayed nonce is a distinct authority token.
  const Bytes key = test_key();
  const auto object =
      smftest::make_descriptor(smf::StateKind::TENSOR, "nonce/object", 1, 4096, 4096);
  std::vector<std::string> nonces;
  for (int i = 0; i < 2000; ++i) {
    const smf::TransferGrant grant = make_grant(object, key);
    nonces.push_back(grant.grant_nonce.hex());
  }
  std::sort(nonces.begin(), nonces.end());
  SMF_CHECK(std::adjacent_find(nonces.begin(), nonces.end()) == nonces.end());
}

SMF_TEST(protocol, stale_epoch_and_boot_bindings_are_distinguishable) {
  smf::IdIssuer issuer;
  const auto endpoint = smf::EndpointId::parse("source-1").value();
  const auto older = smf::SourceIncarnation::make(endpoint, issuer.new_boot_id(),
                                                  smf::IncarnationEpoch(4))
                         .value();
  const auto restarted = smf::SourceIncarnation::make(endpoint, issuer.new_boot_id(),
                                                      smf::IncarnationEpoch(5))
                             .value();
  const auto other_boot = smf::SourceIncarnation::make(endpoint, issuer.new_boot_id(),
                                                       smf::IncarnationEpoch(5))
                              .value();

  SMF_CHECK(older != restarted);
  SMF_CHECK(restarted != other_boot);
  // Same endpoint name, different process: never equal.
  SMF_CHECK(restarted.epoch() == other_boot.epoch());
  SMF_CHECK(restarted.boot() != other_boot.boot());
}
