// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Message codecs and the framed helpers declared in smf/wire.hpp.
//
// The shape of every codec here is deliberately identical: encode() writes the
// domain string first and then the fields in declaration order; decode() reads
// the domain string first, mirrors the same order with a bounded read for every
// field, and finishes by calling validate(). A reviewer can therefore check any
// message by reading its three functions side by side.

#include "smf/wire.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace smf {
namespace {

// ---------------------------------------------------------------------------
// Small shared checks
// ---------------------------------------------------------------------------

// The domain string is the first field of every message, and the only thing
// that distinguishes two bindings over the same field values.
[[nodiscard]] Status check_domain(CanonicalDecoder& decoder, std::string_view expected) {
  const auto found = decoder.text(kMaxWireDomainBytes);
  if (!found.ok()) return found.status();
  if (found.value() != expected) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION,
                  "message domain string is not the expected one");
  }
  return Status::success();
}

[[nodiscard]] Status require_bound(std::string_view value, std::size_t bound, const char* what) {
  if (value.size() > bound) {
    return Status(ReasonCode::INVALID_SIZE, std::string(what) + " exceeds the wire bound");
  }
  if (!value.empty() && !is_valid_utf8(as_bytes(value))) {
    return Status(ReasonCode::INVALID_UTF8, std::string(what) + " is not valid UTF-8");
  }
  return Status::success();
}

[[nodiscard]] Status require_digest(const Digest& value, const char* what) {
  if (value.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, std::string(what) + " must not be zero");
  }
  return Status::success();
}

[[nodiscard]] Status require_endpoint(const EndpointId& value, const char* what) {
  if (value.empty() || !EndpointId::is_valid(value.value())) {
    return Status(ReasonCode::INVALID_ID, std::string(what) + " is not a valid endpoint id");
  }
  return Status::success();
}

template <class Tag>
[[nodiscard]] Status require_generation(const Generation<Tag>& value, const char* what) {
  if (!value.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, std::string(what) + " must be non-zero");
  }
  return Status::success();
}

// The role byte is a SessionRole. Anything else is a canonical violation, which
// is also what decode() reports for it.
[[nodiscard]] Status require_role(std::uint8_t role) {
  if (role != static_cast<std::uint8_t>(SessionRole::ENDPOINT) &&
      role != static_cast<std::uint8_t>(SessionRole::ADMIN)) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION, "session role is not recognized");
  }
  return Status::success();
}

// An address must name a host and a port. allow_unset admits the all-zero
// address, which RegisterRequest uses to mean "the same host as the service
// address, on the same port".
[[nodiscard]] Status require_address(const SocketAddress& address, bool allow_unset,
                                     const char* what) {
  if (allow_unset && address.host.empty() && address.port == 0) return Status::success();
  if (address.host.empty()) {
    return Status(ReasonCode::INVALID_ADDRESS, std::string(what) + " requires a host");
  }
  if (address.host.size() > kMaxWireHostBytes) {
    return Status(ReasonCode::INVALID_ADDRESS, std::string(what) + " host exceeds the wire bound");
  }
  if (address.port == 0) {
    return Status(ReasonCode::INVALID_ADDRESS, std::string(what) + " requires a port");
  }
  return Status::success();
}

template <class Tag>
[[nodiscard]] Status require_incarnation(const Incarnation<Tag>& value, const EndpointId& expected,
                                         const char* what) {
  if (!value.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION, std::string(what) + " is not complete");
  }
  if (value.endpoint() != expected) {
    return Status(ReasonCode::STALE_INCARNATION,
                  std::string(what) + " names a different endpoint than the message does");
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Bounded readers
// ---------------------------------------------------------------------------

[[nodiscard]] Result<EndpointId> read_endpoint(CanonicalDecoder& decoder) {
  const auto raw = decoder.text(kMaxEndpointIdBytes);
  if (!raw.ok()) return raw.status();
  if (raw.value().empty()) {
    return Status(ReasonCode::INVALID_ID, "endpoint id must not be empty");
  }
  return EndpointId::parse(raw.value());
}

[[nodiscard]] Result<SocketAddress> read_address(CanonicalDecoder& decoder) {
  const auto host = decoder.text(kMaxWireHostBytes);
  if (!host.ok()) return host.status();
  const auto port = decoder.u16();
  if (!port.ok()) return port.status();
  SocketAddress address;
  address.host = std::string(host.value());
  address.port = port.value();
  return address;
}

[[nodiscard]] Result<std::string> read_detail(CanonicalDecoder& decoder) {
  const auto raw = decoder.text(kMaxDetailBytes);
  if (!raw.ok()) return raw.status();
  return std::string(raw.value());
}

[[nodiscard]] Result<ReasonCode> read_reason(CanonicalDecoder& decoder) {
  const auto raw = decoder.u16();
  if (!raw.ok()) return raw.status();
  if (raw.value() > static_cast<std::uint16_t>(ReasonCode::NO_EVIDENCE)) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION,
                  "reason code is outside the known range");
  }
  return static_cast<ReasonCode>(raw.value());
}

[[nodiscard]] Result<MovementState> read_movement_state(CanonicalDecoder& decoder) {
  const auto raw = decoder.u8();
  if (!raw.ok()) return raw.status();
  if (raw.value() > static_cast<std::uint8_t>(MovementState::SUPERSEDED)) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION, "movement state is not recognized");
  }
  return static_cast<MovementState>(raw.value());
}

[[nodiscard]] Result<EffectClass> read_effect_class(CanonicalDecoder& decoder) {
  const auto raw = decoder.u8();
  if (!raw.ok()) return raw.status();
  if (raw.value() > static_cast<std::uint8_t>(EffectClass::NON_REPEATABLE)) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION, "effect class is not recognized");
  }
  return static_cast<EffectClass>(raw.value());
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

void write_address(CanonicalEncoder& encoder, const SocketAddress& address) {
  encoder.text(address.host);
  encoder.u16(address.port);
}

void write_detail(CanonicalEncoder& encoder, const std::string& detail) {
  encoder.text(detail);
}

void write_reason(CanonicalEncoder& encoder, ReasonCode code) {
  encoder.u16(static_cast<std::uint16_t>(code));
}

template <class Tag>
void write_generation(CanonicalEncoder& encoder, const Generation<Tag>& value) {
  encoder.u64(value.value());
}

template <class Tag>
[[nodiscard]] Result<Generation<Tag>> read_generation(CanonicalDecoder& decoder) {
  const auto raw = decoder.u64();
  if (!raw.ok()) return raw.status();
  return Generation<Tag>(raw.value());
}

template <class Tag>
void write_incarnation(CanonicalEncoder& encoder, const Incarnation<Tag>& value) {
  encoder.text(value.endpoint().value());
  value.boot().encode(encoder);
  encoder.u64(value.epoch().value());
}

template <class Tag>
[[nodiscard]] Result<Incarnation<Tag>> read_incarnation(CanonicalDecoder& decoder) {
  const auto endpoint = read_endpoint(decoder);
  if (!endpoint.ok()) return endpoint.status();
  const auto boot = BootId::decode(decoder);
  if (!boot.ok()) return boot.status();
  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  return Incarnation<Tag>(endpoint.value(), boot.value(), IncarnationEpoch(epoch.value()));
}

// EndpointRegistration is owned by the topology module and has no codec of its
// own; its wire layout lives here so that the whole protocol stays in one file.
void write_registration(CanonicalEncoder& encoder, const EndpointRegistration& registration) {
  encoder.text(registration.endpoint.value());
  write_incarnation(encoder, registration.incarnation);
  write_address(encoder, registration.service_address);
  write_address(encoder, registration.data_address);
  encoder.text(registration.contract);
  encoder.digest(registration.capability_digest);
  encoder.i64(registration.registered_unix_millis);
  encoder.boolean(registration.live);
}

[[nodiscard]] Result<EndpointRegistration> read_registration(CanonicalDecoder& decoder) {
  EndpointRegistration registration;

  const auto endpoint = read_endpoint(decoder);
  if (!endpoint.ok()) return endpoint.status();
  registration.endpoint = endpoint.value();

  const auto incarnation = read_incarnation<EndpointIncarnationTag>(decoder);
  if (!incarnation.ok()) return incarnation.status();
  registration.incarnation = incarnation.value();

  const auto service = read_address(decoder);
  if (!service.ok()) return service.status();
  registration.service_address = service.value();

  const auto data = read_address(decoder);
  if (!data.ok()) return data.status();
  registration.data_address = data.value();

  const auto contract = decoder.text(kMaxWireContractBytes);
  if (!contract.ok()) return contract.status();
  registration.contract = std::string(contract.value());

  const auto capability = decoder.digest();
  if (!capability.ok()) return capability.status();
  registration.capability_digest = capability.value();

  const auto registered = decoder.i64();
  if (!registered.ok()) return registered.status();
  registration.registered_unix_millis = registered.value();

  const auto live = decoder.boolean();
  if (!live.ok()) return live.status();
  registration.live = live.value();

  return registration;
}

}  // namespace

// ---------------------------------------------------------------------------
// Peer identity hint
// ---------------------------------------------------------------------------

Status PeerIdentityHint::validate() const {
  SMF_RETURN_IF_ERROR(require_endpoint(endpoint, "peer endpoint"));
  if (boot.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "peer boot id must not be zero");
  }
  SMF_RETURN_IF_ERROR(require_generation(epoch, "peer incarnation epoch"));
  SMF_RETURN_IF_ERROR(require_role(role));
  if (contract.empty()) {
    return Status(ReasonCode::ENDPOINT_CONTRACT_MISMATCH, "peer contract must not be empty");
  }
  SMF_RETURN_IF_ERROR(require_bound(contract, kMaxWireContractBytes, "peer contract"));
  return require_digest(capability_digest, "peer capability digest");
}

void PeerIdentityHint::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.text(endpoint.value());
  boot.encode(encoder);
  encoder.u64(epoch.value());
  encoder.u8(role);
  encoder.text(contract);
  encoder.digest(capability_digest);
}

Result<PeerIdentityHint> PeerIdentityHint::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  PeerIdentityHint message;

  const auto endpoint = read_endpoint(decoder);
  if (!endpoint.ok()) return endpoint.status();
  message.endpoint = endpoint.value();

  const auto boot = BootId::decode(decoder);
  if (!boot.ok()) return boot.status();
  message.boot = boot.value();

  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  message.epoch = IncarnationEpoch(epoch.value());

  const auto role = decoder.u8();
  if (!role.ok()) return role.status();
  SMF_RETURN_IF_ERROR(require_role(role.value()));
  message.role = role.value();

  const auto contract = decoder.text(kMaxWireContractBytes);
  if (!contract.ok()) return contract.status();
  message.contract = std::string(contract.value());

  const auto capability = decoder.digest();
  if (!capability.ok()) return capability.status();
  message.capability_digest = capability.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Transfer grant
// ---------------------------------------------------------------------------

Status TransferGrant::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "transfer grant requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "transfer grant requires a transfer attempt id");
  }
  SMF_RETURN_IF_ERROR(object.validate());
  SMF_RETURN_IF_ERROR(require_endpoint(source, "grant source"));
  SMF_RETURN_IF_ERROR(require_endpoint(destination, "grant destination"));
  if (source == destination) {
    return Status(ReasonCode::SELF_MOVEMENT, "a transfer grant must move bytes between two endpoints");
  }
  SMF_RETURN_IF_ERROR(require_incarnation(source_incarnation, source, "source incarnation"));
  SMF_RETURN_IF_ERROR(require_incarnation(destination_incarnation, destination,
                                          "destination incarnation"));
  SMF_RETURN_IF_ERROR(require_generation(policy_generation, "policy generation"));
  if (grant_nonce.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "transfer grant requires a nonce");
  }
  if (max_bytes == 0) {
    return Status(ReasonCode::INVALID_SIZE, "transfer grant requires a non-zero byte budget");
  }
  if (max_chunks == 0) {
    return Status(ReasonCode::INVALID_SIZE, "transfer grant requires a non-zero chunk budget");
  }
  if (issued_unix_millis <= 0) {
    return Status(ReasonCode::INVALID_ARGUMENT, "transfer grant requires an issue timestamp");
  }
  if (signature.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, "transfer grant is not signed");
  }
  return Status::success();
}

void TransferGrant::encode_unsigned(CanonicalEncoder& encoder) const {
  movement_id.encode(encoder);
  encoder.u64(movement_generation.value());
  attempt.encode(encoder);
  object.encode(encoder);
  encoder.text(source.value());
  write_incarnation(encoder, source_incarnation);
  encoder.text(destination.value());
  write_incarnation(encoder, destination_incarnation);
  encoder.u64(policy_generation.value());
  grant_nonce.encode(encoder);
  encoder.u64(max_bytes);
  encoder.u32(max_chunks);
  encoder.i64(issued_unix_millis);
  encoder.u8(static_cast<std::uint8_t>(effect_class));
}

void TransferGrant::encode(CanonicalEncoder& encoder) const {
  encode_unsigned(encoder);
  encoder.digest(signature);
}

Result<TransferGrant> TransferGrant::decode(CanonicalDecoder& decoder) {
  TransferGrant grant;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  grant.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  grant.movement_generation = generation.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  grant.attempt = attempt.value();

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  grant.object = object.value();

  const auto source = read_endpoint(decoder);
  if (!source.ok()) return source.status();
  grant.source = source.value();

  const auto source_incarnation = read_incarnation<SourceIncarnationTag>(decoder);
  if (!source_incarnation.ok()) return source_incarnation.status();
  grant.source_incarnation = source_incarnation.value();

  const auto destination = read_endpoint(decoder);
  if (!destination.ok()) return destination.status();
  grant.destination = destination.value();

  const auto destination_incarnation = read_incarnation<DestinationIncarnationTag>(decoder);
  if (!destination_incarnation.ok()) return destination_incarnation.status();
  grant.destination_incarnation = destination_incarnation.value();

  const auto policy_generation = read_generation<PolicyGenerationTag>(decoder);
  if (!policy_generation.ok()) return policy_generation.status();
  grant.policy_generation = policy_generation.value();

  const auto nonce = Nonce::decode(decoder);
  if (!nonce.ok()) return nonce.status();
  grant.grant_nonce = nonce.value();

  const auto max_bytes = decoder.u64();
  if (!max_bytes.ok()) return max_bytes.status();
  grant.max_bytes = max_bytes.value();

  const auto max_chunks = decoder.u32();
  if (!max_chunks.ok()) return max_chunks.status();
  grant.max_chunks = max_chunks.value();

  const auto issued = decoder.i64();
  if (!issued.ok()) return issued.status();
  grant.issued_unix_millis = issued.value();

  const auto effect = read_effect_class(decoder);
  if (!effect.ok()) return effect.status();
  grant.effect_class = effect.value();

  const auto signature = decoder.digest();
  if (!signature.ok()) return signature.status();
  grant.signature = signature.value();

  const Status status = grant.validate();
  if (!status.ok()) return status;
  return grant;
}

Digest TransferGrant::compute_signature(ByteView key) const {
  CanonicalEncoder encoder(kSignatureDomain);
  encode_unsigned(encoder);
  return canonical_mac(key, encoder);
}

Status TransferGrant::sign(ByteView key) {
  signature = compute_signature(key);
  return validate();
}

Status TransferGrant::verify_signature(ByteView key) const {
  SMF_RETURN_IF_ERROR(validate());
  const Digest expected = compute_signature(key);
  if (!constant_time_equal(expected.view(), signature.view())) {
    return Status(ReasonCode::PROTOCOL_AUTH_FAILED, "transfer grant signature did not verify");
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

Status RegisterRequest::validate() const {
  SMF_RETURN_IF_ERROR(identity.validate());
  SMF_RETURN_IF_ERROR(require_address(service_address, false, "service address"));
  SMF_RETURN_IF_ERROR(require_address(data_address, true, "data address"));
  return require_digest(inventory_digest, "inventory digest");
}

void RegisterRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  identity.encode(encoder);
  write_address(encoder, service_address);
  write_address(encoder, data_address);
  encoder.digest(inventory_digest);
}

Result<RegisterRequest> RegisterRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  RegisterRequest message;

  const auto identity = PeerIdentityHint::decode(decoder);
  if (!identity.ok()) return identity.status();
  message.identity = identity.value();

  const auto service = read_address(decoder);
  if (!service.ok()) return service.status();
  message.service_address = service.value();

  const auto data = read_address(decoder);
  if (!data.ok()) return data.status();
  message.data_address = data.value();

  const auto inventory = decoder.digest();
  if (!inventory.ok()) return inventory.status();
  message.inventory_digest = inventory.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status RegisterAck::validate() const {
  SMF_RETURN_IF_ERROR(require_generation(topology_generation, "topology generation"));
  SMF_RETURN_IF_ERROR(require_generation(policy_generation, "policy generation"));
  if (!coordinator.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION, "registration ack requires a coordinator incarnation");
  }
  SMF_RETURN_IF_ERROR(require_digest(policy_digest, "policy digest"));
  if (max_inflight_chunks == 0) {
    return Status(ReasonCode::INVALID_POLICY, "registration ack requires a non-zero in-flight bound");
  }
  if (max_chunk_bytes == 0) {
    return Status(ReasonCode::INVALID_POLICY, "registration ack requires a non-zero chunk bound");
  }
  if (max_object_bytes == 0) {
    return Status(ReasonCode::INVALID_POLICY, "registration ack requires a non-zero object bound");
  }
  if (io_budget_millis == 0) {
    return Status(ReasonCode::INVALID_POLICY, "registration ack requires a non-zero io budget");
  }
  if (transfer_budget_millis == 0) {
    return Status(ReasonCode::INVALID_POLICY,
                  "registration ack requires a non-zero transfer budget");
  }
  return Status::success();
}

void RegisterAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  write_generation(encoder, topology_generation);
  write_generation(encoder, policy_generation);
  write_incarnation(encoder, coordinator);
  encoder.digest(policy_digest);
  encoder.u32(max_inflight_chunks);
  encoder.u64(max_chunk_bytes);
  encoder.u64(max_object_bytes);
  encoder.u32(io_budget_millis);
  encoder.u32(transfer_budget_millis);
}

Result<RegisterAck> RegisterAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  RegisterAck message;

  const auto topology = read_generation<TopologyGenerationTag>(decoder);
  if (!topology.ok()) return topology.status();
  message.topology_generation = topology.value();

  const auto policy = read_generation<PolicyGenerationTag>(decoder);
  if (!policy.ok()) return policy.status();
  message.policy_generation = policy.value();

  const auto coordinator = read_incarnation<EndpointIncarnationTag>(decoder);
  if (!coordinator.ok()) return coordinator.status();
  message.coordinator = coordinator.value();

  const auto digest = decoder.digest();
  if (!digest.ok()) return digest.status();
  message.policy_digest = digest.value();

  const auto inflight = decoder.u32();
  if (!inflight.ok()) return inflight.status();
  message.max_inflight_chunks = inflight.value();

  const auto chunk_bytes = decoder.u64();
  if (!chunk_bytes.ok()) return chunk_bytes.status();
  message.max_chunk_bytes = chunk_bytes.value();

  const auto object_bytes = decoder.u64();
  if (!object_bytes.ok()) return object_bytes.status();
  message.max_object_bytes = object_bytes.value();

  const auto io_budget = decoder.u32();
  if (!io_budget.ok()) return io_budget.status();
  message.io_budget_millis = io_budget.value();

  const auto transfer_budget = decoder.u32();
  if (!transfer_budget.ok()) return transfer_budget.status();
  message.transfer_budget_millis = transfer_budget.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status AnnounceObject::validate() const { return descriptor.validate(); }

void AnnounceObject::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  descriptor.encode(encoder);
}

Result<AnnounceObject> AnnounceObject::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  AnnounceObject message;
  const auto descriptor = StateObjectDescriptor::decode(decoder);
  if (!descriptor.ok()) return descriptor.status();
  message.descriptor = descriptor.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status AnnounceAck::validate() const { return require_bound(detail, kMaxDetailBytes, "detail"); }

void AnnounceAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<AnnounceAck> AnnounceAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  AnnounceAck message;
  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Authority and attempt lifecycle
// ---------------------------------------------------------------------------

Status GrantTransfer::validate() const { return grant.validate(); }

void GrantTransfer::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  grant.encode(encoder);
}

Result<GrantTransfer> GrantTransfer::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  GrantTransfer message;
  const auto grant = TransferGrant::decode(decoder);
  if (!grant.ok()) return grant.status();
  message.grant = grant.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status GrantAck::validate() const {
  SMF_RETURN_IF_ERROR(require_digest(nonce, "grant nonce"));
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void GrantAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.digest(nonce);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<GrantAck> GrantAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  GrantAck message;

  const auto nonce = decoder.digest();
  if (!nonce.ok()) return nonce.status();
  message.nonce = nonce.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ExecuteMovement::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "execute movement requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "execute movement requires a transfer attempt id");
  }
  SMF_RETURN_IF_ERROR(require_digest(nonce, "execute movement nonce"));
  return require_endpoint(source, "execute movement source");
}

void ExecuteMovement::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  attempt.encode(encoder);
  encoder.digest(nonce);
  encoder.text(source.value());
}

Result<ExecuteMovement> ExecuteMovement::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ExecuteMovement message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto nonce = decoder.digest();
  if (!nonce.ok()) return nonce.status();
  message.nonce = nonce.value();

  const auto source = read_endpoint(decoder);
  if (!source.ok()) return source.status();
  message.source = source.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status AttemptResult::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "attempt result requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "attempt result requires a transfer attempt id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void AttemptResult::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  attempt.encode(encoder);
  encoder.u8(static_cast<std::uint8_t>(state));
  write_reason(encoder, code);
  write_detail(encoder, detail);
  encoder.digest(verified_digest);
  encoder.u64(bytes);
  encoder.u32(chunks);
  encoder.digest(marker_digest);
}

Result<AttemptResult> AttemptResult::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  AttemptResult message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto state = read_movement_state(decoder);
  if (!state.ok()) return state.status();
  message.state = state.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const auto verified = decoder.digest();
  if (!verified.ok()) return verified.status();
  message.verified_digest = verified.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  message.bytes = bytes.value();

  const auto chunks = decoder.u32();
  if (!chunks.ok()) return chunks.status();
  message.chunks = chunks.value();

  const auto marker = decoder.digest();
  if (!marker.ok()) return marker.status();
  message.marker_digest = marker.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CancelRequest::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "cancel request requires a movement id");
  }
  return require_generation(movement_generation, "movement generation");
}

void CancelRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
}

Result<CancelRequest> CancelRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CancelRequest message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CancelAck::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "cancel ack requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void CancelAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<CancelAck> CancelAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CancelAck message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Commit, verify, authority, cleanup (destination side)
// ---------------------------------------------------------------------------

Status CommitRequest::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "commit request requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "commit request requires a transfer attempt id");
  }
  return object.validate();
}

void CommitRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  attempt.encode(encoder);
  object.encode(encoder);
  encoder.text(source.value());
}

Result<CommitRequest> CommitRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CommitRequest message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  message.object = object.value();

  const auto source = decoder.text(kMaxEndpointIdBytes);
  if (!source.ok()) return source.status();
  if (!source.value().empty()) {
    const auto parsed = EndpointId::parse(source.value());
    if (!parsed.ok()) return parsed.status();
    message.source = parsed.value();
  }

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CommitResult::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "commit result requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void CommitResult::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  write_reason(encoder, code);
  encoder.digest(marker_digest);
  write_detail(encoder, detail);
}

Result<CommitResult> CommitResult::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CommitResult message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto marker = decoder.digest();
  if (!marker.ok()) return marker.status();
  message.marker_digest = marker.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status VerifyRequest::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "verify request requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "verify request requires a state object id");
  }
  return require_generation(object_generation, "state object generation");
}

void VerifyRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  object_id.encode(encoder);
  write_generation(encoder, object_generation);
  encoder.boolean(full_digest_requested);
  encoder.u32(chunk_index);
  encoder.u64(chunk_bytes);
}

Result<VerifyRequest> VerifyRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  VerifyRequest message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto object_id = StateObjectId::decode(decoder);
  if (!object_id.ok()) return object_id.status();
  message.object_id = object_id.value();

  const auto object_generation = read_generation<StateGenerationTag>(decoder);
  if (!object_generation.ok()) return object_generation.status();
  message.object_generation = object_generation.value();

  const auto full = decoder.boolean();
  if (!full.ok()) return full.status();
  message.full_digest_requested = full.value();

  const auto chunk = decoder.u32();
  if (!chunk.ok()) return chunk.status();
  message.chunk_index = chunk.value();

  const auto chunk_bytes = decoder.u64();
  if (!chunk_bytes.ok()) return chunk_bytes.status();
  message.chunk_bytes = chunk_bytes.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status VerifyResponse::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "verify response requires a movement id");
  }
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "verify response requires a state object id");
  }
  SMF_RETURN_IF_ERROR(require_generation(object_generation, "state object generation"));
  if (chunk_payload.size() > kMaxWireChunkBytes) {
    return Status(ReasonCode::INVALID_SIZE, "verify response payload exceeds the chunk bound");
  }
  return Status::success();
}

void VerifyResponse::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  object_id.encode(encoder);
  write_generation(encoder, object_generation);
  write_reason(encoder, code);
  encoder.digest(stored_digest);
  encoder.u64(stored_bytes);
  encoder.u32(stored_chunks);
  encoder.u32(chunk_index);
  encoder.digest(chunk_digest);
  encoder.blob(chunk_payload);
}

Result<VerifyResponse> VerifyResponse::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  VerifyResponse message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto object_id = StateObjectId::decode(decoder);
  if (!object_id.ok()) return object_id.status();
  message.object_id = object_id.value();

  const auto object_generation = read_generation<StateGenerationTag>(decoder);
  if (!object_generation.ok()) return object_generation.status();
  message.object_generation = object_generation.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto stored_digest = decoder.digest();
  if (!stored_digest.ok()) return stored_digest.status();
  message.stored_digest = stored_digest.value();

  const auto stored_bytes = decoder.u64();
  if (!stored_bytes.ok()) return stored_bytes.status();
  message.stored_bytes = stored_bytes.value();

  const auto stored_chunks = decoder.u32();
  if (!stored_chunks.ok()) return stored_chunks.status();
  message.stored_chunks = stored_chunks.value();

  const auto chunk_index = decoder.u32();
  if (!chunk_index.ok()) return chunk_index.status();
  message.chunk_index = chunk_index.value();

  const auto chunk_digest = decoder.digest();
  if (!chunk_digest.ok()) return chunk_digest.status();
  message.chunk_digest = chunk_digest.value();

  const auto payload = decoder.blob(kMaxWireChunkBytes);
  if (!payload.ok()) return payload.status();
  message.chunk_payload.assign(payload.value().begin(), payload.value().end());

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status AuthorityQuery::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "authority query requires a movement id");
  }
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "authority query requires a state object id");
  }
  return require_generation(object_generation, "state object generation");
}

void AuthorityQuery::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  object_id.encode(encoder);
  write_generation(encoder, object_generation);
}

Result<AuthorityQuery> AuthorityQuery::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  AuthorityQuery message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto object_id = StateObjectId::decode(decoder);
  if (!object_id.ok()) return object_id.status();
  message.object_id = object_id.value();

  const auto object_generation = read_generation<StateGenerationTag>(decoder);
  if (!object_generation.ok()) return object_generation.status();
  message.object_generation = object_generation.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status AuthorityReport::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "authority report requires a movement id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void AuthorityReport::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_reason(encoder, code);
  encoder.boolean(bytes_present);
  encoder.boolean(verified);
  encoder.boolean(marker_present);
  encoder.boolean(authoritative);
  encoder.digest(marker_digest);
  encoder.u64(stored_bytes);
  write_detail(encoder, detail);
}

Result<AuthorityReport> AuthorityReport::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  AuthorityReport message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto bytes_present = decoder.boolean();
  if (!bytes_present.ok()) return bytes_present.status();
  message.bytes_present = bytes_present.value();

  const auto verified = decoder.boolean();
  if (!verified.ok()) return verified.status();
  message.verified = verified.value();

  const auto marker_present = decoder.boolean();
  if (!marker_present.ok()) return marker_present.status();
  message.marker_present = marker_present.value();

  const auto authoritative = decoder.boolean();
  if (!authoritative.ok()) return authoritative.status();
  message.authoritative = authoritative.value();

  const auto marker = decoder.digest();
  if (!marker.ok()) return marker.status();
  message.marker_digest = marker.value();

  const auto stored_bytes = decoder.u64();
  if (!stored_bytes.ok()) return stored_bytes.status();
  message.stored_bytes = stored_bytes.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CleanupRequest::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "cleanup request requires a movement id");
  }
  return Status::success();
}

void CleanupRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  encoder.boolean(quarantine);
}

Result<CleanupRequest> CleanupRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CleanupRequest message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto quarantine = decoder.boolean();
  if (!quarantine.ok()) return quarantine.status();
  message.quarantine = quarantine.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CleanupResult::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "cleanup result requires a movement id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void CleanupResult::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_reason(encoder, code);
  encoder.u64(bytes_removed);
  encoder.u32(entries_removed);
  write_detail(encoder, detail);
}

Result<CleanupResult> CleanupResult::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CleanupResult message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto bytes_removed = decoder.u64();
  if (!bytes_removed.ok()) return bytes_removed.status();
  message.bytes_removed = bytes_removed.value();

  const auto entries_removed = decoder.u32();
  if (!entries_removed.ok()) return entries_removed.status();
  message.entries_removed = entries_removed.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Data plane
// ---------------------------------------------------------------------------

Status DataBegin::validate() const {
  SMF_RETURN_IF_ERROR(require_digest(nonce, "data begin nonce"));
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data begin requires a movement id");
  }
  SMF_RETURN_IF_ERROR(require_generation(movement_generation, "movement generation"));
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data begin requires a transfer attempt id");
  }
  SMF_RETURN_IF_ERROR(object.validate());
  SMF_RETURN_IF_ERROR(require_endpoint(destination, "data begin destination"));
  return require_incarnation(destination_incarnation, destination, "destination incarnation");
}

void DataBegin::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.digest(nonce);
  movement_id.encode(encoder);
  write_generation(encoder, movement_generation);
  attempt.encode(encoder);
  object.encode(encoder);
  encoder.text(destination.value());
  write_incarnation(encoder, destination_incarnation);
}

Result<DataBegin> DataBegin::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataBegin message;

  const auto nonce = decoder.digest();
  if (!nonce.ok()) return nonce.status();
  message.nonce = nonce.value();

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto generation = read_generation<MovementGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.movement_generation = generation.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  message.object = object.value();

  const auto destination = read_endpoint(decoder);
  if (!destination.ok()) return destination.status();
  message.destination = destination.value();

  const auto incarnation = read_incarnation<DestinationIncarnationTag>(decoder);
  if (!incarnation.ok()) return incarnation.status();
  message.destination_incarnation = incarnation.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataBeginAck::validate() const {
  SMF_RETURN_IF_ERROR(require_digest(nonce, "data begin ack nonce"));
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void DataBeginAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.digest(nonce);
  write_reason(encoder, code);
  encoder.u32(resume_from_chunk);
  encoder.u64(resume_from_offset);
  write_detail(encoder, detail);
}

Result<DataBeginAck> DataBeginAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataBeginAck message;

  const auto nonce = decoder.digest();
  if (!nonce.ok()) return nonce.status();
  message.nonce = nonce.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto resume_chunk = decoder.u32();
  if (!resume_chunk.ok()) return resume_chunk.status();
  message.resume_from_chunk = resume_chunk.value();

  const auto resume_offset = decoder.u64();
  if (!resume_offset.ok()) return resume_offset.status();
  message.resume_from_offset = resume_offset.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataChunk::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data chunk requires a movement id");
  }
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data chunk requires a transfer attempt id");
  }
  if (payload.size() > kMaxWireChunkBytes) {
    return Status(ReasonCode::INVALID_SIZE, "data chunk payload exceeds the chunk bound");
  }
  if (chunk_length != static_cast<std::uint64_t>(payload.size())) {
    return Status(ReasonCode::INVALID_SIZE,
                  "data chunk length does not match the payload it carries");
  }
  return Status::success();
}

void DataChunk::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  attempt.encode(encoder);
  encoder.u32(chunk_index);
  encoder.u64(chunk_offset);
  encoder.u64(chunk_length);
  encoder.digest(chunk_digest);
  encoder.blob(payload);
}

Result<DataChunk> DataChunk::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataChunk message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto chunk_index = decoder.u32();
  if (!chunk_index.ok()) return chunk_index.status();
  message.chunk_index = chunk_index.value();

  const auto chunk_offset = decoder.u64();
  if (!chunk_offset.ok()) return chunk_offset.status();
  message.chunk_offset = chunk_offset.value();

  const auto chunk_length = decoder.u64();
  if (!chunk_length.ok()) return chunk_length.status();
  message.chunk_length = chunk_length.value();

  const auto chunk_digest = decoder.digest();
  if (!chunk_digest.ok()) return chunk_digest.status();
  message.chunk_digest = chunk_digest.value();

  const auto payload = decoder.blob(kMaxWireChunkBytes);
  if (!payload.ok()) return payload.status();
  message.payload.assign(payload.value().begin(), payload.value().end());

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataChunkAck::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data chunk ack requires a movement id");
  }
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data chunk ack requires a transfer attempt id");
  }
  return Status::success();
}

void DataChunkAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  attempt.encode(encoder);
  encoder.u32(highest_contiguous_index);
  encoder.u32(duplicates_ignored);
}

Result<DataChunkAck> DataChunkAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataChunkAck message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto highest = decoder.u32();
  if (!highest.ok()) return highest.status();
  message.highest_contiguous_index = highest.value();

  const auto duplicates = decoder.u32();
  if (!duplicates.ok()) return duplicates.status();
  message.duplicates_ignored = duplicates.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataEnd::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data end requires a movement id");
  }
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data end requires a transfer attempt id");
  }
  if (total_bytes > 0 && content_digest.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, "data end requires the digest of what was sent");
  }
  return Status::success();
}

void DataEnd::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  attempt.encode(encoder);
  encoder.u32(total_chunks);
  encoder.u64(total_bytes);
  encoder.digest(content_digest);
}

Result<DataEnd> DataEnd::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataEnd message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto total_chunks = decoder.u32();
  if (!total_chunks.ok()) return total_chunks.status();
  message.total_chunks = total_chunks.value();

  const auto total_bytes = decoder.u64();
  if (!total_bytes.ok()) return total_bytes.status();
  message.total_bytes = total_bytes.value();

  const auto content = decoder.digest();
  if (!content.ok()) return content.status();
  message.content_digest = content.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataResult::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data result requires a movement id");
  }
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data result requires a transfer attempt id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void DataResult::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  attempt.encode(encoder);
  write_reason(encoder, code);
  encoder.digest(stored_digest);
  encoder.u64(stored_bytes);
  encoder.u32(stored_chunks);
  encoder.digest(marker_digest);
  write_detail(encoder, detail);
}

Result<DataResult> DataResult::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataResult message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto stored_digest = decoder.digest();
  if (!stored_digest.ok()) return stored_digest.status();
  message.stored_digest = stored_digest.value();

  const auto stored_bytes = decoder.u64();
  if (!stored_bytes.ok()) return stored_bytes.status();
  message.stored_bytes = stored_bytes.value();

  const auto stored_chunks = decoder.u32();
  if (!stored_chunks.ok()) return stored_chunks.status();
  message.stored_chunks = stored_chunks.value();

  const auto marker = decoder.digest();
  if (!marker.ok()) return marker.status();
  message.marker_digest = marker.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status DataAbort::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data abort requires a movement id");
  }
  if (attempt.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "data abort requires a transfer attempt id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void DataAbort::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  attempt.encode(encoder);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<DataAbort> DataAbort::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  DataAbort message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  message.attempt = attempt.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Movement administration
// ---------------------------------------------------------------------------

Status SubmitMovement::validate() const {
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "submit movement requires a state object id");
  }
  SMF_RETURN_IF_ERROR(require_generation(object_generation, "state object generation"));
  SMF_RETURN_IF_ERROR(require_endpoint(source, "submit movement source"));
  SMF_RETURN_IF_ERROR(require_endpoint(destination, "submit movement destination"));
  if (source == destination) {
    return Status(ReasonCode::SELF_MOVEMENT, "source and destination endpoints are the same");
  }
  return Status::success();
}

void SubmitMovement::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  object_id.encode(encoder);
  write_generation(encoder, object_generation);
  encoder.text(source.value());
  encoder.text(destination.value());
}

Result<SubmitMovement> SubmitMovement::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  SubmitMovement message;

  const auto object_id = StateObjectId::decode(decoder);
  if (!object_id.ok()) return object_id.status();
  message.object_id = object_id.value();

  const auto object_generation = read_generation<StateGenerationTag>(decoder);
  if (!object_generation.ok()) return object_generation.status();
  message.object_generation = object_generation.value();

  const auto source = read_endpoint(decoder);
  if (!source.ok()) return source.status();
  message.source = source.value();

  const auto destination = read_endpoint(decoder);
  if (!destination.ok()) return destination.status();
  message.destination = destination.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status MovementAccepted::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "movement accepted requires a movement id");
  }
  return require_bound(detail, kMaxDetailBytes, "detail");
}

void MovementAccepted::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  encoder.u8(static_cast<std::uint8_t>(state));
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<MovementAccepted> MovementAccepted::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  MovementAccepted message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto state = read_movement_state(decoder);
  if (!state.ok()) return state.status();
  message.state = state.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status QueryMovement::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "query movement requires a movement id");
  }
  return Status::success();
}

void QueryMovement::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
}

Result<QueryMovement> QueryMovement::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  QueryMovement message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status MovementStatus::validate() const { return record.validate(); }

void MovementStatus::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  record.encode(encoder);
}

Result<MovementStatus> MovementStatus::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  MovementStatus message;
  const auto record = MovementRecord::decode(decoder);
  if (!record.ok()) return record.status();
  message.record = record.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ListMovements::validate() const {
  if (limit == 0 || limit > kMaxWireListLimit) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED,
                  "list movements requires a page size inside the wire bound");
  }
  return Status::success();
}

void ListMovements::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.u32(limit);
  encoder.u32(offset);
}

Result<ListMovements> ListMovements::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ListMovements message;

  const auto limit = decoder.u32();
  if (!limit.ok()) return limit.status();
  message.limit = limit.value();

  const auto offset = decoder.u32();
  if (!offset.ok()) return offset.status();
  message.offset = offset.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status MovementSummary::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "movement summary requires a movement id");
  }
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "movement summary requires a state object id");
  }
  SMF_RETURN_IF_ERROR(require_generation(object_generation, "state object generation"));
  SMF_RETURN_IF_ERROR(require_endpoint(source, "movement summary source"));
  SMF_RETURN_IF_ERROR(require_endpoint(destination, "movement summary destination"));
  if (source == destination) {
    return Status(ReasonCode::SELF_MOVEMENT, "source and destination endpoints are the same");
  }
  return Status::success();
}

void MovementSummary::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  encoder.u8(static_cast<std::uint8_t>(state));
  object_id.encode(encoder);
  write_generation(encoder, object_generation);
  encoder.text(source.value());
  encoder.text(destination.value());
  write_reason(encoder, last_reason);
  encoder.u32(attempt_count);
  encoder.u64(bytes_transferred);
}

Result<MovementSummary> MovementSummary::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  MovementSummary message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto state = read_movement_state(decoder);
  if (!state.ok()) return state.status();
  message.state = state.value();

  const auto object_id = StateObjectId::decode(decoder);
  if (!object_id.ok()) return object_id.status();
  message.object_id = object_id.value();

  const auto object_generation = read_generation<StateGenerationTag>(decoder);
  if (!object_generation.ok()) return object_generation.status();
  message.object_generation = object_generation.value();

  const auto source = read_endpoint(decoder);
  if (!source.ok()) return source.status();
  message.source = source.value();

  const auto destination = read_endpoint(decoder);
  if (!destination.ok()) return destination.status();
  message.destination = destination.value();

  const auto reason = read_reason(decoder);
  if (!reason.ok()) return reason.status();
  message.last_reason = reason.value();

  const auto attempt_count = decoder.u32();
  if (!attempt_count.ok()) return attempt_count.status();
  message.attempt_count = attempt_count.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  message.bytes_transferred = bytes.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status MovementList::validate() const {
  if (movements.size() > kMaxMovementSummaries) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "movement list exceeds the wire bound");
  }
  for (const MovementSummary& summary : movements) {
    SMF_RETURN_IF_ERROR(summary.validate());
  }
  return Status::success();
}

void MovementList::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  encoder.u32(static_cast<std::uint32_t>(movements.size()));
  for (const MovementSummary& summary : movements) {
    summary.encode(encoder);
  }
}

Result<MovementList> MovementList::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  MovementList message;

  const auto count = decoder.count(kMaxMovementSummaries);
  if (!count.ok()) return count.status();
  message.movements.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    const auto summary = MovementSummary::decode(decoder);
    if (!summary.ok()) return summary.status();
    message.movements.push_back(summary.value());
  }

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status CancelMovement::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "cancel movement requires a movement id");
  }
  return Status::success();
}

void CancelMovement::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
}

Result<CancelMovement> CancelMovement::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  CancelMovement message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ReconcileMovement::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "reconcile movement requires a movement id");
  }
  return Status::success();
}

void ReconcileMovement::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
}

Result<ReconcileMovement> ReconcileMovement::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ReconcileMovement message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ProvenanceRequest::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "provenance request requires a movement id");
  }
  return Status::success();
}

void ProvenanceRequest::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
}

Result<ProvenanceRequest> ProvenanceRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ProvenanceRequest message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ProvenanceReport::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "provenance report requires a movement id");
  }
  if (events.size() > kMaxProvenanceEvents) {
    return Status(ReasonCode::HISTORY_LIMIT_REACHED, "provenance report exceeds the wire bound");
  }
  for (std::size_t i = 0; i < events.size(); ++i) {
    SMF_RETURN_IF_ERROR(events[i].validate());
    if (events[i].sequence != static_cast<std::uint64_t>(i) + 1U) {
      return Status(ReasonCode::STORE_RECORD_INVALID,
                    "provenance report is not contiguous or is out of order");
    }
  }
  return Status::success();
}

void ProvenanceReport::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  movement_id.encode(encoder);
  write_reason(encoder, code);
  encoder.u32(static_cast<std::uint32_t>(events.size()));
  for (const ProvenanceEvent& event : events) {
    event.encode(encoder);
  }
}

Result<ProvenanceReport> ProvenanceReport::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ProvenanceReport message;

  const auto movement_id = MovementId::decode(decoder);
  if (!movement_id.ok()) return movement_id.status();
  message.movement_id = movement_id.value();

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto count = decoder.count(kMaxProvenanceEvents);
  if (!count.ok()) return count.status();
  message.events.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    const auto event = ProvenanceEvent::decode(decoder);
    if (!event.ok()) return event.status();
    message.events.push_back(event.value());
  }

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

// ---------------------------------------------------------------------------
// Read-only administrative queries
// ---------------------------------------------------------------------------

Status TopologyRequest::validate() const { return Status::success(); }

void TopologyRequest::encode(CanonicalEncoder& encoder) const { encoder.text(kDomain); }

Result<TopologyRequest> TopologyRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  TopologyRequest message;
  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status TopologyReport::validate() const {
  SMF_RETURN_IF_ERROR(require_generation(topology_generation, "topology generation"));
  if (!coordinator.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION, "topology report requires a coordinator incarnation");
  }
  if (endpoints.size() > kMaxEndpoints) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "topology report exceeds the wire bound");
  }
  for (const EndpointRegistration& registration : endpoints) {
    SMF_RETURN_IF_ERROR(registration.validate());
  }
  return Status::success();
}

void TopologyReport::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  write_generation(encoder, topology_generation);
  write_incarnation(encoder, coordinator);
  encoder.u32(static_cast<std::uint32_t>(endpoints.size()));
  for (const EndpointRegistration& registration : endpoints) {
    write_registration(encoder, registration);
  }
}

Result<TopologyReport> TopologyReport::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  TopologyReport message;

  const auto generation = read_generation<TopologyGenerationTag>(decoder);
  if (!generation.ok()) return generation.status();
  message.topology_generation = generation.value();

  const auto coordinator = read_incarnation<EndpointIncarnationTag>(decoder);
  if (!coordinator.ok()) return coordinator.status();
  message.coordinator = coordinator.value();

  const auto count = decoder.count(kMaxEndpoints);
  if (!count.ok()) return count.status();
  message.endpoints.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    const auto registration = read_registration(decoder);
    if (!registration.ok()) return registration.status();
    message.endpoints.push_back(registration.value());
  }

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status PolicyRequest::validate() const { return Status::success(); }

void PolicyRequest::encode(CanonicalEncoder& encoder) const { encoder.text(kDomain); }

Result<PolicyRequest> PolicyRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  PolicyRequest message;
  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status PolicyReport::validate() const {
  SMF_RETURN_IF_ERROR(policy.validate());
  return require_digest(policy_digest, "policy digest");
}

void PolicyReport::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  policy.encode(encoder);
  encoder.digest(policy_digest);
}

Result<PolicyReport> PolicyReport::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  PolicyReport message;

  const auto policy = PolicySet::decode(decoder);
  if (!policy.ok()) return policy.status();
  message.policy = policy.value();

  const auto digest = decoder.digest();
  if (!digest.ok()) return digest.status();
  message.policy_digest = digest.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ShutdownRequest::validate() const { return Status::success(); }

void ShutdownRequest::encode(CanonicalEncoder& encoder) const { encoder.text(kDomain); }

Result<ShutdownRequest> ShutdownRequest::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ShutdownRequest message;
  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ShutdownAck::validate() const { return require_bound(detail, kMaxDetailBytes, "detail"); }

void ShutdownAck::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<ShutdownAck> ShutdownAck::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ShutdownAck message;

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

Status ErrorMessage::validate() const { return require_bound(detail, kMaxDetailBytes, "detail"); }

void ErrorMessage::encode(CanonicalEncoder& encoder) const {
  encoder.text(kDomain);
  write_reason(encoder, code);
  write_detail(encoder, detail);
}

Result<ErrorMessage> ErrorMessage::decode(CanonicalDecoder& decoder) {
  SMF_RETURN_IF_ERROR(check_domain(decoder, kDomain));

  ErrorMessage message;

  const auto code = read_reason(decoder);
  if (!code.ok()) return code.status();
  message.code = code.value();

  const auto detail = read_detail(decoder);
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();

  const Status status = message.validate();
  if (!status.ok()) return status;
  return message;
}

}  // namespace smf
