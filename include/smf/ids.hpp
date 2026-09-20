// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Strongly typed identities, generations, and incarnations.
//
// Every type here is distinct at compile time from every other type with the
// same representation, so a source incarnation can never be passed where a
// destination incarnation is expected, and a movement generation can never be
// passed where a state generation is expected. Zero is never a valid
// generation: "unset" and "generation zero" are the same thing and are always
// rejected at the boundary.

#ifndef SMF_IDS_HPP
#define SMF_IDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "smf/bytes.hpp"
#include "smf/codec.hpp"
#include "smf/digest.hpp"
#include "smf/status.hpp"

namespace smf {

// ---------------------------------------------------------------------------
// Fixed-width identifiers
// ---------------------------------------------------------------------------

template <class Tag, std::size_t N>
class FixedId {
 public:
  static constexpr std::size_t kBytes = N;

  FixedId() noexcept = default;
  explicit FixedId(std::array<Byte, N> bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] static Result<FixedId> from_bytes(ByteView raw) {
    if (raw.size() != N) {
      return Status(ReasonCode::INVALID_ID, "identifier has the wrong width");
    }
    std::array<Byte, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = raw[i];
    return FixedId(out);
  }

  [[nodiscard]] static Result<FixedId> from_hex(std::string_view text) {
    Bytes raw;
    if (!smf::from_hex(text, raw) || raw.size() != N) {
      return Status(ReasonCode::INVALID_ID, "identifier is not valid hexadecimal of the expected width");
    }
    std::array<Byte, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = raw[i];
    return FixedId(out);
  }

  [[nodiscard]] static FixedId from_digest(const Digest& digest) noexcept {
    std::array<Byte, N> out{};
    const std::size_t width = N < Digest::kBytes ? N : Digest::kBytes;
    for (std::size_t i = 0; i < width; ++i) out[i] = digest.bytes()[i];
    return FixedId(out);
  }

  [[nodiscard]] const std::array<Byte, N>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] ByteView view() const noexcept { return ByteView(bytes_.data(), N); }
  [[nodiscard]] std::string hex() const { return to_hex(view()); }

  [[nodiscard]] bool is_zero() const noexcept {
    Byte accumulator = 0;
    for (const Byte b : bytes_) accumulator = static_cast<Byte>(accumulator | b);
    return accumulator == 0;
  }

  // Canonical field encoding. Blobs are used rather than digests so that a
  // 16-byte identifier is never padded into a 32-byte slot where its width
  // would be lost.
  void encode(CanonicalEncoder& encoder) const { encoder.blob(view()); }

  [[nodiscard]] static Result<FixedId> decode(CanonicalDecoder& decoder) {
    const auto raw = decoder.blob(N);
    if (!raw.ok()) return raw.status();
    if (raw.value().size() != N) {
      return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION,
                    "identifier field has the wrong width");
    }
    return FixedId::from_bytes(raw.value());
  }

  friend bool operator==(const FixedId& a, const FixedId& b) noexcept { return a.bytes_ == b.bytes_; }
  friend bool operator!=(const FixedId& a, const FixedId& b) noexcept { return !(a == b); }
  friend bool operator<(const FixedId& a, const FixedId& b) noexcept { return a.bytes_ < b.bytes_; }

 private:
  std::array<Byte, N> bytes_{};
};

struct StateObjectIdTag {};
struct MovementIdTag {};
struct TransferAttemptIdTag {};
struct BootIdTag {};
struct SessionIdTag {};
struct NonceTag {};

using StateObjectId = FixedId<StateObjectIdTag, 32>;
using MovementId = FixedId<MovementIdTag, 16>;
using TransferAttemptId = FixedId<TransferAttemptIdTag, 16>;
using BootId = FixedId<BootIdTag, 16>;
using SessionId = FixedId<SessionIdTag, 16>;
using Nonce = FixedId<NonceTag, 32>;

// ---------------------------------------------------------------------------
// Generations
// ---------------------------------------------------------------------------

template <class Tag>
class Generation {
 public:
  using value_type = std::uint64_t;

  Generation() noexcept = default;
  explicit Generation(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] static Result<Generation> from_value(std::uint64_t value) {
    if (value == 0) {
      return Status(ReasonCode::INVALID_GENERATION, "generation zero is not a valid generation");
    }
    return Generation(value);
  }

  [[nodiscard]] bool is_set() const noexcept { return value_ != 0; }
  [[nodiscard]] std::uint64_t value() const noexcept { return value_; }

  // Overflow-checked successor. Exhausting the generation space is an error,
  // never a wraparound.
  [[nodiscard]] Result<Generation> next() const {
    if (value_ == UINT64_MAX) {
      return Status(ReasonCode::SIZE_OVERFLOW, "generation space exhausted");
    }
    return Generation(value_ + 1U);
  }

  friend bool operator==(const Generation& a, const Generation& b) noexcept { return a.value_ == b.value_; }
  friend bool operator!=(const Generation& a, const Generation& b) noexcept { return !(a == b); }
  friend bool operator<(const Generation& a, const Generation& b) noexcept { return a.value_ < b.value_; }
  friend bool operator<=(const Generation& a, const Generation& b) noexcept { return a.value_ <= b.value_; }
  friend bool operator>(const Generation& a, const Generation& b) noexcept { return a.value_ > b.value_; }
  friend bool operator>=(const Generation& a, const Generation& b) noexcept { return a.value_ >= b.value_; }

 private:
  std::uint64_t value_ = 0;
};

struct StateGenerationTag {};
struct MovementGenerationTag {};
struct CompatibilityGenerationTag {};
struct TopologyGenerationTag {};
struct PolicyGenerationTag {};
struct EpochTag {};

using StateGeneration = Generation<StateGenerationTag>;
using MovementGeneration = Generation<MovementGenerationTag>;
using CompatibilityGeneration = Generation<CompatibilityGenerationTag>;
using TopologyGeneration = Generation<TopologyGenerationTag>;
using PolicyGeneration = Generation<PolicyGenerationTag>;
using IncarnationEpoch = Generation<EpochTag>;

// ---------------------------------------------------------------------------
// Endpoint identity
// ---------------------------------------------------------------------------

// Operator-facing endpoint name. Deliberately a bounded, restricted ASCII
// string rather than an opaque id so that the CLI and the durable records stay
// readable; the wire still binds it into authenticated envelopes.
class EndpointId {
 public:
  static constexpr std::size_t kMaxLength = 63;

  EndpointId() = default;

  [[nodiscard]] static Result<EndpointId> parse(std::string_view text);
  [[nodiscard]] static bool is_valid(std::string_view text) noexcept;

  [[nodiscard]] const std::string& value() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

  friend bool operator==(const EndpointId& a, const EndpointId& b) noexcept { return a.value_ == b.value_; }
  friend bool operator!=(const EndpointId& a, const EndpointId& b) noexcept { return !(a == b); }
  friend bool operator<(const EndpointId& a, const EndpointId& b) noexcept { return a.value_ < b.value_; }

 private:
  explicit EndpointId(std::string value) : value_(std::move(value)) {}
  std::string value_;
};

// ---------------------------------------------------------------------------
// Incarnation
// ---------------------------------------------------------------------------

// A process instance of an endpoint. boot is freshly random on every process
// start and epoch is monotonic across restarts, so a restarted process is
// never mistaken for the process it replaced.
template <class Tag>
class Incarnation {
 public:
  Incarnation() noexcept = default;
  Incarnation(EndpointId endpoint, BootId boot, IncarnationEpoch epoch) noexcept
      : endpoint_(std::move(endpoint)), boot_(boot), epoch_(epoch) {}

  [[nodiscard]] static Result<Incarnation> make(EndpointId endpoint, BootId boot, IncarnationEpoch epoch) {
    if (!epoch.is_set()) {
      return Status(ReasonCode::INVALID_GENERATION, "incarnation epoch must be non-zero");
    }
    if (endpoint.empty()) {
      return Status(ReasonCode::INVALID_ID, "incarnation endpoint must not be empty");
    }
    if (boot.is_zero()) {
      return Status(ReasonCode::INVALID_ID, "incarnation boot id must not be zero");
    }
    return Incarnation(std::move(endpoint), boot, epoch);
  }

  [[nodiscard]] const EndpointId& endpoint() const noexcept { return endpoint_; }
  [[nodiscard]] const BootId& boot() const noexcept { return boot_; }
  [[nodiscard]] const IncarnationEpoch& epoch() const noexcept { return epoch_; }
  [[nodiscard]] bool is_set() const noexcept { return !endpoint_.empty() && !boot_.is_zero() && epoch_.is_set(); }

  // Explicit conversion between role-specific incarnations. It is never
  // implicit, so a source incarnation cannot drift into a destination slot
  // without a deliberate act.
  template <class OtherTag>
  [[nodiscard]] Incarnation<OtherTag> retag() const noexcept {
    return Incarnation<OtherTag>(endpoint_, boot_, epoch_);
  }

  friend bool operator==(const Incarnation& a, const Incarnation& b) noexcept {
    return a.endpoint_ == b.endpoint_ && a.boot_ == b.boot_ && a.epoch_ == b.epoch_;
  }
  friend bool operator!=(const Incarnation& a, const Incarnation& b) noexcept { return !(a == b); }

 private:
  EndpointId endpoint_;
  BootId boot_;
  IncarnationEpoch epoch_;
};

struct SourceIncarnationTag {};
struct DestinationIncarnationTag {};
struct EndpointIncarnationTag {};

using SourceIncarnation = Incarnation<SourceIncarnationTag>;
using DestinationIncarnation = Incarnation<DestinationIncarnationTag>;
using EndpointIncarnation = Incarnation<EndpointIncarnationTag>;

// ---------------------------------------------------------------------------
// State kinds and canonical object identity
// ---------------------------------------------------------------------------

enum class StateKind : std::uint8_t {
  UNKNOWN = 0,
  MODEL = 1,
  ADAPTER = 2,
  TENSOR = 3,
  KV = 4,
  PREFIX = 5,
  CHECKPOINT = 6,
  ARTIFACT = 7,
  GENERIC_BLOB = 8,
};

[[nodiscard]] const char* to_string(StateKind kind) noexcept;
[[nodiscard]] const char* state_kind_description(StateKind kind) noexcept;
[[nodiscard]] bool state_kind_from_string(std::string_view text, StateKind& out) noexcept;

// UNKNOWN is a real, distinct kind: it is never treated as any other kind, and
// state objects of unknown kind are still movable as opaque bytes.
[[nodiscard]] inline bool is_known_state_kind(StateKind kind) noexcept {
  return kind != StateKind::UNKNOWN;
}

// Canonical logical identity of a state object: SHA-256 over a domain
// separator, the kind, and the logical name. Independent of content, so
// generations of the same object share an id.
[[nodiscard]] Result<StateObjectId> derive_state_object_id(StateKind kind, std::string_view name);

// Canonical digest of one chunk payload, binding the payload to the exact
// object, generation, index, offset, and length it is claimed to occupy. A
// chunk cannot be replayed into a different slot without changing this digest.
[[nodiscard]] Digest compute_chunk_digest(const StateObjectId& object_id, StateGeneration generation,
                                          std::uint32_t chunk_index, std::uint64_t chunk_offset,
                                          std::uint64_t chunk_length, ByteView payload) noexcept;

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

class EntropySource {
 public:
  EntropySource() = default;
  EntropySource(const EntropySource&) = delete;
  EntropySource& operator=(const EntropySource&) = delete;
  virtual ~EntropySource() = default;

  virtual void fill(ByteSpan out) = 0;
};

// Operating system entropy (RtlGenRandom on Windows, /dev/urandom elsewhere).
class SystemEntropySource final : public EntropySource {
 public:
  SystemEntropySource() = default;
  void fill(ByteSpan out) override;
};

// Reproducible stream for proofs. Never used unless a caller asks for it.
class DeterministicEntropySource final : public EntropySource {
 public:
  explicit DeterministicEntropySource(std::uint64_t seed) noexcept : state_(seed) {}
  void fill(ByteSpan out) override;
  [[nodiscard]] std::uint64_t counter() const noexcept { return counter_; }

 private:
  [[nodiscard]] std::uint64_t next_u64() noexcept;

  std::uint64_t state_;
  std::uint64_t counter_ = 0;
};

[[nodiscard]] EntropySource& system_entropy() noexcept;

// Issuer of fresh identifiers. Uniqueness is the requirement; secrecy is not
// claimed for ids, only for nonces and keys.
class IdIssuer {
 public:
  explicit IdIssuer(EntropySource& entropy) noexcept : entropy_(&entropy) {}
  IdIssuer() noexcept : entropy_(&system_entropy()) {}

  [[nodiscard]] MovementId new_movement_id();
  [[nodiscard]] TransferAttemptId new_attempt_id();
  [[nodiscard]] BootId new_boot_id();
  [[nodiscard]] SessionId new_session_id();
  [[nodiscard]] Nonce new_nonce();

 private:
  EntropySource* entropy_;
};

}  // namespace smf

namespace std {

template <class Tag, size_t N>
struct hash<smf::FixedId<Tag, N>> {
  size_t operator()(const smf::FixedId<Tag, N>& value) const noexcept {
    const auto& raw = value.bytes();
    size_t seed = 1469598103934665603ULL;
    for (size_t i = 0; i < N; ++i) {
      seed ^= static_cast<size_t>(raw[i]);
      seed *= 1099511628211ULL;
    }
    return seed;
  }
};

template <class Tag>
struct hash<smf::Generation<Tag>> {
  size_t operator()(const smf::Generation<Tag>& value) const noexcept {
    return std::hash<uint64_t>{}(value.value());
  }
};

template <>
struct hash<smf::EndpointId> {
  size_t operator()(const smf::EndpointId& value) const noexcept {
    return std::hash<std::string>{}(value.value());
  }
};

}  // namespace std

#endif  // SMF_IDS_HPP
