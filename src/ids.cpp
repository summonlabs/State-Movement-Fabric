// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/ids.hpp"

#include <random>

#include "smf/codec.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cstdio>
#endif

namespace smf {
namespace {

[[nodiscard]] std::uint64_t splitmix64(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

[[nodiscard]] bool is_name_byte(char c) noexcept {
  const bool digit = c >= '0' && c <= '9';
  const bool lower = c >= 'a' && c <= 'z';
  const bool upper = c >= 'A' && c <= 'Z';
  return digit || lower || upper || c == '.' || c == '_' || c == '-';
}

}  // namespace

Result<EndpointId> EndpointId::parse(std::string_view text) {
  if (text.empty()) {
    return Status(ReasonCode::INVALID_ID, "endpoint id must not be empty");
  }
  if (text.size() > kMaxLength) {
    return Status(ReasonCode::INVALID_ID, "endpoint id exceeds the maximum length");
  }
  if (text.front() == '-' || text.front() == '.') {
    return Status(ReasonCode::INVALID_ID, "endpoint id must not start with '-' or '.'");
  }
  for (const char c : text) {
    if (!is_name_byte(c)) {
      return Status(ReasonCode::INVALID_ID,
                    "endpoint id may only contain ASCII letters, digits, '.', '_', and '-'");
    }
  }
  return EndpointId(std::string(text));
}

bool EndpointId::is_valid(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxLength) return false;
  if (text.front() == '-' || text.front() == '.') return false;
  for (const char c : text) {
    if (!is_name_byte(c)) return false;
  }
  return true;
}

const char* to_string(StateKind kind) noexcept {
  switch (kind) {
    case StateKind::UNKNOWN:
      return "UNKNOWN";
    case StateKind::MODEL:
      return "MODEL";
    case StateKind::ADAPTER:
      return "ADAPTER";
    case StateKind::TENSOR:
      return "TENSOR";
    case StateKind::KV:
      return "KV";
    case StateKind::PREFIX:
      return "PREFIX";
    case StateKind::CHECKPOINT:
      return "CHECKPOINT";
    case StateKind::ARTIFACT:
      return "ARTIFACT";
    case StateKind::GENERIC_BLOB:
      return "GENERIC_BLOB";
  }
  return "UNRECOGNIZED_STATE_KIND";
}

const char* state_kind_description(StateKind kind) noexcept {
  switch (kind) {
    case StateKind::UNKNOWN:
      return "kind is not known to this runtime; the bytes are moved as an opaque blob";
    case StateKind::MODEL:
      return "model weights";
    case StateKind::ADAPTER:
      return "adapter or delta weights";
    case StateKind::TENSOR:
      return "individual tensor payload";
    case StateKind::KV:
      return "attention key/value cache";
    case StateKind::PREFIX:
      return "shared prompt prefix cache";
    case StateKind::CHECKPOINT:
      return "training or serving checkpoint";
    case StateKind::ARTIFACT:
      return "derived artifact";
    case StateKind::GENERIC_BLOB:
      return "generic opaque blob";
  }
  return "unrecognized state kind";
}

bool state_kind_from_string(std::string_view text, StateKind& out) noexcept {
  constexpr StateKind kAll[] = {StateKind::UNKNOWN,  StateKind::MODEL,  StateKind::ADAPTER,
                                StateKind::TENSOR,   StateKind::KV,     StateKind::PREFIX,
                                StateKind::CHECKPOINT, StateKind::ARTIFACT, StateKind::GENERIC_BLOB};
  for (const StateKind kind : kAll) {
    if (text == to_string(kind)) {
      out = kind;
      return true;
    }
  }
  return false;
}

Result<StateObjectId> derive_state_object_id(StateKind kind, std::string_view name) {
  if (name.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "state object name must not be empty");
  }
  if (name.size() > 4096) {
    return Status(ReasonCode::INVALID_ARGUMENT, "state object name exceeds the maximum length");
  }
  if (!is_valid_utf8(as_bytes(name))) {
    return Status(ReasonCode::INVALID_UTF8, "state object name is not valid UTF-8");
  }
  CanonicalEncoder encoder("SMF-STATE-OBJECT-ID-v1");
  encoder.u8(static_cast<std::uint8_t>(kind));
  encoder.text(name);
  return StateObjectId::from_digest(canonical_digest(encoder));
}

Digest compute_chunk_digest(const StateObjectId& object_id, StateGeneration generation,
                            std::uint32_t chunk_index, std::uint64_t chunk_offset,
                            std::uint64_t chunk_length, ByteView payload) noexcept {
  CanonicalEncoder encoder("SMF-CHUNK-v1");
  encoder.digest(Digest(object_id.bytes()));
  encoder.u64(generation.value());
  encoder.u32(chunk_index);
  encoder.u64(chunk_offset);
  encoder.u64(chunk_length);
  encoder.blob(payload);
  return canonical_digest(encoder);
}

void SystemEntropySource::fill(ByteSpan out) {
  if (out.empty()) return;
#if defined(_WIN32)
  const NTSTATUS status =
      BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status >= 0) return;
#endif
  std::random_device device;
  std::size_t offset = 0;
  while (offset < out.size()) {
    const std::uint32_t word = device();
    for (std::size_t i = 0; i < 4 && offset < out.size(); ++i, ++offset) {
      out[offset] = static_cast<Byte>((word >> (8U * i)) & 0xFFU);
    }
  }
}

std::uint64_t DeterministicEntropySource::next_u64() noexcept {
  ++counter_;
  return splitmix64(state_);
}

void DeterministicEntropySource::fill(ByteSpan out) {
  std::size_t offset = 0;
  while (offset < out.size()) {
    const std::uint64_t word = next_u64();
    for (std::size_t i = 0; i < 8 && offset < out.size(); ++i, ++offset) {
      out[offset] = static_cast<Byte>((word >> (8U * i)) & 0xFFU);
    }
  }
}

EntropySource& system_entropy() noexcept {
  static SystemEntropySource instance;
  return instance;
}

MovementId IdIssuer::new_movement_id() {
  std::array<Byte, MovementId::kBytes> raw{};
  entropy_->fill(ByteSpan(raw.data(), raw.size()));
  return MovementId(raw);
}

TransferAttemptId IdIssuer::new_attempt_id() {
  std::array<Byte, TransferAttemptId::kBytes> raw{};
  entropy_->fill(ByteSpan(raw.data(), raw.size()));
  return TransferAttemptId(raw);
}

BootId IdIssuer::new_boot_id() {
  std::array<Byte, BootId::kBytes> raw{};
  entropy_->fill(ByteSpan(raw.data(), raw.size()));
  return BootId(raw);
}

SessionId IdIssuer::new_session_id() {
  std::array<Byte, SessionId::kBytes> raw{};
  entropy_->fill(ByteSpan(raw.data(), raw.size()));
  return SessionId(raw);
}

Nonce IdIssuer::new_nonce() {
  std::array<Byte, Nonce::kBytes> raw{};
  entropy_->fill(ByteSpan(raw.data(), raw.size()));
  return Nonce(raw);
}

}  // namespace smf
