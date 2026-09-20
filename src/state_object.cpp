// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/state_object.hpp"

#include <string>

namespace smf {
namespace {

[[nodiscard]] constexpr std::uint64_t ceil_div(std::uint64_t numerator,
                                               std::uint64_t denominator) noexcept {
  return (numerator + denominator - 1U) / denominator;
}

}  // namespace

Result<StateObjectDescriptor> StateObjectDescriptor::create(StateKind kind, std::string name,
                                                            StateGeneration generation,
                                                            Digest content_digest,
                                                            std::uint64_t total_bytes,
                                                            std::uint64_t chunk_bytes,
                                                            Millis created_unix_millis,
                                                            std::string producer) {
  const auto object_id = derive_state_object_id(kind, name);
  if (!object_id.ok()) return object_id.status();

  StateObjectDescriptor descriptor;
  descriptor.object_id = object_id.value();
  descriptor.kind = kind;
  descriptor.name = std::move(name);
  descriptor.generation = generation;
  descriptor.content_digest = content_digest;
  descriptor.total_bytes = total_bytes;
  descriptor.chunk_bytes = chunk_bytes;
  descriptor.chunk_count =
      total_bytes == 0 ? 0U : static_cast<std::uint32_t>(ceil_div(total_bytes, chunk_bytes));
  descriptor.created_unix_millis = created_unix_millis;
  descriptor.producer = std::move(producer);

  const Status status = descriptor.validate();
  if (!status.ok()) return status;
  return descriptor;
}

Status StateObjectDescriptor::validate() const {
  if (object_id.is_zero()) {
    return Status(ReasonCode::INVALID_ID, "state object id must not be zero");
  }
  if (name.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "state object name must not be empty");
  }
  if (name.size() > kMaxObjectNameBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "state object name exceeds the maximum length");
  }
  if (!is_valid_utf8(as_bytes(name))) {
    return Status(ReasonCode::INVALID_UTF8, "state object name is not valid UTF-8");
  }
  if (name.size() > kMaxTextBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "state object name exceeds the text bound");
  }

  const auto derived = derive_state_object_id(kind, name);
  if (!derived.ok()) return derived.status();
  if (derived.value() != object_id) {
    return Status(ReasonCode::INVALID_ID,
                  "state object id does not match the canonical identity of its kind and name");
  }

  if (!generation.is_set()) {
    return Status(ReasonCode::INVALID_GENERATION, "state generation must be non-zero");
  }
  if (content_digest.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST, "content digest must not be zero");
  }
  if (total_bytes > kMaxObjectBytes) {
    return Status(ReasonCode::INVALID_SIZE, "state object exceeds the maximum supported size");
  }
  if (chunk_bytes < kMinChunkBytes || chunk_bytes > kMaxChunkBytes) {
    return Status(ReasonCode::INVALID_SIZE, "chunk size is outside the supported range");
  }
  if (chunk_bytes == 0) {
    return Status(ReasonCode::INVALID_SIZE, "chunk size must not be zero");
  }

  const std::uint64_t expected_chunks =
      total_bytes == 0 ? 0U : ceil_div(total_bytes, chunk_bytes);
  if (expected_chunks > kMaxChunksPerObject) {
    return Status(ReasonCode::INVALID_SIZE, "state object would require too many chunks");
  }
  if (expected_chunks != static_cast<std::uint64_t>(chunk_count)) {
    return Status(ReasonCode::INVALID_SIZE,
                  "chunk count is inconsistent with the total size and chunk size");
  }

  if (producer.size() > kMaxTextBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "producer string exceeds the text bound");
  }
  if (!producer.empty() && !is_valid_utf8(as_bytes(producer))) {
    return Status(ReasonCode::INVALID_UTF8, "producer string is not valid UTF-8");
  }
  return Status::success();
}

bool StateObjectDescriptor::same_version(const StateObjectDescriptor& other) const {
  return object_id == other.object_id && generation == other.generation &&
         content_digest == other.content_digest && total_bytes == other.total_bytes &&
         chunk_bytes == other.chunk_bytes && chunk_count == other.chunk_count;
}

Result<std::uint64_t> StateObjectDescriptor::chunk_offset(std::uint32_t index) const {
  if (index >= chunk_count) {
    return Status(ReasonCode::CHUNK_INDEX_OUT_OF_RANGE, "chunk index is outside the object");
  }
  std::uint64_t offset = 0;
  if (!checked_mul(static_cast<std::uint64_t>(index), chunk_bytes, offset)) {
    return Status(ReasonCode::SIZE_OVERFLOW, "chunk offset computation overflowed");
  }
  if (offset >= total_bytes) {
    return Status(ReasonCode::CHUNK_INDEX_OUT_OF_RANGE, "chunk offset is beyond the object");
  }
  return offset;
}

Result<std::uint64_t> StateObjectDescriptor::chunk_length(std::uint32_t index) const {
  const auto offset = chunk_offset(index);
  if (!offset.ok()) return offset.status();
  const std::uint64_t remaining = total_bytes - offset.value();
  return remaining < chunk_bytes ? remaining : chunk_bytes;
}

void StateObjectDescriptor::encode(CanonicalEncoder& encoder) const {
  encoder.digest(Digest(object_id.bytes()));
  encoder.u8(static_cast<std::uint8_t>(kind));
  encoder.text(name);
  encoder.u64(generation.value());
  encoder.digest(content_digest);
  encoder.u64(total_bytes);
  encoder.u64(chunk_bytes);
  encoder.u32(chunk_count);
  encoder.i64(created_unix_millis);
  encoder.text(producer);
  encoder.boolean(repeatable);
}

Result<StateObjectDescriptor> StateObjectDescriptor::decode(CanonicalDecoder& decoder) {
  StateObjectDescriptor descriptor;

  const auto object_id = decoder.digest();
  if (!object_id.ok()) return object_id.status();
  descriptor.object_id = StateObjectId::from_digest(object_id.value());

  const auto kind = decoder.u8();
  if (!kind.ok()) return kind.status();
  if (kind.value() > static_cast<std::uint8_t>(StateKind::GENERIC_BLOB)) {
    return Status(ReasonCode::INVALID_STATE_KIND, "state kind is not recognized");
  }
  descriptor.kind = static_cast<StateKind>(kind.value());

  const auto name = decoder.text(kMaxObjectNameBytes);
  if (!name.ok()) return name.status();
  descriptor.name = std::string(name.value());

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  descriptor.generation = StateGeneration(generation.value());

  const auto content = decoder.digest();
  if (!content.ok()) return content.status();
  descriptor.content_digest = content.value();

  const auto total = decoder.u64();
  if (!total.ok()) return total.status();
  descriptor.total_bytes = total.value();

  const auto chunk = decoder.u64();
  if (!chunk.ok()) return chunk.status();
  descriptor.chunk_bytes = chunk.value();

  const auto count = decoder.u32();
  if (!count.ok()) return count.status();
  descriptor.chunk_count = count.value();

  const auto created = decoder.i64();
  if (!created.ok()) return created.status();
  descriptor.created_unix_millis = created.value();

  const auto producer = decoder.text(kMaxTextBytes);
  if (!producer.ok()) return producer.status();
  descriptor.producer = std::string(producer.value());

  const auto repeatable = decoder.boolean();
  if (!repeatable.ok()) return repeatable.status();
  descriptor.repeatable = repeatable.value();

  const Status status = descriptor.validate();
  if (!status.ok()) return status;
  return descriptor;
}

Digest StateObjectDescriptor::descriptor_digest() const {
  CanonicalEncoder encoder("SMF-STATE-OBJECT-DESCRIPTOR-v1");
  encode(encoder);
  return canonical_digest(encoder);
}

std::string describe(const StateObjectDescriptor& descriptor) {
  std::string out = to_string(descriptor.kind);
  out += " ";
  out += descriptor.name;
  out += "@";
  out += std::to_string(descriptor.generation.value());
  out += " ";
  out += std::to_string(descriptor.total_bytes);
  out += "B/";
  out += std::to_string(descriptor.chunk_count);
  out += "chunks/";
  out += descriptor.content_digest.hex().substr(0, 12);
  return out;
}

}  // namespace smf
