// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf_fixture.hpp"

#include <cstdio>

#include "smf/digest.hpp"
#include "smf_test.hpp"

namespace smftest {

smf::StateObjectDescriptor make_descriptor(smf::StateKind kind, const std::string& name,
                                           std::uint64_t generation, std::uint64_t total_bytes,
                                           std::uint64_t chunk_bytes) {
  const smf::Digest content = smf::sha256(name + "@" + std::to_string(generation));
  auto descriptor = smf::StateObjectDescriptor::create(kind, name, smf::StateGeneration(generation),
                                                       content, total_bytes, chunk_bytes,
                                                       smf::kEpoch2026, "fixture");
  if (!descriptor.ok()) {
    smf::Status status = descriptor.status();
    std::fprintf(stderr, "fixture descriptor is invalid: %s\n", status.to_string().c_str());
    std::abort();
  }
  return descriptor.value();
}

smf::MovementRecord make_record(const smf::StateObjectDescriptor& object, const std::string& source,
                                const std::string& destination, std::uint64_t epoch) {
  smf::IdIssuer issuer;
  smf::MovementRecord record;
  record.id = issuer.new_movement_id();
  record.generation = smf::MovementGeneration(1);
  record.object = object;
  record.source = smf::EndpointId::parse(source).value();
  record.destination = smf::EndpointId::parse(destination).value();
  record.source_incarnation =
      smf::SourceIncarnation::make(record.source, issuer.new_boot_id(), smf::IncarnationEpoch(epoch))
          .value();
  record.destination_incarnation =
      smf::DestinationIncarnation::make(record.destination, issuer.new_boot_id(),
                                        smf::IncarnationEpoch(epoch))
          .value();
  record.compatibility_generation = smf::CompatibilityGeneration(1);
  record.topology_generation = smf::TopologyGeneration(1);
  record.policy_generation = smf::PolicyGeneration(1);
  record.state = smf::MovementState::PLANNED;
  record.created_unix_millis = smf::kEpoch2026;
  record.updated_unix_millis = smf::kEpoch2026;
  record.provenance.set_bound(16);
  const smf::Status appended =
      record.provenance.append(smf::ProvenanceEventKind::CREATED, smf::MovementState::PLANNED,
                               record.generation, smf::ReasonCode::OK, smf::kEpoch2026, "fixture");
  if (!appended.ok()) std::abort();
  const smf::Status valid = record.validate();
  if (!valid.ok()) {
    std::fprintf(stderr, "fixture record is invalid: %s\n", valid.to_string().c_str());
    std::abort();
  }
  return record;
}

smf::Bytes pattern_bytes(std::uint64_t seed, std::size_t length) {
  Rng rng(seed);
  return rng.bytes(length);
}

smf::Bytes read_file(const std::filesystem::path& path) {
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) return {};
  std::fseek(file, 0, SEEK_END);
  const long size = std::ftell(file);
  std::fseek(file, 0, SEEK_SET);
  smf::Bytes out(static_cast<std::size_t>(size < 0 ? 0 : size));
  if (!out.empty()) {
    const std::size_t read = std::fread(out.data(), 1, out.size(), file);
    out.resize(read);
  }
  std::fclose(file);
  return out;
}

void write_file(const std::filesystem::path& path, smf::ByteView contents) {
  std::FILE* file = std::fopen(path.string().c_str(), "wb");
  if (file == nullptr) std::abort();
  if (!contents.empty()) std::fwrite(contents.data(), 1, contents.size(), file);
  std::fclose(file);
}

std::uint64_t file_size(const std::filesystem::path& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  return error ? 0 : static_cast<std::uint64_t>(size);
}

void truncate_file(const std::filesystem::path& path, std::uint64_t size) {
  smf::Bytes contents = read_file(path);
  if (size < contents.size()) contents.resize(static_cast<std::size_t>(size));
  write_file(path, smf::as_bytes(contents));
}

void append_bytes(const std::filesystem::path& path, smf::ByteView extra) {
  std::FILE* file = std::fopen(path.string().c_str(), "ab");
  if (file == nullptr) std::abort();
  if (!extra.empty()) std::fwrite(extra.data(), 1, extra.size(), file);
  std::fclose(file);
}

void patch_bytes(const std::filesystem::path& path, std::uint64_t offset, smf::ByteView value) {
  smf::Bytes contents = read_file(path);
  if (offset + value.size() > contents.size()) std::abort();
  for (std::size_t i = 0; i < value.size(); ++i) {
    contents[static_cast<std::size_t>(offset) + i] = value[i];
  }
  write_file(path, smf::as_bytes(contents));
}

void patch_byte(const std::filesystem::path& path, std::uint64_t offset, std::uint8_t value) {
  const smf::Byte one = value;
  patch_bytes(path, offset, smf::ByteView(&one, 1));
}

std::uint8_t read_byte(const std::filesystem::path& path, std::uint64_t offset) {
  const smf::Bytes contents = read_file(path);
  if (offset >= contents.size()) std::abort();
  return contents[static_cast<std::size_t>(offset)];
}

void patch_u32_le(const std::filesystem::path& path, std::uint64_t offset, std::uint32_t value) {
  smf::Byte raw[4];
  for (std::size_t i = 0; i < 4; ++i) {
    raw[i] = static_cast<smf::Byte>((value >> (8U * i)) & 0xFFU);
  }
  patch_bytes(path, offset, smf::ByteView(raw, 4));
}

void patch_u64_le(const std::filesystem::path& path, std::uint64_t offset, std::uint64_t value) {
  smf::Byte raw[8];
  for (std::size_t i = 0; i < 8; ++i) {
    raw[i] = static_cast<smf::Byte>((value >> (8U * i)) & 0xFFU);
  }
  patch_bytes(path, offset, smf::ByteView(raw, 8));
}

std::vector<RecordSpan> scan_records(const std::filesystem::path& path) {
  std::vector<RecordSpan> spans;
  const smf::Bytes contents = read_file(path);
  if (contents.size() < store_layout::kFileHeaderBytes) return spans;

  std::uint64_t offset = store_layout::kFileHeaderBytes;
  while (offset + store_layout::kRecordHeaderBytes <= contents.size()) {
    const smf::Byte* header = contents.data() + offset;
    const std::uint64_t payload_length =
        static_cast<std::uint64_t>(header[store_layout::kRecordPayloadLength]) |
        (static_cast<std::uint64_t>(header[store_layout::kRecordPayloadLength + 1]) << 8U) |
        (static_cast<std::uint64_t>(header[store_layout::kRecordPayloadLength + 2]) << 16U) |
        (static_cast<std::uint64_t>(header[store_layout::kRecordPayloadLength + 3]) << 24U);
    RecordSpan span;
    span.offset = offset;
    span.header_bytes = store_layout::kRecordHeaderBytes;
    span.payload_bytes = payload_length;
    spans.push_back(span);
    if (payload_length > contents.size() - offset - store_layout::kRecordHeaderBytes) break;
    offset += store_layout::kRecordHeaderBytes + payload_length;
  }
  return spans;
}

void reseal_record(const std::filesystem::path& path, std::size_t index) {
  const std::vector<RecordSpan> spans = scan_records(path);
  if (index >= spans.size()) std::abort();
  const RecordSpan& span = spans[index];
  const smf::Bytes contents = read_file(path);
  if (span.offset + span.header_bytes + span.payload_bytes > contents.size()) std::abort();

  smf::Sha256 hasher;
  hasher.update(smf::ByteView(contents.data() + span.offset, 24));
  hasher.update(smf::ByteView(contents.data() + span.offset + span.header_bytes, span.payload_bytes));
  const smf::Digest digest = hasher.finalize();
  patch_bytes(path, span.offset + store_layout::kRecordChecksum, digest.view());
}

}  // namespace smftest
