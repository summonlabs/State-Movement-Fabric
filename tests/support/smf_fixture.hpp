// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared fixtures for the proof suites: valid movement records, descriptors, and
// byte-level file surgery used by the persistence adversarial proofs.

#ifndef SMF_TEST_FIXTURE_HPP
#define SMF_TEST_FIXTURE_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "smf/ids.hpp"
#include "smf/movement.hpp"
#include "smf/movement_store.hpp"
#include "smf/state_object.hpp"

namespace smftest {

[[nodiscard]] smf::StateObjectDescriptor make_descriptor(smf::StateKind kind, const std::string& name,
                                                         std::uint64_t generation,
                                                         std::uint64_t total_bytes,
                                                         std::uint64_t chunk_bytes);

// A record that satisfies every invariant MovementRecord::validate() enforces.
[[nodiscard]] smf::MovementRecord make_record(const smf::StateObjectDescriptor& object,
                                              const std::string& source, const std::string& destination,
                                              std::uint64_t epoch = 1);

// Deterministic bytes for a given seed and length.
[[nodiscard]] smf::Bytes pattern_bytes(std::uint64_t seed, std::size_t length);

// --- byte-level file surgery ------------------------------------------------

[[nodiscard]] smf::Bytes read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, smf::ByteView contents);
[[nodiscard]] std::uint64_t file_size(const std::filesystem::path& path);
void truncate_file(const std::filesystem::path& path, std::uint64_t size);
void append_bytes(const std::filesystem::path& path, smf::ByteView extra);
void patch_byte(const std::filesystem::path& path, std::uint64_t offset, std::uint8_t value);
void patch_u32_le(const std::filesystem::path& path, std::uint64_t offset, std::uint32_t value);
void patch_u64_le(const std::filesystem::path& path, std::uint64_t offset, std::uint64_t value);
void patch_bytes(const std::filesystem::path& path, std::uint64_t offset, smf::ByteView value);
[[nodiscard]] std::uint8_t read_byte(const std::filesystem::path& path, std::uint64_t offset);

struct RecordSpan {
  std::uint64_t offset = 0;
  std::uint64_t header_bytes = 0;
  std::uint64_t payload_bytes = 0;
};

// Byte-accurate scan of a movement-store log. Used by the adversarial proofs to
// aim corruption at an exact record without hard-coding record sizes.
[[nodiscard]] std::vector<RecordSpan> scan_records(const std::filesystem::path& path);

// Recomputes the checksum of one record so that its container is internally
// consistent. This is how the proofs separate "damaged container" from
// "well-formed container carrying an impossible payload".
void reseal_record(const std::filesystem::path& path, std::size_t index);

// Offsets in the durable movement-store format, used to aim corruption.
namespace store_layout {
inline constexpr std::uint64_t kFileHeaderBytes = 96;
inline constexpr std::uint64_t kRecordHeaderBytes = 56;
inline constexpr std::uint64_t kFileMagic = 0;
inline constexpr std::uint64_t kFileVersion = 8;
inline constexpr std::uint64_t kFileHeaderSize = 12;
inline constexpr std::uint64_t kFileChecksum = 64;
inline constexpr std::uint64_t kRecordMagic = 0;
inline constexpr std::uint64_t kRecordVersion = 4;
inline constexpr std::uint64_t kRecordType = 5;
inline constexpr std::uint64_t kRecordReserved = 6;
inline constexpr std::uint64_t kRecordSequence = 8;
inline constexpr std::uint64_t kRecordPayloadLength = 16;
inline constexpr std::uint64_t kRecordReserved2 = 20;
inline constexpr std::uint64_t kRecordChecksum = 24;
inline constexpr std::uint64_t kPayload = 56;

// Byte offset of the n-th record header (0-based).
[[nodiscard]] inline std::uint64_t record_offset(std::uint64_t index,
                                                 std::uint64_t payload_bytes) {
  return kFileHeaderBytes + (index * (kRecordHeaderBytes + payload_bytes));
}
}  // namespace store_layout

}  // namespace smftest

#endif  // SMF_TEST_FIXTURE_HPP
