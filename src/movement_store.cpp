// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/movement_store.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <system_error>

#include "smf/codec.hpp"
#include "smf/logging.hpp"
#include "smf/version.hpp"
#include "file_utils.hpp"

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace smf {
namespace {

constexpr char kFileMagic[8] = {'S', 'M', 'F', 'M', 'S', 'T', '0', '1'};
constexpr char kRecordMagic[4] = {'S', 'M', 'F', 'R'};
constexpr std::size_t kFileHeaderBytes = 96;
constexpr std::size_t kRecordHeaderBytes = 56;
constexpr std::uint8_t kRecordMovement = 1;
constexpr std::uint8_t kRecordCoordinatorState = 2;
constexpr std::uint8_t kRecordRetire = 3;

struct RecordHeader {
  std::uint8_t type = 0;
  std::uint64_t sequence = 0;
  std::uint32_t payload_length = 0;
  Digest checksum;
};

void store_le(std::uint64_t value, Byte* out, std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    out[i] = static_cast<Byte>((value >> (8U * i)) & 0xFFU);
  }
}

[[nodiscard]] std::uint64_t load_le(const Byte* data, std::size_t width) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8U * i);
  }
  return value;
}

[[nodiscard]] Digest record_checksum(const Byte* header_prefix, ByteView payload) {
  Sha256 hasher;
  hasher.update(ByteView(header_prefix, 24));
  hasher.update(payload);
  return hasher.finalize();
}

}  // namespace

void CoordinatorPersistentState::encode(CanonicalEncoder& encoder) const {
  encoder.u64(epoch.value());
  encoder.u64(policy_generation.value());
  encoder.u64(compatibility_generation.value());
  encoder.u64(topology_generation.value());
  encoder.digest(policy_digest);
  encoder.i64(last_saved_unix_millis);
}

Result<CoordinatorPersistentState> CoordinatorPersistentState::decode(CanonicalDecoder& decoder) {
  CoordinatorPersistentState state;

  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  state.epoch = IncarnationEpoch(epoch.value());

  const auto policy = decoder.u64();
  if (!policy.ok()) return policy.status();
  state.policy_generation = PolicyGeneration(policy.value());

  const auto compatibility = decoder.u64();
  if (!compatibility.ok()) return compatibility.status();
  state.compatibility_generation = CompatibilityGeneration(compatibility.value());

  const auto topology = decoder.u64();
  if (!topology.ok()) return topology.status();
  state.topology_generation = TopologyGeneration(topology.value());

  const auto digest = decoder.digest();
  if (!digest.ok()) return digest.status();
  state.policy_digest = digest.value();

  const auto saved = decoder.i64();
  if (!saved.ok()) return saved.status();
  state.last_saved_unix_millis = saved.value();

  if (!state.epoch.is_set()) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "persisted coordinator epoch must be non-zero");
  }
  return state;
}





MovementStore::~MovementStore() {
  // The exclusive lock and the open file handle are owned for the store's
  // lifetime and must both be released here. Leaking either one leaves the
  // directory permanently unusable and the final records unflushed.
  close_file();
  if (lock_handle_ != nullptr) {
    delete static_cast<FileLock*>(lock_handle_);
    lock_handle_ = nullptr;
  }
}

Result<std::unique_ptr<MovementStore>> MovementStore::open(const MovementStoreOptions& options,
                                                          StoreRecoveryReport* report) {
  if (options.directory.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "store directory must not be empty");
  }
  if (options.max_record_bytes == 0 || options.max_record_bytes > (64U << 20)) {
    return Status(ReasonCode::INVALID_ARGUMENT, "max_record_bytes is outside the supported range");
  }
  if (options.max_history_records == 0) {
    return Status(ReasonCode::INVALID_ARGUMENT, "max_history_records must be non-zero");
  }

  auto store = std::unique_ptr<MovementStore>(new MovementStore());
  store->options_ = options;
  store->log_path_ = options.directory / "movements.smf";
  store->lock_path_ = options.directory / "movements.lock";

  std::error_code error;
  std::filesystem::create_directories(options.directory, error);
  if (error) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not create the store directory");
  }

  if (options.exclusive_lock) {
    auto* lock = new FileLock();
    const Status acquired = lock->acquire(store->lock_path_);
    if (!acquired.ok()) {
      delete lock;
      return acquired;
    }
    store->lock_handle_ = lock;
  }

  StoreRecoveryReport local_report;
  std::uintmax_t existing_size = 0;
  if (std::filesystem::exists(store->log_path_, error)) {
    existing_size = std::filesystem::file_size(store->log_path_, error);
    if (error) {
      return Status(ReasonCode::STORE_IO_ERROR, "could not determine the store file size");
    }
  }
  // A zero-length file is exactly what a crash between create and header write
  // leaves behind, so it is treated as a new store rather than a damaged one.
  local_report.created = existing_size == 0;

  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(store->log_path_, true));

  if (local_report.created) {
    Bytes header(kFileHeaderBytes, Byte{0});
    std::memcpy(header.data(), kFileMagic, sizeof(kFileMagic));
    store_le(kMovementStoreFormatVersion, header.data() + 8, 2);
    store_le(kFileHeaderBytes, header.data() + 12, 4);
    const Digest checksum = sha256(ByteView(header.data(), 64));
    std::memcpy(header.data() + 64, checksum.data(), Digest::kBytes);
    SMF_RETURN_IF_ERROR(handle.write(smf::as_bytes(header)));
    SMF_RETURN_IF_ERROR(handle.sync());
  } else {
    Bytes header(kFileHeaderBytes);
    const auto read = handle.read(ByteSpan(header.data(), header.size()));
    if (!read.ok()) return read.status();
    if (read.value() != header.size()) {
      return Status(ReasonCode::STORE_TRUNCATED, "store file header is incomplete");
    }
    if (std::memcmp(header.data(), kFileMagic, sizeof(kFileMagic)) != 0) {
      return Status(ReasonCode::STORE_CORRUPT, "store file magic does not match");
    }
    const std::uint64_t version = load_le(header.data() + 8, 2);
    if (version != kMovementStoreFormatVersion) {
      return Status(ReasonCode::STORE_VERSION_UNSUPPORTED,
                    "store file format version is not supported");
    }
    const std::uint64_t header_size = load_le(header.data() + 12, 4);
    if (header_size != kFileHeaderBytes) {
      return Status(ReasonCode::STORE_CORRUPT, "store file header size is not recognised");
    }
    const Digest expected = sha256(ByteView(header.data(), 64));
    if (!constant_time_equal(expected.view(), ByteView(header.data() + 64, Digest::kBytes))) {
      return Status(ReasonCode::STORE_CHECKSUM_MISMATCH, "store file header checksum mismatch");
    }
  }

  // Sequential recovery.
  std::uint64_t offset = kFileHeaderBytes;
  std::uint64_t sequence = 0;
  std::vector<MovementRecord> loaded;
  std::optional<CoordinatorPersistentState> coordinator_state;
  std::vector<MovementId> retired;

  const std::uintmax_t file_size =
      local_report.created ? static_cast<std::uintmax_t>(kFileHeaderBytes) : existing_size;

  for (;;) {
    if (offset >= file_size) break;

    Bytes header(kRecordHeaderBytes);
    const std::uint64_t remaining = file_size - offset;
    const auto read = handle.read(ByteSpan(header.data(), header.size()));
    if (!read.ok()) return read.status();
    if (read.value() != header.size()) {
      local_report.partial_tail_truncated = true;
      local_report.truncated_bytes = remaining;
      break;
    }
    if (std::memcmp(header.data(), kRecordMagic, sizeof(kRecordMagic)) != 0) {
      return Status(ReasonCode::STORE_CORRUPT, "store record magic does not match");
    }
    if (header[4] != kMovementStoreFormatVersion) {
      return Status(ReasonCode::STORE_VERSION_UNSUPPORTED, "store record version is not supported");
    }
    if (load_le(header.data() + 6, 2) != 0 || load_le(header.data() + 20, 4) != 0) {
      return Status(ReasonCode::STORE_RECORD_INVALID, "store record reserved fields are non-zero");
    }
    const std::uint64_t payload_length = load_le(header.data() + 16, 4);
    if (payload_length > store->options_.max_record_bytes) {
      return Status(ReasonCode::STORE_OVERSIZED, "store record declares an oversized payload");
    }

    Bytes payload(static_cast<std::size_t>(payload_length));
    if (payload_length > file_size - offset - kRecordHeaderBytes) {
      local_report.partial_tail_truncated = true;
      local_report.truncated_bytes = file_size - offset;
      break;
    }
    if (!payload.empty()) {
      const auto payload_read = handle.read(ByteSpan(payload.data(), payload.size()));
      if (!payload_read.ok()) return payload_read.status();
      if (payload_read.value() != payload.size()) {
        local_report.partial_tail_truncated = true;
        local_report.truncated_bytes = file_size - offset;
        break;
      }
    }

    const Digest expected = record_checksum(header.data(), smf::as_bytes(payload));
    const bool checksum_ok =
        constant_time_equal(expected.view(), ByteView(header.data() + 24, Digest::kBytes));
    const std::uint64_t next_offset = offset + kRecordHeaderBytes + payload_length;
    if (!checksum_ok) {
      // A damaged final record with nothing after it is indistinguishable from a
      // torn write, so it is treated as a torn tail. Damage anywhere earlier is
      // corruption and stops recovery.
      if (next_offset >= file_size) {
        local_report.partial_tail_truncated = true;
        local_report.truncated_bytes = file_size - offset;
        break;
      }
      return Status(ReasonCode::STORE_CHECKSUM_MISMATCH, "store record checksum mismatch");
    }

    // The sequence number is checked before anything is applied. A duplicate or
    // regressing sequence means the log was rewritten, spliced, or replayed, and
    // the file is refused rather than silently reordered.
    const std::uint64_t record_sequence = load_le(header.data() + 8, 8);
    if (record_sequence <= sequence) {
      return Status(ReasonCode::STORE_RECORD_INVALID,
                    "store record sequence is not strictly increasing");
    }

    const auto applied = store->apply_record(header[5], smf::as_bytes(payload));
    if (!applied.ok()) return applied;

    sequence = record_sequence;
    local_report.records_read += 1;
    local_report.records_applied += 1;
    offset = next_offset;
  }

  if (local_report.partial_tail_truncated) {
    SMF_RETURN_IF_ERROR(handle.truncate_at(offset));
    SMF_RETURN_IF_ERROR(handle.sync());
  }

  store->log_bytes_ = offset;
  store->append_offset_ = offset;
  handle.close();
  store->file_ = new FileHandle();
  SMF_RETURN_IF_ERROR(static_cast<FileHandle*>(store->file_)->open(store->log_path_, true));
  SMF_RETURN_IF_ERROR(static_cast<FileHandle*>(store->file_)->seek(offset));

  local_report.movements_loaded = store->records_.size();
  local_report.retired_loaded = store->stats_.retired_total;
  store->stats_.records_read = local_report.records_read;
  store->stats_.bytes_on_disk = offset;
  store->stats_.live_movements = store->records_.size();
  store->next_sequence_ = sequence + 1U;

  if (report != nullptr) *report = local_report;

  log_message(LogLevel::INFO, "movement-store",
              "opened " + store->log_path_.string() + " with " +
                  std::to_string(store->records_.size()) + " movements" +
                  (local_report.partial_tail_truncated ? " (torn tail discarded)" : ""));
  return store;
}

Status MovementStore::apply_record(std::uint8_t type, ByteView payload) {
  CanonicalDecoder decoder(payload, DecodeLimits{options_.max_record_bytes, kMaxTextBytes,
                                                 options_.max_record_bytes + (1U << 16)});
  switch (type) {
    case kRecordMovement: {
      const auto record = MovementRecord::decode(decoder);
      if (!record.ok()) return record.status();
      SMF_RETURN_IF_ERROR(decoder.require_end());
      const MovementRecord& value = record.value();
      if (records_.find(value.id) == records_.end()) {
        order_.push_back(value.id);
        stats_.live_movements = 0;
      }
      records_.insert_or_assign(value.id, value);
      stats_.live_movements = records_.size();
      return Status::success();
    }
    case kRecordCoordinatorState: {
      const auto state = CoordinatorPersistentState::decode(decoder);
      if (!state.ok()) return state.status();
      SMF_RETURN_IF_ERROR(decoder.require_end());
      coordinator_state_ = state.value();
      return Status::success();
    }
    case kRecordRetire: {
      const auto raw = MovementId::decode(decoder);
      if (!raw.ok()) return raw.status();
      SMF_RETURN_IF_ERROR(decoder.require_end());
      const MovementId id = raw.value();
      if (records_.erase(id) > 0) {
        order_.erase(std::remove(order_.begin(), order_.end(), id), order_.end());
        stats_.retired_total += 1;
        stats_.live_movements = records_.size();
      }
      return Status::success();
    }
    default:
      return Status(ReasonCode::STORE_RECORD_INVALID, "store record type is not recognized");
  }
}

Status MovementStore::append_record(std::uint8_t type, const Bytes& payload) {
  auto* handle = static_cast<FileHandle*>(file_);
  if (handle == nullptr || !handle->is_open()) {
    return Status(ReasonCode::STORE_IO_ERROR, "store file is not open");
  }
  if (payload.size() > options_.max_record_bytes) {
    return Status(ReasonCode::STORE_OVERSIZED, "record payload exceeds the configured maximum");
  }

  Bytes header(kRecordHeaderBytes, Byte{0});
  std::memcpy(header.data(), kRecordMagic, sizeof(kRecordMagic));
  header[4] = kMovementStoreFormatVersion;
  header[5] = type;
  store_le(next_sequence_++, header.data() + 8, 8);
  store_le(payload.size(), header.data() + 16, 4);
  const Digest checksum = record_checksum(header.data(), smf::as_bytes(payload));
  std::memcpy(header.data() + 24, checksum.data(), Digest::kBytes);

  SMF_RETURN_IF_ERROR(handle->seek(append_offset_));
  SMF_RETURN_IF_ERROR(handle->write(smf::as_bytes(header)));
  SMF_RETURN_IF_ERROR(handle->write(smf::as_bytes(payload)));
  if (options_.sync_on_write) {
    SMF_RETURN_IF_ERROR(handle->sync());
  }
  append_offset_ += kRecordHeaderBytes + payload.size();
  log_bytes_ = append_offset_;
  stats_.records_appended += 1;
  stats_.bytes_written += kRecordHeaderBytes + payload.size();
  stats_.bytes_on_disk = append_offset_;
  return Status::success();
}

Status MovementStore::put(const MovementRecord& record) {
  const Status valid = record.validate();
  if (!valid.ok()) return valid;

  CanonicalEncoder encoder;
  record.encode(encoder);

  std::lock_guard<std::mutex> lock(mutex_);
  SMF_RETURN_IF_ERROR(append_record(kRecordMovement, encoder.bytes()));

  const bool is_new = records_.find(record.id) == records_.end();
  records_.insert_or_assign(record.id, record);
  if (is_new) order_.push_back(record.id);
  stats_.live_movements = records_.size();

  SMF_RETURN_IF_ERROR(enforce_retention());
  stats_.bytes_on_disk = append_offset_;
  return Status::success();
}

Status MovementStore::retire(const MovementId& id) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (records_.find(id) == records_.end()) {
    return Status(ReasonCode::MOVEMENT_NOT_FOUND, "movement is not present in the store");
  }
  CanonicalEncoder encoder;
  id.encode(encoder);
  SMF_RETURN_IF_ERROR(append_record(kRecordRetire, encoder.bytes()));
  records_.erase(id);
  order_.erase(std::remove(order_.begin(), order_.end(), id), order_.end());
  stats_.retired_total += 1;
  stats_.live_movements = records_.size();
  return Status::success();
}

Result<MovementRecord> MovementStore::get(const MovementId& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  stats_.index_lookup_steps += 1;
  const auto found = records_.find(id);
  if (found == records_.end()) {
    return Status(ReasonCode::MOVEMENT_NOT_FOUND, "movement is not present in the store");
  }
  return found->second;
}

bool MovementStore::contains(const MovementId& id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  stats_.index_lookup_steps += 1;
  return records_.find(id) != records_.end();
}

std::size_t MovementStore::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return records_.size();
}

Result<std::vector<MovementRecord>> MovementStore::list(std::uint32_t limit,
                                                        std::uint32_t offset) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<MovementRecord> out;
  if (offset >= order_.size()) return out;
  const std::size_t available = order_.size() - offset;
  const std::size_t take = std::min<std::size_t>(available, limit);
  out.reserve(take);
  // Newest first.
  for (std::size_t i = 0; i < take; ++i) {
    const MovementId& id = order_[order_.size() - 1U - offset - i];
    const auto found = records_.find(id);
    if (found != records_.end()) out.push_back(found->second);
  }
  return out;
}

Status MovementStore::sync() {
  std::lock_guard<std::mutex> lock(mutex_);
  auto* handle = static_cast<FileHandle*>(file_);
  if (handle == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "store file is not open");
  return handle->sync();
}

Status MovementStore::enforce_retention() {
  if (options_.retention_completed == 0) return Status::success();
  if (records_.size() <= options_.retention_completed) return Status::success();
  if (records_.size() <= options_.max_history_records) {
    // Still inside the record bound: nothing is retired until the completed
    // history bound is exceeded.
    return Status::success();
  }

  std::size_t to_retire = records_.size() - options_.retention_completed;
  std::vector<MovementId> victims;
  for (const MovementId& id : order_) {
    if (to_retire == 0) break;
    const auto found = records_.find(id);
    if (found == records_.end()) continue;
    if (!found->second.is_terminal()) continue;
    victims.push_back(id);
    --to_retire;
  }
  for (const MovementId& id : victims) {
    CanonicalEncoder encoder;
    id.encode(encoder);
    SMF_RETURN_IF_ERROR(append_record(kRecordRetire, encoder.bytes()));
    records_.erase(id);
    order_.erase(std::remove(order_.begin(), order_.end(), id), order_.end());
    stats_.retired_total += 1;
  }
  stats_.live_movements = records_.size();
  stats_.bytes_on_disk = append_offset_;
  return Status::success();
}

Status MovementStore::compact() {
  std::lock_guard<std::mutex> lock(mutex_);

  const std::filesystem::path temporary = log_path_.string() + ".compact";
  std::error_code error;
  std::filesystem::remove(temporary, error);

  FileHandle fresh;
  SMF_RETURN_IF_ERROR(fresh.open(temporary, true));

  Bytes header(kFileHeaderBytes, Byte{0});
  std::memcpy(header.data(), kFileMagic, sizeof(kFileMagic));
  store_le(kMovementStoreFormatVersion, header.data() + 8, 2);
  store_le(kFileHeaderBytes, header.data() + 12, 4);
  const Digest header_checksum = sha256(ByteView(header.data(), 64));
  std::memcpy(header.data() + 64, header_checksum.data(), Digest::kBytes);
  SMF_RETURN_IF_ERROR(fresh.write(smf::as_bytes(header)));

  std::uint64_t offset = kFileHeaderBytes;
  std::uint64_t sequence = 0;

  const auto write_record = [&](std::uint8_t type, const Bytes& payload) -> Status {
    Bytes record_header(kRecordHeaderBytes, Byte{0});
    std::memcpy(record_header.data(), kRecordMagic, sizeof(kRecordMagic));
    record_header[4] = kMovementStoreFormatVersion;
    record_header[5] = type;
    store_le(++sequence, record_header.data() + 8, 8);
    store_le(payload.size(), record_header.data() + 16, 4);
    const Digest checksum = record_checksum(record_header.data(), smf::as_bytes(payload));
    std::memcpy(record_header.data() + 24, checksum.data(), Digest::kBytes);
    SMF_RETURN_IF_ERROR(fresh.write(smf::as_bytes(record_header)));
    SMF_RETURN_IF_ERROR(fresh.write(smf::as_bytes(payload)));
    offset += kRecordHeaderBytes + payload.size();
    return Status::success();
  };

  for (const MovementId& id : order_) {
    const auto found = records_.find(id);
    if (found == records_.end()) continue;
    CanonicalEncoder encoder;
    found->second.encode(encoder);
    SMF_RETURN_IF_ERROR(write_record(kRecordMovement, encoder.bytes()));
  }
  if (coordinator_state_.has_value()) {
    CanonicalEncoder encoder;
    coordinator_state_->encode(encoder);
    SMF_RETURN_IF_ERROR(write_record(kRecordCoordinatorState, encoder.bytes()));
  }
  SMF_RETURN_IF_ERROR(fresh.sync());
  fresh.close();

  auto* current = static_cast<FileHandle*>(file_);
  if (current != nullptr) {
    current->close();
    delete current;
    file_ = nullptr;
  }

#if defined(_WIN32)
  if (!MoveFileExW(temporary.wstring().c_str(), log_path_.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::filesystem::remove(temporary, error);
    return Status(ReasonCode::STORE_IO_ERROR, "atomic store replacement failed");
  }
#else
  std::filesystem::rename(temporary, log_path_, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    return Status(ReasonCode::STORE_IO_ERROR, "atomic store replacement failed");
  }
#endif

  auto* reopened = new FileHandle();
  const Status opened = reopened->open(log_path_, true);
  if (!opened.ok()) {
    delete reopened;
    return opened;
  }
  const Status seeked = reopened->seek(offset);
  if (!seeked.ok()) {
    delete reopened;
    return seeked;
  }
  file_ = reopened;
  append_offset_ = offset;
  log_bytes_ = offset;
  stats_.compactions += 1;
  stats_.bytes_on_disk = offset;
  return Status::success();
}

Status MovementStore::save_coordinator_state(const CoordinatorPersistentState& state) {
  CanonicalEncoder encoder;
  state.encode(encoder);
  std::lock_guard<std::mutex> lock(mutex_);
  SMF_RETURN_IF_ERROR(append_record(kRecordCoordinatorState, encoder.bytes()));
  coordinator_state_ = state;
  return Status::success();
}

Result<CoordinatorPersistentState> MovementStore::load_coordinator_state() const {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!coordinator_state_.has_value()) {
    return Status(ReasonCode::NOT_FOUND, "no coordinator state has been persisted yet");
  }
  return *coordinator_state_;
}

MovementStoreStats MovementStore::stats() const {
  std::lock_guard<std::mutex> lock(mutex_);
  MovementStoreStats snapshot = stats_;
  snapshot.bytes_on_disk = append_offset_;
  snapshot.live_movements = records_.size();
  return snapshot;
}

std::uint64_t MovementStore::history_records() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return stats_.records_appended;
}

void MovementStore::close_file() {
  auto* handle = static_cast<FileHandle*>(file_);
  if (handle != nullptr) {
    delete handle;
    file_ = nullptr;
  }
}

}  // namespace smf
