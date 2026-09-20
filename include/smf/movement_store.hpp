// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Durable storage for movement transactions.
//
// Format: a fixed file header followed by a sequence of checksummed records.
// Recovery rules, stated exhaustively:
//   * a record is applied only if it is completely present and its checksum
//     matches, so a partially written record is never applied;
//   * a trailing incomplete record is discarded and reported as
//     STORE_PARTIAL_TAIL, never silently;
//   * a checksum failure on any record that is not the final one, an unknown
//     magic, or an unsupported version is fatal: the store refuses to open
//     rather than partially applying a damaged file;
//   * an impossible record (bad payload, inconsistent accounting) is fatal.
//
// What is deliberately NOT durable: endpoint liveness, topology membership,
// transfer grants, and any in-flight attempt state. Those are dynamic facts
// that must be re-established by a live process after a restart.

#ifndef SMF_MOVEMENT_STORE_HPP
#define SMF_MOVEMENT_STORE_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "smf/ids.hpp"
#include "smf/movement.hpp"
#include "smf/status.hpp"

namespace smf {

struct CoordinatorPersistentState {
  IncarnationEpoch epoch;
  PolicyGeneration policy_generation;
  CompatibilityGeneration compatibility_generation;
  TopologyGeneration topology_generation;
  Digest policy_digest;
  Millis last_saved_unix_millis = 0;

  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CoordinatorPersistentState> decode(CanonicalDecoder& decoder);
};

struct MovementStoreOptions {
  std::filesystem::path directory;
  std::uint32_t max_record_bytes = 4U << 20;      // 4 MiB
  std::uint64_t max_store_bytes = 256ULL << 20;   // 256 MiB
  std::uint32_t max_history_records = 200000;
  std::uint32_t retention_completed = 10000;
  bool sync_on_write = true;
  bool exclusive_lock = true;
};

struct StoreRecoveryReport {
  bool created = false;
  bool partial_tail_truncated = false;
  std::uint64_t truncated_bytes = 0;
  std::uint64_t records_read = 0;
  std::uint64_t records_applied = 0;
  std::uint64_t movements_loaded = 0;
  std::uint64_t retired_loaded = 0;
};

struct MovementStoreStats {
  std::uint64_t records_appended = 0;
  std::uint64_t records_read = 0;
  std::uint64_t index_lookup_steps = 0;
  std::uint64_t compactions = 0;
  std::uint64_t retired_total = 0;
  std::uint64_t bytes_written = 0;
  std::uint64_t bytes_on_disk = 0;
  std::size_t live_movements = 0;
};

// Not copyable and not movable: the exclusive lock and the open file handle are
// owned for the process lifetime.
class MovementStore {
 public:
  ~MovementStore();
  MovementStore(const MovementStore&) = delete;
  MovementStore& operator=(const MovementStore&) = delete;
  MovementStore(MovementStore&&) = delete;
  MovementStore& operator=(MovementStore&&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<MovementStore>> open(
      const MovementStoreOptions& options, StoreRecoveryReport* report = nullptr);

  // Appends a durable snapshot of the record and updates the index. Returns
  // only after the record is durable when sync_on_write is enabled, so a caller
  // that reports success has already passed the durability point.
  [[nodiscard]] Status put(const MovementRecord& record);

  // Durable removal from the retained history.
  [[nodiscard]] Status retire(const MovementId& id);

  [[nodiscard]] Result<MovementRecord> get(const MovementId& id) const;
  [[nodiscard]] bool contains(const MovementId& id) const;
  [[nodiscard]] std::size_t size() const;

  // Newest first, bounded.
  [[nodiscard]] Result<std::vector<MovementRecord>> list(std::uint32_t limit,
                                                         std::uint32_t offset) const;

  [[nodiscard]] Status sync();

  // Rewrites the log with only live records. Uses write-to-temp, fsync, atomic
  // replace; a crash at any point leaves either the old or the new log intact.
  [[nodiscard]] Status compact();

  [[nodiscard]] Status save_coordinator_state(const CoordinatorPersistentState& state);
  [[nodiscard]] Result<CoordinatorPersistentState> load_coordinator_state() const;

  [[nodiscard]] MovementStoreStats stats() const;
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return log_path_; }
  [[nodiscard]] std::uint64_t history_records() const;

 private:
  MovementStore() = default;

  [[nodiscard]] Status append_record(std::uint8_t type, const Bytes& payload);
  [[nodiscard]] Status apply_record(std::uint8_t type, ByteView payload);
  [[nodiscard]] Status enforce_retention();
  void close_file();

  MovementStoreOptions options_;
  std::filesystem::path log_path_;
  std::filesystem::path lock_path_;
  void* file_ = nullptr;
  void* lock_handle_ = nullptr;
  std::uint64_t log_bytes_ = 0;
  std::uint64_t append_offset_ = 0;
  std::uint64_t next_sequence_ = 1;

  mutable std::mutex mutex_;
  std::unordered_map<MovementId, MovementRecord> records_;
  std::vector<MovementId> order_;  // oldest first
  std::optional<CoordinatorPersistentState> coordinator_state_;
  mutable MovementStoreStats stats_;
};

}  // namespace smf

#endif  // SMF_MOVEMENT_STORE_HPP
