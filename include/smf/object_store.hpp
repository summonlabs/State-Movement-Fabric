// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Destination-side placement of state objects.
//
// Layout under the store root:
//   staging/<movement-id>/data.part          bytes received so far
//   staging/<movement-id>/journal            verified prefix and per-chunk digests
//   objects/<object-id>/<generation>/data    verified bytes, promoted on success
//   commits/<object-id>/<generation>.marker  the atomic commit marker
//   quarantine/<movement-id>/...             residue that must not be reused
//
// Two properties matter more than anything else here:
//   * bytes in objects/ are never authority on their own. Authority requires a
//     commit marker whose binding verifies, and the marker is written with
//     write-temp + flush + atomic rename, so a partially written marker can
//     never be observed;
//   * a resumed transfer continues only over a verified prefix whose per-chunk
//     digests are journalled, and that prefix is re-read and re-hashed from disk
//     before any append continues.

#ifndef SMF_OBJECT_STORE_HPP
#define SMF_OBJECT_STORE_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "smf/chunk_plan.hpp"
#include "smf/codec.hpp"
#include "smf/digest.hpp"
#include "smf/ids.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"

namespace smf {

struct CommitMarker {
  MovementId movement_id;
  MovementGeneration movement_generation;
  StateObjectDescriptor object;
  EndpointId source;
  EndpointId destination;
  DestinationIncarnation destination_incarnation;
  Digest content_digest;
  std::uint64_t stored_bytes = 0;
  std::uint32_t stored_chunks = 0;
  Millis committed_unix_millis = 0;
  Digest marker_digest;

  [[nodiscard]] Status validate() const;
  [[nodiscard]] Digest compute_digest() const;
  // Fills in marker_digest from every other field. Callers seal before writing.
  void seal();
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<CommitMarker> decode(CanonicalDecoder& decoder);
};

// Answer to "may this state be reused at this destination right now".
//
// This is the object store's own view. The wire protocol has a separate
// AuthorityReport message; the endpoint agent maps between the two so that the
// storage layer does not depend on the transport layer.
struct ObjectAuthority {
  StateObjectId object_id;
  StateGeneration generation;
  MovementId movement_id;
  bool bytes_present = false;
  bool marker_present = false;
  bool marker_valid = false;
  // True only when the marker binding verifies and the stored byte count
  // matches it. It is never true merely because bytes exist.
  bool authoritative = false;
  Digest marker_digest;
  std::uint64_t stored_bytes = 0;
  ReasonCode code = ReasonCode::OBJECT_VERSION_NOT_FOUND;
  std::string detail;
};

// Journal of a partially received object.
struct StagingJournal {
  MovementId movement_id;
  MovementGeneration movement_generation;
  TransferAttemptId attempt;
  StateObjectDescriptor object;
  std::uint32_t verified_chunks = 0;
  std::uint64_t verified_bytes = 0;
  std::vector<Digest> chunk_digests;

  [[nodiscard]] Status validate() const;
  void encode(CanonicalEncoder& encoder) const;
  [[nodiscard]] static Result<StagingJournal> decode(CanonicalDecoder& decoder);
};

// Resumption is journalled per chunk; beyond this bound the journal would grow
// without limit, so resumption is simply not offered for such objects and the
// transfer starts clean instead.
inline constexpr std::uint32_t kMaxResumeJournalChunks = 65536;

struct ObjectStoreOptions {
  std::filesystem::path root;
  std::uint64_t max_object_bytes = 256ULL << 30;
  bool sync_on_write = true;
  bool allow_resume = true;
};

struct CleanupTarget {
  MovementId movement_id;
  StateObjectId object_id;
  StateGeneration generation;
  // Move residue aside instead of deleting it.
  bool quarantine = false;
  // Also remove the placed object bytes and the commit marker. The caller must
  // only set this when it has established that those bytes belong to this
  // movement and must not remain usable.
  bool remove_placed = false;
};

class ObjectStore {
 public:
  ~ObjectStore();
  ObjectStore(const ObjectStore&) = delete;
  ObjectStore& operator=(const ObjectStore&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<ObjectStore>> open(const ObjectStoreOptions& options);

  [[nodiscard]] const std::filesystem::path& root() const noexcept { return options_.root; }
  [[nodiscard]] const ObjectStoreOptions& options() const noexcept { return options_; }

  [[nodiscard]] std::filesystem::path staging_directory(const MovementId& id) const;
  [[nodiscard]] std::filesystem::path staging_data_path(const MovementId& id) const;
  [[nodiscard]] std::filesystem::path staging_journal_path(const MovementId& id) const;
  [[nodiscard]] std::filesystem::path object_directory(const StateObjectId& id,
                                                       StateGeneration generation) const;
  [[nodiscard]] std::filesystem::path object_data_path(const StateObjectId& id,
                                                       StateGeneration generation) const;
  [[nodiscard]] std::filesystem::path commit_marker_path(const StateObjectId& id,
                                                         StateGeneration generation) const;

  // --- staging ---
  [[nodiscard]] Result<StagingJournal> load_journal(const MovementId& id) const;
  [[nodiscard]] Status save_journal(const StagingJournal& journal) const;
  [[nodiscard]] Status discard_staging(const MovementId& id,
                                       std::uint64_t* bytes_removed = nullptr) const;
  [[nodiscard]] bool staging_present(const MovementId& id) const;
  [[nodiscard]] std::uint64_t staging_bytes(const MovementId& id) const;

  // Moves staged bytes into place. The caller is responsible for having
  // verified the content digest before calling.
  [[nodiscard]] Status promote_staging(const MovementId& id,
                                        const StateObjectDescriptor& object) const;

  // --- placed objects ---
  [[nodiscard]] bool object_present(const StateObjectId& id, StateGeneration generation) const;
  [[nodiscard]] Result<std::uint64_t> object_size(const StateObjectId& id,
                                                  StateGeneration generation) const;
  [[nodiscard]] Result<Bytes> read_range(const StateObjectId& id, StateGeneration generation,
                                         std::uint64_t offset, std::uint64_t length,
                                         std::uint64_t max_length) const;
  [[nodiscard]] Result<Digest> digest_object(const StateObjectId& id, StateGeneration generation,
                                             std::uint64_t* bytes_out = nullptr) const;

  // --- commit markers ---
  [[nodiscard]] Status write_commit_marker(const CommitMarker& marker);
  [[nodiscard]] Result<CommitMarker> read_commit_marker(const StateObjectId& id,
                                                        StateGeneration generation) const;
  [[nodiscard]] bool commit_marker_present(const StateObjectId& id,
                                           StateGeneration generation) const;

  // --- authority ---
  [[nodiscard]] Result<ObjectAuthority> authority(const StateObjectId& id,
                                                  StateGeneration generation) const;

  // --- cleanup ---
  [[nodiscard]] Status cleanup(const CleanupTarget& target, std::uint64_t* bytes_removed = nullptr,
                               std::uint32_t* entries_removed = nullptr);

 private:
  ObjectStore() = default;

  ObjectStoreOptions options_;
};

// One in-flight destination write. Owns the staging file for the duration of an
// attempt and refuses to write anything that is not the next expected chunk.
class StagingWriter {
 public:
  StagingWriter() = default;
  ~StagingWriter();
  StagingWriter(const StagingWriter&) = delete;
  StagingWriter& operator=(const StagingWriter&) = delete;
  StagingWriter(StagingWriter&& other) noexcept;
  StagingWriter& operator=(StagingWriter&& other) noexcept;

  // Continues a compatible staged prefix when one exists and resumption is
  // allowed, otherwise starts clean.
  [[nodiscard]] static Result<StagingWriter> begin(const ObjectStore& store,
                                                   const MovementId& movement_id,
                                                   MovementGeneration movement_generation,
                                                   TransferAttemptId attempt,
                                                   const StateObjectDescriptor& object);

  // Accepts the next chunk, or an exact duplicate of an already verified chunk.
  [[nodiscard]] Result<ResumeState> append(std::uint32_t index, std::uint64_t offset,
                                           ByteView payload, const Digest& chunk_digest);

  // Verifies completeness, flushes, and returns the running content digest of
  // the staged bytes. Nothing is promoted yet: promotion is a separate,
  // deliberate step that only happens once the digest has been checked against
  // the version the movement was authorized to move.
  [[nodiscard]] Result<Digest> finish();

  // Publishes the staged bytes as the object version in journal().object.
  [[nodiscard]] Status promote();

  // Releases the file without promoting anything.
  void abort() noexcept;

  [[nodiscard]] const StagingJournal& journal() const noexcept { return journal_; }
  [[nodiscard]] std::uint32_t resume_from_chunk() const noexcept { return journal_.verified_chunks; }
  [[nodiscard]] std::uint64_t resume_from_offset() const noexcept { return journal_.verified_bytes; }
  [[nodiscard]] bool finalized() const noexcept { return finalized_; }

 private:
  void close_file() noexcept;

  const ObjectStore* store_ = nullptr;
  void* file_ = nullptr;
  StagingJournal journal_;
  Sha256 running_;
  bool journaling_ = true;
  bool open_ = false;
  bool completed_ = false;
  bool finalized_ = false;
};

}  // namespace smf

#endif  // SMF_OBJECT_STORE_HPP
