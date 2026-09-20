// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/object_store.hpp"

#include <algorithm>
#include <system_error>

#include "file_utils.hpp"
#include "smf/fault_injection.hpp"
#include "smf/limits.hpp"
#include "smf/logging.hpp"

namespace smf {
namespace {

constexpr std::size_t kCopyBufferBytes = 256U << 10;

[[nodiscard]] std::string hex_of(ByteView value) { return to_hex(value); }

void accumulate(std::uint64_t& total, std::uint64_t add) { total += add; }

}  // namespace

// ---------------------------------------------------------------------------
// CommitMarker
// ---------------------------------------------------------------------------

Status CommitMarker::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker requires a movement id");
  }
  if (!movement_generation.is_set()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker requires a movement generation");
  }
  const Status object_status = object.validate();
  if (!object_status.ok()) return object_status;
  if (source.empty() || destination.empty()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker must name both endpoints");
  }
  if (source == destination) {
    return Status(ReasonCode::SELF_MOVEMENT, "commit marker names the same endpoint twice");
  }
  if (!destination_incarnation.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION, "commit marker requires a destination incarnation");
  }
  if (destination_incarnation.endpoint() != destination) {
    return Status(ReasonCode::STALE_INCARNATION,
                  "commit marker destination incarnation names a different endpoint");
  }
  if (content_digest.is_zero()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker requires a content digest");
  }
  if (content_digest != object.content_digest) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "commit marker content digest does not match the object descriptor");
  }
  if (stored_bytes != object.total_bytes) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "commit marker byte count does not match the object descriptor");
  }
  if (stored_chunks != object.chunk_count) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "commit marker chunk count does not match the object descriptor");
  }
  if (committed_unix_millis <= 0) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker requires a timestamp");
  }
  if (marker_digest.is_zero()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker is not sealed");
  }
  return Status::success();
}

Digest CommitMarker::compute_digest() const {
  CanonicalEncoder encoder("SMF-COMMIT-MARKER-v1");
  movement_id.encode(encoder);
  encoder.u64(movement_generation.value());
  object.encode(encoder);
  encoder.text(source.value());
  encoder.text(destination.value());
  encoder.text(destination_incarnation.endpoint().value());
  destination_incarnation.boot().encode(encoder);
  encoder.u64(destination_incarnation.epoch().value());
  encoder.digest(content_digest);
  encoder.u64(stored_bytes);
  encoder.u32(stored_chunks);
  encoder.i64(committed_unix_millis);
  return canonical_digest(encoder);
}

void CommitMarker::seal() { marker_digest = compute_digest(); }

void CommitMarker::encode(CanonicalEncoder& encoder) const {
  movement_id.encode(encoder);
  encoder.u64(movement_generation.value());
  object.encode(encoder);
  encoder.text(source.value());
  encoder.text(destination.value());
  encoder.text(destination_incarnation.endpoint().value());
  destination_incarnation.boot().encode(encoder);
  encoder.u64(destination_incarnation.epoch().value());
  encoder.digest(content_digest);
  encoder.u64(stored_bytes);
  encoder.u32(stored_chunks);
  encoder.i64(committed_unix_millis);
  encoder.digest(marker_digest);
}

Result<CommitMarker> CommitMarker::decode(CanonicalDecoder& decoder) {
  CommitMarker marker;

  const auto movement = MovementId::decode(decoder);
  if (!movement.ok()) return movement.status();
  marker.movement_id = movement.value();

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  marker.movement_generation = MovementGeneration(generation.value());

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  marker.object = object.value();

  const auto source = decoder.text(kMaxEndpointIdBytes);
  if (!source.ok()) return source.status();
  const auto source_id = EndpointId::parse(source.value());
  if (!source_id.ok()) return source_id.status();
  marker.source = source_id.value();

  const auto destination = decoder.text(kMaxEndpointIdBytes);
  if (!destination.ok()) return destination.status();
  const auto destination_id = EndpointId::parse(destination.value());
  if (!destination_id.ok()) return destination_id.status();
  marker.destination = destination_id.value();

  const auto destination_endpoint = decoder.text(kMaxEndpointIdBytes);
  if (!destination_endpoint.ok()) return destination_endpoint.status();
  const auto boot = BootId::decode(decoder);
  if (!boot.ok()) return boot.status();
  const auto epoch = decoder.u64();
  if (!epoch.ok()) return epoch.status();
  const auto parsed_endpoint = EndpointId::parse(destination_endpoint.value());
  if (!parsed_endpoint.ok()) return parsed_endpoint.status();
  const auto incarnation = DestinationIncarnation::make(parsed_endpoint.value(), boot.value(),
                                                        IncarnationEpoch(epoch.value()));
  if (!incarnation.ok()) return incarnation.status();
  marker.destination_incarnation = incarnation.value();

  const auto content = decoder.digest();
  if (!content.ok()) return content.status();
  marker.content_digest = content.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  marker.stored_bytes = bytes.value();

  const auto chunks = decoder.u32();
  if (!chunks.ok()) return chunks.status();
  marker.stored_chunks = chunks.value();

  const auto committed = decoder.i64();
  if (!committed.ok()) return committed.status();
  marker.committed_unix_millis = committed.value();

  const auto digest = decoder.digest();
  if (!digest.ok()) return digest.status();
  marker.marker_digest = digest.value();

  const Status status = marker.validate();
  if (!status.ok()) return status;
  return marker;
}

// ---------------------------------------------------------------------------
// StagingJournal
// ---------------------------------------------------------------------------

Status StagingJournal::validate() const {
  if (movement_id.is_zero()) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "staging journal requires a movement id");
  }
  if (!movement_generation.is_set()) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "staging journal requires a generation");
  }
  const Status object_status = object.validate();
  if (!object_status.ok()) return object_status;
  if (verified_chunks > object.chunk_count) {
    return Status(ReasonCode::STORE_RECORD_INVALID, "staging journal claims more chunks than exist");
  }
  if (chunk_digests.size() != verified_chunks) {
    return Status(ReasonCode::STORE_RECORD_INVALID,
                  "staging journal chunk digest count does not match the verified prefix");
  }
  std::uint64_t expected_bytes = 0;
  for (std::uint32_t index = 0; index < verified_chunks; ++index) {
    const auto length = object.chunk_length(index);
    if (!length.ok()) return length.status();
    std::uint64_t next = 0;
    if (!checked_add(expected_bytes, length.value(), next)) {
      return Status(ReasonCode::SIZE_OVERFLOW, "staging journal byte accounting overflowed");
    }
    expected_bytes = next;
  }
  if (expected_bytes != verified_bytes) {
    return Status(ReasonCode::STORE_RECORD_INVALID,
                  "staging journal byte count is inconsistent with its verified prefix");
  }
  return Status::success();
}

void StagingJournal::encode(CanonicalEncoder& encoder) const {
  movement_id.encode(encoder);
  encoder.u64(movement_generation.value());
  attempt.encode(encoder);
  object.encode(encoder);
  encoder.u32(verified_chunks);
  encoder.u64(verified_bytes);
  encoder.u32(static_cast<std::uint32_t>(chunk_digests.size()));
  for (const Digest& digest : chunk_digests) {
    encoder.digest(digest);
  }
}

Result<StagingJournal> StagingJournal::decode(CanonicalDecoder& decoder) {
  StagingJournal journal;

  const auto movement = MovementId::decode(decoder);
  if (!movement.ok()) return movement.status();
  journal.movement_id = movement.value();

  const auto generation = decoder.u64();
  if (!generation.ok()) return generation.status();
  journal.movement_generation = MovementGeneration(generation.value());

  const auto attempt = TransferAttemptId::decode(decoder);
  if (!attempt.ok()) return attempt.status();
  journal.attempt = attempt.value();

  const auto object = StateObjectDescriptor::decode(decoder);
  if (!object.ok()) return object.status();
  journal.object = object.value();

  const auto chunks = decoder.u32();
  if (!chunks.ok()) return chunks.status();
  journal.verified_chunks = chunks.value();

  const auto bytes = decoder.u64();
  if (!bytes.ok()) return bytes.status();
  journal.verified_bytes = bytes.value();

  const auto count = decoder.count(kMaxResumeJournalChunks);
  if (!count.ok()) return count.status();
  journal.chunk_digests.reserve(count.value());
  for (std::size_t i = 0; i < count.value(); ++i) {
    const auto digest = decoder.digest();
    if (!digest.ok()) return digest.status();
    journal.chunk_digests.push_back(digest.value());
  }

  const Status status = journal.validate();
  if (!status.ok()) return status;
  return journal;
}

// ---------------------------------------------------------------------------
// ObjectStore
// ---------------------------------------------------------------------------

ObjectStore::~ObjectStore() = default;

Result<std::unique_ptr<ObjectStore>> ObjectStore::open(const ObjectStoreOptions& options) {
  if (options.root.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "object store root must not be empty");
  }
  if (options.max_object_bytes == 0 || options.max_object_bytes > kMaxObjectBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "max_object_bytes is outside the supported range");
  }

  auto store = std::unique_ptr<ObjectStore>(new ObjectStore());
  store->options_ = options;

  std::error_code error;
  std::filesystem::create_directories(options.root / "staging", error);
  std::filesystem::create_directories(options.root / "objects", error);
  std::filesystem::create_directories(options.root / "commits", error);
  std::filesystem::create_directories(options.root / "quarantine", error);
  if (error) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not create the object store layout");
  }
  return store;
}

std::filesystem::path ObjectStore::staging_directory(const MovementId& id) const {
  return options_.root / "staging" / id.hex();
}

std::filesystem::path ObjectStore::staging_data_path(const MovementId& id) const {
  return staging_directory(id) / "data.part";
}

std::filesystem::path ObjectStore::staging_journal_path(const MovementId& id) const {
  return staging_directory(id) / "journal";
}

std::filesystem::path ObjectStore::object_directory(const StateObjectId& id,
                                                    StateGeneration generation) const {
  return options_.root / "objects" / id.hex() / std::to_string(generation.value());
}

std::filesystem::path ObjectStore::object_data_path(const StateObjectId& id,
                                                    StateGeneration generation) const {
  return object_directory(id, generation) / "data";
}

std::filesystem::path ObjectStore::commit_marker_path(const StateObjectId& id,
                                                      StateGeneration generation) const {
  return options_.root / "commits" / id.hex() / (std::to_string(generation.value()) + ".marker");
}

Result<StagingJournal> ObjectStore::load_journal(const MovementId& id) const {
  const std::filesystem::path path = staging_journal_path(id);
  std::error_code error;
  if (!std::filesystem::exists(path, error)) {
    return Status(ReasonCode::NOT_FOUND, "no staging journal exists for that movement");
  }
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(path, false));
  const auto size = handle.size();
  if (!size.ok()) return size.status();
  if (size.value() == 0 || size.value() > (4U << 20)) {
    return Status(ReasonCode::STORE_OVERSIZED, "staging journal has an implausible size");
  }
  Bytes buffer(static_cast<std::size_t>(size.value()));
  const auto read = handle.read(ByteSpan(buffer.data(), buffer.size()));
  if (!read.ok()) return read.status();
  if (read.value() != buffer.size()) {
    return Status(ReasonCode::STORE_TRUNCATED, "staging journal is truncated");
  }
  handle.close();

  CanonicalDecoder decoder(smf::as_bytes(buffer));
  const auto domain = decoder.text(kMaxTextBytes);
  if (!domain.ok()) return domain.status();
  if (domain.value() != "SMF-STAGING-JOURNAL-v1") {
    return Status(ReasonCode::STORE_CORRUPT, "staging journal domain does not match");
  }
  const auto journal = StagingJournal::decode(decoder);
  if (!journal.ok()) return journal.status();
  SMF_RETURN_IF_ERROR(decoder.require_end());
  if (journal.value().movement_id != id) {
    return Status(ReasonCode::STORE_RECORD_INVALID,
                  "staging journal belongs to a different movement");
  }
  return journal;
}

Status ObjectStore::save_journal(const StagingJournal& journal) const {
  const Status valid = journal.validate();
  if (!valid.ok()) return valid;

  CanonicalEncoder encoder("SMF-STAGING-JOURNAL-v1");
  journal.encode(encoder);

  std::error_code error;
  std::filesystem::create_directories(staging_directory(journal.movement_id), error);
  if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not create the staging directory");
  return atomic_replace_file(staging_journal_path(journal.movement_id), encoder.view(),
                             options_.sync_on_write);
}

bool ObjectStore::staging_present(const MovementId& id) const {
  std::error_code error;
  return std::filesystem::exists(staging_data_path(id), error);
}

std::uint64_t ObjectStore::staging_bytes(const MovementId& id) const {
  std::error_code error;
  const auto size = std::filesystem::file_size(staging_data_path(id), error);
  if (error) return 0;
  return static_cast<std::uint64_t>(size);
}

Status ObjectStore::discard_staging(const MovementId& id, std::uint64_t* bytes_removed) const {
  std::error_code error;
  if (bytes_removed != nullptr) {
    *bytes_removed = staging_bytes(id) + [&]() -> std::uint64_t {
      const auto size = std::filesystem::file_size(staging_journal_path(id), error);
      return error ? 0U : static_cast<std::uint64_t>(size);
    }();
  }
  std::filesystem::remove_all(staging_directory(id), error);
  if (error) {
    return Status(ReasonCode::CLEANUP_FAILED, "could not remove the staging directory");
  }
  return Status::success();
}

Status ObjectStore::promote_staging(const MovementId& id,
                                     const StateObjectDescriptor& object) const {
  const std::filesystem::path source = staging_data_path(id);
  std::error_code error;
  if (!std::filesystem::exists(source, error)) {
    return Status(ReasonCode::OBJECT_NOT_FOUND, "no staged bytes exist to promote");
  }

  const std::filesystem::path directory = object_directory(object.object_id, object.generation);
  std::filesystem::create_directories(directory, error);
  if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not create the object directory");

  const std::filesystem::path target = object_data_path(object.object_id, object.generation);
  // A previous promotion of the same version would have produced identical
  // bytes, so replacing it is safe and idempotent.
  if (std::filesystem::exists(target, error)) {
    std::filesystem::remove(target, error);
    if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not clear the previous object data");
  }

  std::filesystem::rename(source, target, error);
  if (error) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not promote the staged bytes");
  }
  if (options_.sync_on_write) {
    SMF_RETURN_IF_ERROR(sync_existing_file(target));
  }
  // The staging directory still holds the journal, so it is removed
  // recursively rather than with a single-file remove that would fail.
  std::filesystem::remove_all(staging_directory(id), error);
  return Status::success();
}

bool ObjectStore::object_present(const StateObjectId& id, StateGeneration generation) const {
  std::error_code error;
  return std::filesystem::exists(object_data_path(id, generation), error);
}

Result<std::uint64_t> ObjectStore::object_size(const StateObjectId& id,
                                               StateGeneration generation) const {
  std::error_code error;
  const auto size = std::filesystem::file_size(object_data_path(id, generation), error);
  if (error) {
    return Status(ReasonCode::OBJECT_VERSION_NOT_FOUND, "no bytes are placed for that version");
  }
  return static_cast<std::uint64_t>(size);
}

Result<Bytes> ObjectStore::read_range(const StateObjectId& id, StateGeneration generation,
                                      std::uint64_t offset, std::uint64_t length,
                                      std::uint64_t max_length) const {
  if (length > max_length) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "requested range exceeds the permitted bound");
  }
  const std::filesystem::path path = object_data_path(id, generation);
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(path, false));
  const auto size = handle.size();
  if (!size.ok()) return size.status();

  std::uint64_t end = 0;
  if (!checked_add(offset, length, end) || end > size.value()) {
    return Status(ReasonCode::CHUNK_INDEX_OUT_OF_RANGE, "requested range lies outside the object");
  }
  SMF_RETURN_IF_ERROR(handle.seek(offset));
  Bytes buffer(static_cast<std::size_t>(length));
  if (!buffer.empty()) {
    const auto read = handle.read(ByteSpan(buffer.data(), buffer.size()));
    if (!read.ok()) return read.status();
    if (read.value() != buffer.size()) {
      return Status(ReasonCode::STORE_TRUNCATED, "object bytes ended inside the requested range");
    }
  }
  return buffer;
}

Result<Digest> ObjectStore::digest_object(const StateObjectId& id, StateGeneration generation,
                                          std::uint64_t* bytes_out) const {
  const std::filesystem::path path = object_data_path(id, generation);
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(path, false));

  Sha256 hasher;
  Bytes buffer(kCopyBufferBytes);
  std::uint64_t total = 0;
  for (;;) {
    const auto read = handle.read(ByteSpan(buffer.data(), buffer.size()));
    if (!read.ok()) return read.status();
    if (read.value() == 0) break;
    hasher.update(ByteView(buffer.data(), read.value()));
    total += read.value();
    if (read.value() < buffer.size()) break;
  }
  if (bytes_out != nullptr) *bytes_out = total;
  return hasher.finalize();
}

Status ObjectStore::write_commit_marker(const CommitMarker& marker) {
  CommitMarker sealed = marker;
  if (sealed.marker_digest.is_zero()) sealed.seal();
  if (sealed.marker_digest != sealed.compute_digest()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker digest does not match its fields");
  }
  const Status valid = sealed.validate();
  if (!valid.ok()) return valid;

  const std::filesystem::path path =
      commit_marker_path(sealed.object.object_id, sealed.object.generation);

  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    FileHandle existing;
    if (existing.open(path, false).ok()) {
      const auto size = existing.size();
      if (size.ok() && size.value() > 0 && size.value() <= (1U << 20)) {
        Bytes buffer(static_cast<std::size_t>(size.value()));
        const auto read = existing.read(ByteSpan(buffer.data(), buffer.size()));
        existing.close();
        if (read.ok() && read.value() == buffer.size()) {
          CanonicalDecoder decoder(smf::as_bytes(buffer));
          const auto domain = decoder.text(kMaxTextBytes);
          if (domain.ok() && domain.value() == "SMF-COMMIT-MARKER-v1") {
            const auto decoded = CommitMarker::decode(decoder);
            if (decoded.ok()) {
              if (decoded.value().marker_digest == sealed.marker_digest) {
                return Status::success();  // idempotent repeat of the same commit
              }
              return Status(ReasonCode::COMMIT_ALREADY_EXISTS,
                            "a different commit marker already exists for this object version");
            }
          }
        }
      }
    }
  }

  CanonicalEncoder encoder("SMF-COMMIT-MARKER-v1");
  sealed.encode(encoder);

  std::filesystem::create_directories(path.parent_path(), error);
  if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not create the commit directory");
  return atomic_replace_file(path, encoder.view(), options_.sync_on_write);
}

Result<CommitMarker> ObjectStore::read_commit_marker(const StateObjectId& id,
                                                     StateGeneration generation) const {
  const std::filesystem::path path = commit_marker_path(id, generation);
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(path, false));
  const auto size = handle.size();
  if (!size.ok()) return size.status();
  if (size.value() == 0 || size.value() > (1U << 20)) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker has an implausible size");
  }
  Bytes buffer(static_cast<std::size_t>(size.value()));
  const auto read = handle.read(ByteSpan(buffer.data(), buffer.size()));
  if (!read.ok()) return read.status();
  if (read.value() != buffer.size()) {
    return Status(ReasonCode::STORE_TRUNCATED, "commit marker is truncated");
  }
  handle.close();

  CanonicalDecoder decoder(smf::as_bytes(buffer));
  const auto domain = decoder.text(kMaxTextBytes);
  if (!domain.ok()) return domain.status();
  if (domain.value() != "SMF-COMMIT-MARKER-v1") {
    return Status(ReasonCode::COMMIT_MARKER_INVALID, "commit marker domain does not match");
  }
  const auto marker = CommitMarker::decode(decoder);
  if (!marker.ok()) return marker.status();
  SMF_RETURN_IF_ERROR(decoder.require_end());

  if (marker.value().marker_digest != marker.value().compute_digest()) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "commit marker digest does not match its own fields");
  }
  if (marker.value().object.object_id != id || marker.value().object.generation != generation) {
    return Status(ReasonCode::COMMIT_MARKER_INVALID,
                  "commit marker is filed under the wrong object version");
  }
  return marker;
}

bool ObjectStore::commit_marker_present(const StateObjectId& id, StateGeneration generation) const {
  std::error_code error;
  return std::filesystem::exists(commit_marker_path(id, generation), error);
}

Result<ObjectAuthority> ObjectStore::authority(const StateObjectId& id,
                                                StateGeneration generation) const {
  ObjectAuthority report;
  report.object_id = id;
  report.generation = generation;
  report.bytes_present = object_present(id, generation);

  const auto marker = read_commit_marker(id, generation);
  if (!marker.ok()) {
    report.marker_present = commit_marker_present(id, generation);
    report.marker_valid = false;
    report.authoritative = false;
    report.code = report.marker_present ? marker.status().code() : ReasonCode::OBJECT_VERSION_NOT_FOUND;
    report.detail = report.marker_present
                        ? marker.status().to_string()
                        : "no commit marker exists for this object version, so any bytes present "
                          "there are staged residue and not reusable authority";
    return report;
  }

  report.marker_present = true;
  report.marker_valid = true;
  report.movement_id = marker.value().movement_id;
  report.marker_digest = marker.value().marker_digest;

  const auto size = object_size(id, generation);
  report.stored_bytes = size.ok() ? size.value() : 0;

  if (!report.bytes_present) {
    report.code = ReasonCode::OBJECT_NOT_FOUND;
    report.detail = "a commit marker exists but the object bytes are missing";
    return report;
  }
  if (report.stored_bytes != marker.value().stored_bytes) {
    report.code = ReasonCode::BYTE_COUNT_MISMATCH;
    report.detail = "stored byte count does not match the commit marker";
    return report;
  }

  report.authoritative = true;
  report.code = ReasonCode::OK;
  report.detail = "commit marker verified and stored byte count matches";
  return report;
}

Status ObjectStore::cleanup(const CleanupTarget& target, std::uint64_t* bytes_removed,
                            std::uint32_t* entries_removed) {
  std::uint64_t removed_bytes = 0;
  std::uint32_t removed_entries = 0;
  std::error_code error;

  const std::uint64_t staged = staging_bytes(target.movement_id);
  if (target.quarantine) {
    const std::filesystem::path quarantine =
        options_.root / "quarantine" / target.movement_id.hex();
    if (std::filesystem::exists(staging_directory(target.movement_id), error)) {
      std::filesystem::create_directories(quarantine, error);
      if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not create the quarantine area");
      std::filesystem::rename(staging_directory(target.movement_id), quarantine / "staging", error);
      if (error) {
        return Status(ReasonCode::CLEANUP_FAILED, "could not quarantine the staged bytes");
      }
      removed_bytes += staged;
      removed_entries += 1;
    }
  } else if (std::filesystem::exists(staging_directory(target.movement_id), error)) {
    std::filesystem::remove_all(staging_directory(target.movement_id), error);
    if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not remove the staged bytes");
    removed_bytes += staged;
    removed_entries += 1;
  }

  if (target.remove_placed) {
    const std::filesystem::path directory = object_directory(target.object_id, target.generation);
    const auto size = object_size(target.object_id, target.generation);
    const bool marker = commit_marker_present(target.object_id, target.generation);

    if (target.quarantine) {
      const std::filesystem::path quarantine =
          options_.root / "quarantine" / target.movement_id.hex();
      std::filesystem::create_directories(quarantine, error);
      if (std::filesystem::exists(directory, error)) {
        std::filesystem::rename(directory, quarantine / "objects", error);
        if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not quarantine the object bytes");
        removed_bytes += size.ok() ? size.value() : 0;
        removed_entries += 1;
      }
      const std::filesystem::path marker_path =
          commit_marker_path(target.object_id, target.generation);
      if (marker && std::filesystem::exists(marker_path, error)) {
        std::filesystem::rename(marker_path, quarantine / "marker", error);
        if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not quarantine the commit marker");
        removed_entries += 1;
      }
    } else {
      if (std::filesystem::exists(directory, error)) {
        std::filesystem::remove_all(directory, error);
        if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not remove the object bytes");
        removed_bytes += size.ok() ? size.value() : 0;
        removed_entries += 1;
      }
      if (marker) {
        std::filesystem::remove(commit_marker_path(target.object_id, target.generation), error);
        if (error) return Status(ReasonCode::CLEANUP_FAILED, "could not remove the commit marker");
        removed_entries += 1;
      }
    }
  }

  if (bytes_removed != nullptr) *bytes_removed = removed_bytes;
  if (entries_removed != nullptr) *entries_removed = removed_entries;
  log_message(LogLevel::DEBUG, "object-store",
              "cleaned movement " + target.movement_id.hex().substr(0, 12) + " removed " +
                  std::to_string(removed_bytes) + " bytes");
  return Status::success();
}

// ---------------------------------------------------------------------------
// StagingWriter
// ---------------------------------------------------------------------------

StagingWriter::~StagingWriter() {
  close_file();
}

StagingWriter::StagingWriter(StagingWriter&& other) noexcept { *this = std::move(other); }

StagingWriter& StagingWriter::operator=(StagingWriter&& other) noexcept {
  if (this != &other) {
    close_file();
    store_ = other.store_;
    file_ = other.file_;
    journal_ = std::move(other.journal_);
    running_ = other.running_;
    journaling_ = other.journaling_;
    open_ = other.open_;
    completed_ = other.completed_;
    finalized_ = other.finalized_;
    other.store_ = nullptr;
    other.file_ = nullptr;
    other.open_ = false;
    other.completed_ = false;
    other.finalized_ = false;
  }
  return *this;
}

void StagingWriter::close_file() noexcept {
  if (file_ != nullptr) {
    delete static_cast<FileHandle*>(file_);
    file_ = nullptr;
  }
  open_ = false;
}

Result<StagingWriter> StagingWriter::begin(const ObjectStore& store, const MovementId& movement_id,
                                           MovementGeneration movement_generation,
                                           TransferAttemptId attempt,
                                           const StateObjectDescriptor& object) {
  const Status object_status = object.validate();
  if (!object_status.ok()) return object_status;

  StagingWriter writer;
  writer.store_ = &store;
  writer.journaling_ =
      store.options().allow_resume && object.chunk_count <= kMaxResumeJournalChunks;

  std::error_code error;
  std::filesystem::create_directories(store.staging_directory(movement_id), error);
  if (error) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not create the staging directory");
  }

  bool resumed = false;
  if (writer.journaling_) {
    const auto stored = store.load_journal(movement_id);
    if (stored.ok()) {
      const Status compatible = check_resume_compatible(object, stored.value().object);
      if (compatible.ok()) {
        writer.journal_ = stored.value();
        if (writer.journal_.verified_chunks > 0) {
          resumed = true;
        }
      }
    }
  }

  if (!resumed) {
    SMF_RETURN_IF_ERROR(store.discard_staging(movement_id));
    std::filesystem::create_directories(store.staging_directory(movement_id), error);
    writer.journal_ = StagingJournal{};
    writer.journal_.movement_id = movement_id;
    writer.journal_.movement_generation = movement_generation;
    writer.journal_.attempt = attempt;
    writer.journal_.object = object;
  } else {
    writer.journal_.movement_generation = movement_generation;
    writer.journal_.attempt = attempt;
  }

  auto* handle = new FileHandle();
  // The staging file is created on the first attempt and reused on a resume.
  const Status opened = handle->open(store.staging_data_path(movement_id), true);
  if (!opened.ok()) {
    delete handle;
    return opened;
  }
  writer.file_ = handle;
  writer.open_ = true;

  if (resumed) {
    // Re-read the verified prefix from disk and re-hash it. A journal that
    // claims more progress than the bytes support is discarded rather than
    // trusted.
    const std::uint64_t prefix_bytes = writer.journal_.verified_bytes;
    const auto size = handle->size();
    if (!size.ok() || size.value() < prefix_bytes) {
      return Status(ReasonCode::RESUME_INCOMPATIBLE,
                    "the staged file is shorter than the journal claims");
    }

    SMF_RETURN_IF_ERROR(handle->seek(0));
    std::uint64_t offset = 0;
    for (std::uint32_t index = 0; index < writer.journal_.verified_chunks; ++index) {
      const auto length = object.chunk_length(index);
      if (!length.ok()) return length.status();
      Bytes buffer(static_cast<std::size_t>(length.value()));
      if (!buffer.empty()) {
        const auto read = handle->read(ByteSpan(buffer.data(), buffer.size()));
        if (!read.ok()) return read.status();
        if (read.value() != buffer.size()) {
          return Status(ReasonCode::RESUME_INCOMPATIBLE,
                        "the staged file ended inside the verified prefix");
        }
      }
      const Digest recomputed = compute_chunk_digest(object.object_id, object.generation, index,
                                                     offset, length.value(), smf::as_bytes(buffer));
      if (recomputed != writer.journal_.chunk_digests[index]) {
        return Status(ReasonCode::RESUME_INCOMPATIBLE,
                      "the staged bytes do not match the journalled chunk digest");
      }
      writer.running_.update(smf::as_bytes(buffer));
      offset += length.value();
    }
    log_message(LogLevel::INFO, "object-store",
                "resuming " + movement_id.hex().substr(0, 12) + " at chunk " +
                    std::to_string(writer.journal_.verified_chunks));
  } else {
    SMF_RETURN_IF_ERROR(handle->truncate_at(0));
    if (writer.journaling_) {
      SMF_RETURN_IF_ERROR(store.save_journal(writer.journal_));
    }
  }

  return writer;
}

Result<ResumeState> StagingWriter::append(std::uint32_t index, std::uint64_t offset,
                                          ByteView payload, const Digest& chunk_digest) {
  if (!open_ || file_ == nullptr) {
    return Status(ReasonCode::INTERNAL_ERROR, "staging writer is not open");
  }
  if (finalized_) {
    return Status(ReasonCode::ALREADY_TERMINAL, "staging writer already finished");
  }

  const StateObjectDescriptor& object = journal_.object;
  if (index >= object.chunk_count) {
    return Status(ReasonCode::CHUNK_INDEX_OUT_OF_RANGE, "chunk index is outside the object");
  }
  const auto expected_offset = object.chunk_offset(index);
  if (!expected_offset.ok()) return expected_offset.status();
  if (offset != expected_offset.value()) {
    return Status(ReasonCode::CHUNK_OUT_OF_ORDER,
                  "chunk offset does not match the planned segmentation");
  }
  const auto expected_length = object.chunk_length(index);
  if (!expected_length.ok()) return expected_length.status();
  if (payload.size() != expected_length.value()) {
    return Status(ReasonCode::BYTE_COUNT_MISMATCH,
                  "chunk payload length does not match the planned chunk length");
  }

  const Digest expected = compute_chunk_digest(object.object_id, object.generation, index, offset,
                                               expected_length.value(), payload);
  if (expected != chunk_digest) {
    return Status(ReasonCode::CHUNK_DIGEST_MISMATCH,
                  "the received chunk does not hash to the digest it carries");
  }

  ResumeState state;
  state.descriptor = object;
  state.verified_chunks = journal_.verified_chunks;
  state.verified_bytes = journal_.verified_bytes;

  if (index < journal_.verified_chunks) {
    // A duplicate of an already verified chunk. It is accepted only when it is
    // byte-for-byte the same chunk; anything else is a conflict, not a retry.
    if (journaling_ && journal_.chunk_digests[index] != chunk_digest) {
      return Status(ReasonCode::CHUNK_CONFLICT,
                    "a replayed chunk does not match the digest already recorded for its index");
    }
    auto* handle = static_cast<FileHandle*>(file_);
    Bytes buffer(static_cast<std::size_t>(expected_length.value()));
    SMF_RETURN_IF_ERROR(handle->seek(offset));
    const auto read = handle->read(ByteSpan(buffer.data(), buffer.size()));
    if (!read.ok()) return read.status();
    if (read.value() != buffer.size()) {
      return Status(ReasonCode::CHUNK_CONFLICT, "stored bytes ended inside the replayed chunk");
    }
    const Digest stored = compute_chunk_digest(object.object_id, object.generation, index, offset,
                                               expected_length.value(), smf::as_bytes(buffer));
    if (stored != chunk_digest) {
      return Status(ReasonCode::CHUNK_CONFLICT,
                    "a replayed chunk does not match the bytes already stored for its index");
    }
    return state;
  }

  if (index != journal_.verified_chunks) {
    return Status(ReasonCode::CHUNK_OUT_OF_ORDER,
                  "chunks must arrive in order; this one skips ahead");
  }

  auto* handle = static_cast<FileHandle*>(file_);
  SMF_RETURN_IF_ERROR(handle->seek(offset));
  SMF_RETURN_IF_ERROR(handle->write(payload));
  if (store_->options().sync_on_write) {
    SMF_RETURN_IF_ERROR(handle->sync());
  }

  running_.update(payload);
  if (journaling_) {
    journal_.chunk_digests.push_back(chunk_digest);
  }
  journal_.verified_chunks += 1;
  accumulate(journal_.verified_bytes, expected_length.value());

  // The journal is written after every accepted chunk, independently of whether
  // the store is configured to flush to the device. Durability is what
  // sync_on_write governs; the journal is what makes an interrupted attempt
  // resumable at all, and a retry within the same process must not have to
  // re-transfer a prefix that was already verified.
  if (journaling_) {
    SMF_RETURN_IF_ERROR(store_->save_journal(journal_));
  }

  fault_point(fault_points::kDestinationAfterChunkWrite);

  state.verified_chunks = journal_.verified_chunks;
  state.verified_bytes = journal_.verified_bytes;
  return state;
}

Result<Digest> StagingWriter::finish() {
  if (!open_ || file_ == nullptr) {
    return Status(ReasonCode::INTERNAL_ERROR, "staging writer is not open");
  }
  if (journal_.verified_chunks != journal_.object.chunk_count ||
      journal_.verified_bytes != journal_.object.total_bytes) {
    return Status(ReasonCode::TRANSFER_INCOMPLETE,
                  "the staged bytes do not cover the whole object");
  }

  const Digest content = running_.finalize();
  auto* handle = static_cast<FileHandle*>(file_);
  SMF_RETURN_IF_ERROR(handle->sync());
  handle->close();
  close_file();
  completed_ = true;
  return content;
}

Status StagingWriter::promote() {
  if (!completed_) {
    return Status(ReasonCode::TRANSFER_INCOMPLETE,
                  "the staged transfer is not complete, so there is nothing to promote");
  }
  SMF_RETURN_IF_ERROR(store_->promote_staging(journal_.movement_id, journal_.object));
  finalized_ = true;
  return Status::success();
}

void StagingWriter::abort() noexcept { close_file(); }

}  // namespace smf
