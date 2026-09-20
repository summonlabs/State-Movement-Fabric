// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal file primitives shared by the durable stores. Not installed: it is
// an implementation detail of the library, not part of the public API.

#ifndef SMF_FILE_UTILS_HPP
#define SMF_FILE_UTILS_HPP

#include <cstdint>
#include <filesystem>
#include <string>

#include "smf/bytes.hpp"
#include "smf/status.hpp"

namespace smf {

// Buffered file handle with an explicit durability primitive.
class FileHandle {
 public:
  FileHandle() = default;
  ~FileHandle();
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;

  [[nodiscard]] Status open(const std::filesystem::path& path, bool for_write);
  void close();
  [[nodiscard]] bool is_open() const noexcept;

  [[nodiscard]] Status write(ByteView data);
  [[nodiscard]] Result<std::size_t> read(ByteSpan buffer);
  [[nodiscard]] Status sync();
  [[nodiscard]] Status seek(std::uint64_t offset);
  [[nodiscard]] Status truncate_at(std::uint64_t offset);
  [[nodiscard]] Result<std::uint64_t> size();

 private:
  void* file_ = nullptr;
};

// Exclusive advisory lock on a lock file, so that two processes cannot share one
// store directory.
class FileLock {
 public:
  FileLock() = default;
  ~FileLock();
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  [[nodiscard]] Status acquire(const std::filesystem::path& path);
  void release();

 private:
  void* handle_ = nullptr;
#if !defined(_WIN32)
  int descriptor_ = -1;
#endif
};

// Writes contents to a sibling temporary file, optionally flushes it to the
// platform, then renames it over the target. A crash at any point leaves either
// the previous contents or the new contents, never a mixture.
[[nodiscard]] Status atomic_replace_file(const std::filesystem::path& target, ByteView contents,
                                         bool sync_to_disk);

// Flushes an existing file's contents to the platform.
[[nodiscard]] Status sync_existing_file(const std::filesystem::path& path);

}  // namespace smf

#endif  // SMF_FILE_UTILS_HPP
