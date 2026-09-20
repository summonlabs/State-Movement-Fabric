// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "file_utils.hpp"

#include <cstdio>
#include <system_error>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace smf {

FileHandle::~FileHandle() { close(); }

Status FileHandle::open(const std::filesystem::path& path, bool for_write) {
  close();
  // Read-only callers never need write permission, and update callers must not
  // destroy an existing file: the update mode opens what is there and only
  // creates a file when none exists.
#if defined(_WIN32)
  FILE* handle = nullptr;
  errno_t error = _wfopen_s(&handle, path.wstring().c_str(), for_write ? L"r+b" : L"rb");
  if (for_write && (error != 0 || handle == nullptr)) {
    error = _wfopen_s(&handle, path.wstring().c_str(), L"w+b");
  }
  if (error != 0 || handle == nullptr) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not open " + path.string());
  }
  file_ = handle;
#else
  file_ = std::fopen(path.string().c_str(), for_write ? "r+b" : "rb");
  if (file_ == nullptr && for_write) {
    file_ = std::fopen(path.string().c_str(), "w+b");
  }
  if (file_ == nullptr) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not open " + path.string());
  }
#endif
  return Status::success();
}

void FileHandle::close() {
  if (file_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(file_));
    file_ = nullptr;
  }
}

bool FileHandle::is_open() const noexcept { return file_ != nullptr; }

Status FileHandle::write(ByteView data) {
  if (file_ == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "file is not open");
  if (data.empty()) return Status::success();
  const std::size_t written = std::fwrite(data.data(), 1, data.size(), static_cast<std::FILE*>(file_));
  if (written != data.size()) {
    return Status(ReasonCode::STORE_IO_ERROR, "short write");
  }
  return Status::success();
}

Result<std::size_t> FileHandle::read(ByteSpan buffer) {
  if (file_ == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "file is not open");
  const std::size_t read_count = std::fread(buffer.data(), 1, buffer.size(), static_cast<std::FILE*>(file_));
  if (read_count != buffer.size() && std::ferror(static_cast<std::FILE*>(file_)) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "read error");
  }
  return read_count;
}

Status FileHandle::sync() {
  if (file_ == nullptr) return Status::success();
  if (std::fflush(static_cast<std::FILE*>(file_)) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "flush failed");
  }
#if defined(_WIN32)
  if (_commit(_fileno(static_cast<std::FILE*>(file_))) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "commit to disk failed");
  }
#else
  if (::fsync(fileno(static_cast<std::FILE*>(file_))) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "fsync failed");
  }
#endif
  return Status::success();
}

Status FileHandle::seek(std::uint64_t offset) {
  if (file_ == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "file is not open");
  if (std::fseek(static_cast<std::FILE*>(file_), static_cast<long>(offset), SEEK_SET) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "seek failed");
  }
  return Status::success();
}

Status FileHandle::truncate_at(std::uint64_t offset) {
  if (file_ == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "file is not open");
  if (std::fflush(static_cast<std::FILE*>(file_)) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "flush before truncate failed");
  }
#if defined(_WIN32)
  if (_chsize_s(_fileno(static_cast<std::FILE*>(file_)), static_cast<long long>(offset)) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "truncate failed");
  }
#else
  if (ftruncate(fileno(static_cast<std::FILE*>(file_)), static_cast<off_t>(offset)) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "truncate failed");
  }
#endif
  return seek(offset);
}

Result<std::uint64_t> FileHandle::size() {
  if (file_ == nullptr) return Status(ReasonCode::STORE_IO_ERROR, "file is not open");
  const long current = std::ftell(static_cast<std::FILE*>(file_));
  if (current < 0) return Status(ReasonCode::STORE_IO_ERROR, "tell failed");
  if (std::fseek(static_cast<std::FILE*>(file_), 0, SEEK_END) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "seek to end failed");
  }
  const long end = std::ftell(static_cast<std::FILE*>(file_));
  if (end < 0) return Status(ReasonCode::STORE_IO_ERROR, "tell failed");
  if (std::fseek(static_cast<std::FILE*>(file_), current, SEEK_SET) != 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "seek back failed");
  }
  return static_cast<std::uint64_t>(end);
}

FileLock::~FileLock() { release(); }

Status FileLock::acquire(const std::filesystem::path& path) {
  release();
#if defined(_WIN32)
  const HANDLE handle = CreateFileW(path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status(ReasonCode::STORE_LOCKED,
                  "the directory is already in use by another process");
  }
  handle_ = handle;
#else
  const int descriptor = ::open(path.string().c_str(), O_RDWR | O_CREAT, 0644);
  if (descriptor < 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not open the lock file");
  }
  if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    ::close(descriptor);
    return Status(ReasonCode::STORE_LOCKED,
                  "the directory is already in use by another process");
  }
  descriptor_ = descriptor;
#endif
  return Status::success();
}

void FileLock::release() {
#if defined(_WIN32)
  if (handle_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
#else
  if (descriptor_ >= 0) {
    ::close(descriptor_);
    descriptor_ = -1;
  }
#endif
}

Status sync_existing_file(const std::filesystem::path& path) {
#if defined(_WIN32)
  const HANDLE handle =
      CreateFileW(path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not open the file to sync it");
  }
  const BOOL flushed = FlushFileBuffers(handle);
  CloseHandle(handle);
  if (!flushed) return Status(ReasonCode::STORE_IO_ERROR, "FlushFileBuffers failed");
  return Status::success();
#else
  const int descriptor = ::open(path.string().c_str(), O_RDONLY);
  if (descriptor < 0) {
    return Status(ReasonCode::STORE_IO_ERROR, "could not open the file to sync it");
  }
  const int result = ::fsync(descriptor);
  ::close(descriptor);
  if (result != 0) return Status(ReasonCode::STORE_IO_ERROR, "fsync failed");
  return Status::success();
#endif
}

Status atomic_replace_file(const std::filesystem::path& target, ByteView contents, bool sync_to_disk) {
  std::error_code error;
  const std::filesystem::path temporary = target.string() + ".tmp-replace";
  std::filesystem::remove(temporary, error);

  {
    FileHandle handle;
    SMF_RETURN_IF_ERROR(handle.open(temporary, true));
    SMF_RETURN_IF_ERROR(handle.write(contents));
    if (sync_to_disk) {
      SMF_RETURN_IF_ERROR(handle.sync());
    }
    handle.close();
  }

#if defined(_WIN32)
  if (!MoveFileExW(temporary.wstring().c_str(), target.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::filesystem::remove(temporary, error);
    return Status(ReasonCode::STORE_IO_ERROR, "atomic replacement failed");
  }
#else
  std::filesystem::rename(temporary, target, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    return Status(ReasonCode::STORE_IO_ERROR, "atomic replacement failed");
  }
#endif
  return Status::success();
}

}  // namespace smf
