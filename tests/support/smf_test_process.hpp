// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Child-process control for the distributed proofs. The fabric's most
// important guarantees are about what happens when a process dies at an
// inconvenient moment, so the harness can start, observe, kill, and restart
// real operating-system processes.

#ifndef SMF_TEST_PROCESS_HPP
#define SMF_TEST_PROCESS_HPP

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "smf/status.hpp"

namespace smftest {

// Absolute path of the directory holding the built executables, or an empty
// path when this build configuration did not produce them.
[[nodiscard]] std::filesystem::path binary_directory();

// Absolute path of a sibling executable, for example executable("smf-coordinator").
[[nodiscard]] std::filesystem::path executable(const std::string& name);

[[nodiscard]] bool has_executables();

struct ProcessSpec {
  std::filesystem::path program;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
  std::map<std::string, std::string> environment;
  std::filesystem::path output_file;
};

// A hard-killable child process. Output is redirected to a file rather than a
// pipe so that a killed child can never leave the parent blocked on a read.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;

  [[nodiscard]] static smf::Result<ChildProcess> spawn(const ProcessSpec& spec);

  [[nodiscard]] bool running();
  [[nodiscard]] bool wait_for_exit(std::uint32_t max_wait_millis);
  [[nodiscard]] bool wait_for_exit();
  [[nodiscard]] smf::Result<int> exit_code();

  // TerminateProcess / SIGKILL: no unwinding, no flush, no destructors.
  void kill();

  [[nodiscard]] std::string output() const;
  [[nodiscard]] std::uint64_t pid() const noexcept { return pid_; }

 private:
  void release() noexcept;

  void* process_handle_ = nullptr;
  std::uint64_t pid_ = 0;
  int exit_code_ = 0;
  bool exited_ = false;
  std::filesystem::path output_file_;
};

// Waits until predicate() is true or the budget is exhausted. Returns true when
// the predicate became true. This is an observation helper used to place kills
// at a chosen barrier; it is never used to bound how long a test may run.
template <class Predicate>
[[nodiscard]] bool wait_until(Predicate predicate, std::uint32_t max_wait_millis = 30000) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(max_wait_millis);
  for (;;) {
    if (predicate()) return true;
    if (std::chrono::steady_clock::now() >= deadline) return predicate();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

}  // namespace smftest

#endif  // SMF_TEST_PROCESS_HPP
