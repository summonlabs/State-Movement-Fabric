// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf_test_process.hpp"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#include <windows.h>

#include <map>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace smftest {
namespace {

[[nodiscard]] std::string quote_argument(const std::string& argument) {
  std::string out = "\"";
  for (const char c : argument) {
    if (c == '"') {
      out += "\\\"";
    } else {
      out += c;
    }
  }
  out += "\"";
  return out;
}

#if defined(_WIN32)
// Every Windows process API used here has a wide-character entry point, and the
// narrow one would reinterpret a char buffer as UTF-16. The conversion is
// explicit and UTF-8 aware so that a path outside the ASCII range still works.
[[nodiscard]] std::wstring to_wide(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int required = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
  if (required <= 0) return std::wstring();
  std::wstring out(static_cast<std::size_t>(required), L'\0');
  (void)MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                            required);
  return out;
}
#endif

}  // namespace

std::filesystem::path binary_directory() {
#ifdef SMF_TEST_BIN_DIR
  return std::filesystem::path(SMF_TEST_BIN_DIR);
#else
  return {};
#endif
}

std::filesystem::path executable(const std::string& name) {
  const std::filesystem::path directory = binary_directory();
  if (directory.empty()) return {};
#if defined(_WIN32)
  return directory / (name + ".exe");
#else
  return directory / name;
#endif
}

bool has_executables() {
  const std::filesystem::path directory = binary_directory();
  if (directory.empty()) return false;
  std::error_code error;
  return std::filesystem::is_directory(directory, error);
}

#if defined(_WIN32)

ChildProcess::~ChildProcess() { release(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept { *this = std::move(other); }

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    process_handle_ = other.process_handle_;
    pid_ = other.pid_;
    exit_code_ = other.exit_code_;
    exited_ = other.exited_;
    output_file_ = std::move(other.output_file_);
    other.process_handle_ = nullptr;
    other.pid_ = 0;
    other.exited_ = true;
  }
  return *this;
}

void ChildProcess::release() noexcept {
  if (process_handle_ != nullptr) {
    if (!exited_) {
      TerminateProcess(static_cast<HANDLE>(process_handle_), 137U);
      WaitForSingleObject(static_cast<HANDLE>(process_handle_), INFINITE);
    }
    CloseHandle(static_cast<HANDLE>(process_handle_));
    process_handle_ = nullptr;
  }
}

smf::Result<ChildProcess> ChildProcess::spawn(const ProcessSpec& spec) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  const std::filesystem::path output = spec.output_file;
  HANDLE output_handle = CreateFileW(output.wstring().c_str(), GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
  if (output_handle == INVALID_HANDLE_VALUE) {
    return smf::Status(smf::ReasonCode::IO_ERROR, "could not create the child output file");
  }

  std::string narrow_command = quote_argument(spec.program.string());
  for (const std::string& argument : spec.arguments) {
    narrow_command.push_back(' ');
    narrow_command += quote_argument(argument);
  }
  std::wstring command_line = to_wide(narrow_command);

  // The child inherits the parent environment with the caller's overrides
  // applied. Passing only the overrides would strip SystemRoot and PATH, which
  // the runtime needs before it can do anything at all.
  std::map<std::wstring, std::wstring> environment;
  if (LPWCH current = GetEnvironmentStringsW()) {
    for (LPWCH entry = current; *entry != L'\0';) {
      const std::wstring text(entry);
      entry += text.size() + 1;
      const std::size_t separator = text.find(L'=');
      if (separator == std::wstring::npos || separator == 0) continue;
      environment[text.substr(0, separator)] = text.substr(separator + 1);
    }
    FreeEnvironmentStringsW(current);
  }
  for (const auto& entry : spec.environment) {
    environment[to_wide(entry.first)] = to_wide(entry.second);
  }

  std::wstring environment_block;
  for (const auto& entry : environment) {
    environment_block += entry.first;
    environment_block.push_back(L'=');
    environment_block += entry.second;
    environment_block.push_back(L'\0');
  }
  environment_block.push_back(L'\0');

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdOutput = output_handle;
  startup.StartupInfo.hStdError = output_handle;
  startup.StartupInfo.hStdInput = nullptr;

  PROCESS_INFORMATION information{};
  std::wstring working_directory = spec.working_directory.wstring();

  const BOOL created = CreateProcessW(
      nullptr, command_line.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      environment_block.size() > 1 ? environment_block.data() : nullptr,
      working_directory.empty() ? nullptr : working_directory.c_str(), &startup.StartupInfo,
      &information);

  CloseHandle(output_handle);

  if (!created) {
    return smf::Status(smf::ReasonCode::IO_ERROR,
                       "CreateProcess failed with error " + std::to_string(GetLastError()));
  }

  CloseHandle(information.hThread);

  ChildProcess child;
  child.process_handle_ = information.hProcess;
  child.pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  child.output_file_ = output;
  return child;
}

bool ChildProcess::running() {
  if (process_handle_ == nullptr || exited_) return false;
  const DWORD status = WaitForSingleObject(static_cast<HANDLE>(process_handle_), 0);
  if (status == WAIT_TIMEOUT) return true;
  DWORD code = 0;
  GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code);
  exit_code_ = static_cast<int>(code);
  exited_ = true;
  return false;
}

bool ChildProcess::wait_for_exit(std::uint32_t max_wait_millis) {
  if (process_handle_ == nullptr) return true;
  if (exited_) return true;
  const DWORD status = WaitForSingleObject(static_cast<HANDLE>(process_handle_), max_wait_millis);
  if (status == WAIT_TIMEOUT) return false;
  DWORD code = 0;
  GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code);
  exit_code_ = static_cast<int>(code);
  exited_ = true;
  return true;
}

bool ChildProcess::wait_for_exit() { return wait_for_exit(INFINITE); }

smf::Result<int> ChildProcess::exit_code() {
  if (process_handle_ == nullptr) {
    return smf::Status(smf::ReasonCode::INVALID_ARGUMENT, "child process was never started");
  }
  if (!exited_) {
    if (!wait_for_exit()) {
      return smf::Status(smf::ReasonCode::IO_TIMEOUT, "child process has not exited");
    }
  }
  return exit_code_;
}

void ChildProcess::kill() {
  if (process_handle_ == nullptr) return;
  if (!exited_) {
    TerminateProcess(static_cast<HANDLE>(process_handle_), 137U);
    WaitForSingleObject(static_cast<HANDLE>(process_handle_), INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(static_cast<HANDLE>(process_handle_), &code);
    exit_code_ = static_cast<int>(code);
    exited_ = true;
  }
}

#else

ChildProcess::~ChildProcess() { release(); }

ChildProcess::ChildProcess(ChildProcess&& other) noexcept { *this = std::move(other); }

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    process_handle_ = other.process_handle_;
    pid_ = other.pid_;
    exit_code_ = other.exit_code_;
    exited_ = other.exited_;
    output_file_ = std::move(other.output_file_);
    other.process_handle_ = nullptr;
    other.pid_ = 0;
    other.exited_ = true;
  }
  return *this;
}

void ChildProcess::release() noexcept {
  if (process_handle_ != nullptr) {
    if (!exited_) {
      ::kill(static_cast<pid_t>(pid_), SIGKILL);
      int status = 0;
      ::waitpid(static_cast<pid_t>(pid_), &status, 0);
    }
    process_handle_ = nullptr;
  }
}

smf::Result<ChildProcess> ChildProcess::spawn(const ProcessSpec& spec) {
  const pid_t child = ::fork();
  if (child < 0) {
    return smf::Status(smf::ReasonCode::IO_ERROR, "fork failed");
  }
  if (child == 0) {
    const int output = ::open(spec.output_file.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output >= 0) {
      ::dup2(output, STDOUT_FILENO);
      ::dup2(output, STDERR_FILENO);
      ::close(output);
    }
    if (!spec.working_directory.empty()) {
      (void)::chdir(spec.working_directory.string().c_str());
    }
    for (const auto& entry : spec.environment) {
      (void)::setenv(entry.first.c_str(), entry.second.c_str(), 1);
    }
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(spec.program.string().c_str()));
    for (const std::string& argument : spec.arguments) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    ::execv(spec.program.string().c_str(), argv.data());
    ::_exit(127);
  }

  ChildProcess instance;
  instance.process_handle_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(child));
  instance.pid_ = static_cast<std::uint64_t>(child);
  instance.output_file_ = spec.output_file;
  return instance;
}

bool ChildProcess::running() {
  if (process_handle_ == nullptr || exited_) return false;
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
  if (result == 0) return true;
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  exited_ = true;
  return false;
}

bool ChildProcess::wait_for_exit(std::uint32_t max_wait_millis) {
  if (process_handle_ == nullptr || exited_) return true;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(max_wait_millis);
  for (;;) {
    if (!running()) return true;
    if (std::chrono::steady_clock::now() >= deadline) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

bool ChildProcess::wait_for_exit() { return wait_for_exit(60000); }

smf::Result<int> ChildProcess::exit_code() {
  if (process_handle_ == nullptr) {
    return smf::Status(smf::ReasonCode::INVALID_ARGUMENT, "child process was never started");
  }
  if (!exited_) {
    if (!wait_for_exit()) {
      return smf::Status(smf::ReasonCode::IO_TIMEOUT, "child process has not exited");
    }
  }
  return exit_code_;
}

void ChildProcess::kill() {
  if (process_handle_ == nullptr || exited_) return;
  ::kill(static_cast<pid_t>(pid_), SIGKILL);
  int status = 0;
  ::waitpid(static_cast<pid_t>(pid_), &status, 0);
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  exited_ = true;
}

#endif

std::string ChildProcess::output() const {
  if (output_file_.empty()) return {};
  std::ifstream stream(output_file_, std::ios::binary);
  if (!stream) return {};
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

}  // namespace smftest
