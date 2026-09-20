// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Deliberately tiny logging seam. Library code never writes to a stream on its
// own: a process either installs a sink or gets no output at all, which keeps
// the library free of debug printing.

#ifndef SMF_LOGGING_HPP
#define SMF_LOGGING_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "smf/status.hpp"

namespace smf {

enum class LogLevel : std::uint8_t { TRACE = 0, DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4, OFF = 5 };

[[nodiscard]] const char* to_string(LogLevel level) noexcept;
[[nodiscard]] bool log_level_from_string(std::string_view text, LogLevel& out) noexcept;

struct LogRecord {
  LogLevel level = LogLevel::INFO;
  std::string component;
  std::string message;
};

using LogSink = std::function<void(const LogRecord&)>;

// Installs the process-wide sink. Passing an empty function disables logging.
void set_log_sink(LogSink sink);
void set_log_level(LogLevel level);
[[nodiscard]] LogLevel log_level() noexcept;
[[nodiscard]] bool log_enabled(LogLevel level) noexcept;

void log_message(LogLevel level, std::string_view component, std::string message);

// Sink that writes one line per record to stderr.
[[nodiscard]] LogSink make_stderr_sink();

}  // namespace smf

#endif  // SMF_LOGGING_HPP
