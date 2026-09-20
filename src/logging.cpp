// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/logging.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>

namespace smf {
namespace {

std::mutex g_sink_mutex;
LogSink g_sink;
std::atomic<LogLevel> g_level{LogLevel::WARN};

}  // namespace

const char* to_string(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::TRACE:
      return "TRACE";
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::INFO:
      return "INFO";
    case LogLevel::WARN:
      return "WARN";
    case LogLevel::ERROR:
      return "ERROR";
    case LogLevel::OFF:
      return "OFF";
  }
  return "UNRECOGNIZED_LOG_LEVEL";
}

bool log_level_from_string(std::string_view text, LogLevel& out) noexcept {
  constexpr LogLevel kAll[] = {LogLevel::TRACE, LogLevel::DEBUG, LogLevel::INFO,
                               LogLevel::WARN,  LogLevel::ERROR, LogLevel::OFF};
  for (const LogLevel level : kAll) {
    if (text == to_string(level)) {
      out = level;
      return true;
    }
  }
  return false;
}

void set_log_sink(LogSink sink) {
  std::lock_guard<std::mutex> lock(g_sink_mutex);
  g_sink = std::move(sink);
}

void set_log_level(LogLevel level) { g_level.store(level, std::memory_order_relaxed); }

LogLevel log_level() noexcept { return g_level.load(std::memory_order_relaxed); }

bool log_enabled(LogLevel level) noexcept {
  if (level == LogLevel::OFF) return false;
  const LogLevel threshold = g_level.load(std::memory_order_relaxed);
  if (threshold == LogLevel::OFF) return false;
  return static_cast<std::uint8_t>(level) >= static_cast<std::uint8_t>(threshold);
}

void log_message(LogLevel level, std::string_view component, std::string message) {
  if (!log_enabled(level)) return;
  LogRecord record;
  record.level = level;
  record.component = std::string(component);
  record.message = std::move(message);

  LogSink sink;
  {
    std::lock_guard<std::mutex> lock(g_sink_mutex);
    sink = g_sink;
  }
  // The sink is invoked with no library lock held, so a sink that calls back
  // into the runtime cannot deadlock against a logging mutex.
  if (sink) sink(record);
}

LogSink make_stderr_sink() {
  return [](const LogRecord& record) {
    std::fprintf(stderr, "[%s] %s: %s\n", to_string(record.level), record.component.c_str(),
                 record.message.c_str());
  };
}

}  // namespace smf
