// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/fault_injection.hpp"

#include <chrono>
#include <cstdlib>
#include <thread>
#include <vector>

namespace smf {
namespace {

[[nodiscard]] std::vector<std::string> split(std::string_view text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char c : text) {
    if (c == separator) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts.push_back(current);
  return parts;
}

[[nodiscard]] bool parse_u64(std::string_view text, std::uint64_t& out) {
  if (text.empty()) return false;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
    value = (value * 10U) + static_cast<std::uint64_t>(c - '0');
  }
  out = value;
  return true;
}

[[nodiscard]] bool parse_action(std::string_view text, FaultAction& out) {
  if (text == "exit") {
    out = FaultAction::EXIT_NOW;
    return true;
  }
  if (text == "hold") {
    out = FaultAction::HOLD;
    return true;
  }
  return false;
}

}  // namespace

const char* to_string(FaultAction action) noexcept {
  switch (action) {
    case FaultAction::NONE:
      return "NONE";
    case FaultAction::EXIT_NOW:
      return "EXIT_NOW";
    case FaultAction::HOLD:
      return "HOLD";
  }
  return "UNRECOGNIZED_FAULT_ACTION";
}

FaultInjector& FaultInjector::instance() {
  static FaultInjector injector;
  return injector;
}

Status FaultInjector::configure(std::string_view specification) {
  std::map<std::string, Rule> parsed;
  if (!specification.empty()) {
    for (const std::string& entry : split(specification, ',')) {
      if (entry.empty()) {
        return Status(ReasonCode::INVALID_ARGUMENT, "fault injection specification has an empty entry");
      }
      const std::vector<std::string> assignment = split(entry, '=');
      if (assignment.size() != 2) {
        return Status(ReasonCode::INVALID_ARGUMENT,
                      "fault injection entry must be point=action: " + entry);
      }
      std::string point = assignment[0];
      std::uint64_t ordinal = 0;
      const std::vector<std::string> key = split(point, '@');
      if (key.size() == 2) {
        point = key[0];
        if (!parse_u64(key[1], ordinal) || ordinal == 0) {
          return Status(ReasonCode::INVALID_ARGUMENT,
                        "fault injection ordinal must be a positive integer: " + entry);
        }
      } else if (key.size() != 1) {
        return Status(ReasonCode::INVALID_ARGUMENT, "malformed fault injection point: " + entry);
      }
      if (point.empty()) {
        return Status(ReasonCode::INVALID_ARGUMENT, "fault injection point must not be empty");
      }

      Rule rule;
      if (!parse_action(assignment[1], rule.action)) {
        return Status(ReasonCode::INVALID_ARGUMENT,
                      "fault injection action must be 'exit' or 'hold': " + entry);
      }
      rule.every = key.size() == 1;
      rule.ordinal = ordinal;
      parsed[point] = rule;
    }
  }

  std::lock_guard<std::mutex> lock(mutex_);
  rules_ = std::move(parsed);
  specification_ = std::string(specification);
  return Status::success();
}

bool FaultInjector::enabled() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return !rules_.empty();
}

std::string FaultInjector::specification() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return specification_;
}

void FaultInjector::reach(std::string_view point) {
  FaultAction action = FaultAction::NONE;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rules_.empty()) return;
    const auto found = rules_.find(std::string(point));
    if (found == rules_.end()) return;
    Rule& rule = found->second;
    rule.seen += 1;
    const bool fires = rule.every ? true : (rule.seen == rule.ordinal);
    if (!fires) return;
    if (!rule.every && rule.seen > rule.ordinal) return;
    action = rule.action;
  }

  if (action == FaultAction::HOLD) {
    // Park the worker so that an external killer can land at this exact barrier.
    for (;;) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }

  // Abrupt death: no unwinding, no buffers flushed, no destructors run. This is
  // the same end state as an external hard kill, reached deterministically.
  std::_Exit(86);
}

bool FaultInjector::will_hold(std::string_view point) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto found = rules_.find(std::string(point));
  if (found == rules_.end()) return false;
  return found->second.action == FaultAction::HOLD;
}

}  // namespace smf
