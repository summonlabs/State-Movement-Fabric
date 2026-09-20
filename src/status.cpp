// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/status.hpp"

#include <array>
#include <cstring>

namespace smf {

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
#define SMF_REASON_CODE_CASE(name, value) \
  case ReasonCode::name:                  \
    return #name;
    SMF_REASON_CODE_LIST(SMF_REASON_CODE_CASE)
#undef SMF_REASON_CODE_CASE
  }
  return "UNRECOGNIZED_REASON_CODE";
}

std::optional<ReasonCode> reason_code_from_string(std::string_view text) noexcept {
#define SMF_REASON_CODE_MATCH(name, value)                       \
  if (text == #name) {                                           \
    return ReasonCode::name;                                     \
  }
  SMF_REASON_CODE_LIST(SMF_REASON_CODE_MATCH)
#undef SMF_REASON_CODE_MATCH
  return std::nullopt;
}

bool is_transient(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::IO_ERROR:
    case ReasonCode::IO_TIMEOUT:
    case ReasonCode::CONNECTION_CLOSED:
    case ReasonCode::CONNECTION_RESET:
    case ReasonCode::CONNECTION_REFUSED:
    case ReasonCode::CONNECT_FAILED:
    case ReasonCode::BUSY:
    case ReasonCode::QUEUE_FULL:
    case ReasonCode::STORE_IO_ERROR:
    case ReasonCode::DEADLINE_EXCEEDED:
    case ReasonCode::TRANSFER_INCOMPLETE:
      return true;
    default:
      return false;
  }
}

bool is_staleness(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::STALE_GENERATION:
    case ReasonCode::STALE_STATE_GENERATION:
    case ReasonCode::STALE_MOVEMENT_GENERATION:
    case ReasonCode::STALE_POLICY_GENERATION:
    case ReasonCode::STALE_TOPOLOGY_GENERATION:
    case ReasonCode::STALE_COMPATIBILITY_GENERATION:
    case ReasonCode::STALE_INCARNATION:
    case ReasonCode::STALE_EPOCH:
    case ReasonCode::STALE_ATTEMPT:
    case ReasonCode::STALE_SESSION:
    case ReasonCode::STALE_REPLAY:
    case ReasonCode::AUTHORITY_EXPIRED:
    case ReasonCode::AUTHORITY_CONSUMED:
    case ReasonCode::AUTHORITY_STALE:
    case ReasonCode::REVALIDATION_REQUIRED:
    case ReasonCode::COMPATIBILITY_STALE_EVIDENCE:
      return true;
    default:
      return false;
  }
}

std::string Status::to_string() const {
  std::string out = smf::to_string(code_);
  if (!message_.empty()) {
    out.append(": ");
    out.append(message_);
  }
  return out;
}

}  // namespace smf
