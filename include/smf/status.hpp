// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Deterministic outcome vocabulary. Every decision this runtime makes is
// reported as a stable reason code; booleans are never the public answer to a
// question about authority.

#ifndef SMF_STATUS_HPP
#define SMF_STATUS_HPP

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace smf {

// X-macro list. The integer values are part of the durable store format and of
// the wire protocol; they must never be renumbered, only appended.
#define SMF_REASON_CODE_LIST(X)                     \
  X(OK, 0)                                          \
  X(INTERNAL_ERROR, 1)                              \
  X(NOT_IMPLEMENTED, 2)                             \
  X(UNSUPPORTED, 3)                                 \
  X(INVALID_ARGUMENT, 4)                            \
  X(INVALID_ID, 5)                                  \
  X(INVALID_GENERATION, 6)                          \
  X(INVALID_DIGEST, 7)                              \
  X(INVALID_UTF8, 8)                                \
  X(INVALID_STATE_KIND, 9)                          \
  X(INVALID_SIZE, 10)                               \
  X(INVALID_POLICY, 11)                             \
  X(INVALID_ADDRESS, 12)                            \
  X(INVALID_STATE_TRANSITION, 13)                   \
  X(NOT_FOUND, 14)                                  \
  X(OBJECT_NOT_FOUND, 15)                           \
  X(OBJECT_VERSION_NOT_FOUND, 16)                   \
  X(MOVEMENT_NOT_FOUND, 17)                         \
  X(ENDPOINT_NOT_FOUND, 18)                         \
  X(ATTEMPT_NOT_FOUND, 19)                          \
  X(NOT_AUTHORIZED, 20)                             \
  X(AUTHORITY_EXPIRED, 21)                          \
  X(AUTHORITY_CONSUMED, 22)                         \
  X(AUTHORITY_MISMATCH, 23)                         \
  X(AUTHORITY_REVOKED, 24)                          \
  X(AUTHORITY_STALE, 25)                            \
  X(STALE_GENERATION, 26)                           \
  X(STALE_STATE_GENERATION, 27)                     \
  X(STALE_MOVEMENT_GENERATION, 28)                  \
  X(STALE_POLICY_GENERATION, 29)                    \
  X(STALE_TOPOLOGY_GENERATION, 30)                  \
  X(STALE_COMPATIBILITY_GENERATION, 31)             \
  X(STALE_INCARNATION, 32)                          \
  X(STALE_EPOCH, 33)                                \
  X(STALE_ATTEMPT, 34)                              \
  X(STALE_SESSION, 35)                              \
  X(STALE_REPLAY, 36)                               \
  X(ENDPOINT_NOT_LIVE, 37)                          \
  X(ENDPOINT_LIVENESS_UNKNOWN, 38)                  \
  X(ENDPOINT_CONTRACT_MISMATCH, 39)                 \
  X(COORDINATOR_INCARNATION_MISMATCH, 40)           \
  X(REVALIDATION_REQUIRED, 41)                      \
  X(COMPATIBILITY_EVIDENCE_MISSING, 42)             \
  X(COMPATIBILITY_UNKNOWN, 43)                      \
  X(COMPATIBILITY_UNSUPPORTED, 44)                  \
  X(COMPATIBILITY_MISMATCH, 45)                     \
  X(COMPATIBILITY_STALE_EVIDENCE, 46)               \
  X(ILLEGAL_TRANSITION, 47)                         \
  X(ALREADY_TERMINAL, 48)                           \
  X(MOVEMENT_NOT_CANCELLABLE, 49)                   \
  X(MOVEMENT_NOT_RECONCILABLE, 50)                  \
  X(MOVEMENT_SUPERSEDED, 51)                        \
  X(MOVEMENT_CANCELLED, 52)                         \
  X(MOVEMENT_FAILED, 53)                            \
  X(OUTCOME_UNKNOWN, 54)                            \
  X(COMMIT_ALREADY_EXISTS, 55)                      \
  X(COMMIT_MARKER_INVALID, 56)                      \
  X(COMMIT_REFUSED, 57)                             \
  X(VERIFY_FAILED, 58)                              \
  X(INTEGRITY_CHECK_FAILED, 59)                     \
  X(CHUNK_OUT_OF_ORDER, 60)                         \
  X(CHUNK_CONFLICT, 61)                             \
  X(CHUNK_INDEX_OUT_OF_RANGE, 62)                   \
  X(CHUNK_TOO_LARGE, 63)                            \
  X(CHUNK_DIGEST_MISMATCH, 64)                      \
  X(CONTENT_DIGEST_MISMATCH, 65)                    \
  X(TRANSFER_INCOMPLETE, 66)                        \
  X(BYTE_COUNT_MISMATCH, 67)                        \
  X(RESUME_INCOMPATIBLE, 68)                        \
  X(RESUME_NOT_ALLOWED, 69)                         \
  X(DUPLICATE_ATTEMPT, 70)                          \
  X(ATTEMPT_EXHAUSTED, 71)                          \
  X(RETRY_NOT_REPEATABLE, 72)                       \
  X(SOURCE_REJECTED, 73)                            \
  X(DESTINATION_REJECTED, 74)                       \
  X(PROTOCOL_VERSION_MISMATCH, 75)                  \
  X(PROTOCOL_MAGIC_MISMATCH, 76)                    \
  X(PROTOCOL_RESERVED_NONZERO, 77)                  \
  X(PROTOCOL_FLAGS_INVALID, 78)                     \
  X(PROTOCOL_UNKNOWN_MESSAGE, 79)                   \
  X(PROTOCOL_PAYLOAD_TOO_LARGE, 80)                 \
  X(PROTOCOL_TRUNCATED, 81)                         \
  X(PROTOCOL_TRAILING_GARBAGE, 82)                  \
  X(PROTOCOL_AUTH_FAILED, 83)                       \
  X(PROTOCOL_SEQUENCE_REPLAY, 84)                   \
  X(PROTOCOL_SEQUENCE_REGRESSION, 85)               \
  X(PROTOCOL_STATE_VIOLATION, 86)                   \
  X(PROTOCOL_CANONICAL_VIOLATION, 87)               \
  X(PROTOCOL_MALFORMED, 88)                         \
  X(PROTOCOL_HANDSHAKE_REQUIRED, 89)                \
  X(PROTOCOL_HANDSHAKE_FAILED, 90)                  \
  X(PROTOCOL_BOUNDS_EXCEEDED, 91)                   \
  X(STORE_IO_ERROR, 92)                             \
  X(STORE_CORRUPT, 93)                              \
  X(STORE_VERSION_UNSUPPORTED, 94)                  \
  X(STORE_TRUNCATED, 95)                            \
  X(STORE_OVERSIZED, 96)                            \
  X(STORE_RECORD_INVALID, 97)                       \
  X(STORE_CHECKSUM_MISMATCH, 98)                    \
  X(STORE_PARTIAL_TAIL, 99)                         \
  X(STORE_LOCKED, 100)                              \
  X(STORE_RECOVERY_REQUIRED, 101)                   \
  X(IO_ERROR, 102)                                  \
  X(IO_TIMEOUT, 103)                                \
  X(CONNECTION_CLOSED, 104)                         \
  X(CONNECTION_REFUSED, 105)                        \
  X(CONNECTION_RESET, 106)                          \
  X(ADDRESS_INVALID, 107)                           \
  X(BIND_FAILED, 108)                               \
  X(LISTEN_FAILED, 109)                             \
  X(CONNECT_FAILED, 110)                            \
  X(NETWORK_UNAVAILABLE, 111)                       \
  X(SHUTTING_DOWN, 112)                             \
  X(RESOURCE_EXHAUSTED, 113)                        \
  X(QUEUE_FULL, 114)                                \
  X(TOO_MANY_SESSIONS, 115)                         \
  X(TOO_MANY_MOVEMENTS, 116)                        \
  X(HISTORY_LIMIT_REACHED, 117)                     \
  X(ALLOCATION_LIMIT_EXCEEDED, 118)                 \
  X(BUSY, 119)                                      \
  X(DEADLINE_EXCEEDED, 120)                         \
  X(CANCELLED_BY_OPERATOR, 121)                     \
  X(CLEANUP_FAILED, 122)                            \
  X(CLEANUP_SKIPPED, 123)                           \
  X(QUARANTINED, 124)                               \
  X(POLICY_VIOLATION, 125)                          \
  X(SIZE_OVERFLOW, 126)                             \
  X(DUPLICATE_IDENTITY, 127)                        \
  X(SELF_MOVEMENT, 128)                             \
  X(NO_EVIDENCE, 129)

#define SMF_REASON_CODE_ENUMERATOR(name, value) name = value,

enum class ReasonCode : std::uint16_t { SMF_REASON_CODE_LIST(SMF_REASON_CODE_ENUMERATOR) };

#undef SMF_REASON_CODE_ENUMERATOR

// Stable uppercase spelling, used by the CLI, the durable store, and tests.
[[nodiscard]] const char* to_string(ReasonCode code) noexcept;

// Exact inverse of to_string for known codes. Returns nullopt for anything
// else, including unknown spellings and mixed case.
[[nodiscard]] std::optional<ReasonCode> reason_code_from_string(std::string_view text) noexcept;

// True only for conditions where repeating the same operation can plausibly
// succeed without any authority being re-established.
[[nodiscard]] bool is_transient(ReasonCode code) noexcept;

// True when the condition indicates that a generation, incarnation, or
// authority binding went stale and must be re-established before retrying.
[[nodiscard]] bool is_staleness(ReasonCode code) noexcept;

class Status {
 public:
  Status() noexcept = default;
  Status(ReasonCode code, std::string message) : code_(code), message_(std::move(message)) {}
  explicit Status(ReasonCode code) : code_(code) {}

  // Named success() rather than ok() because ok() is the predicate. A Status
  // constructed by default is already OK; this exists for readability in
  // explicit returns.
  [[nodiscard]] static Status success() noexcept { return Status(); }

  [[nodiscard]] bool ok() const noexcept { return code_ == ReasonCode::OK; }
  [[nodiscard]] ReasonCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }

  [[nodiscard]] std::string to_string() const;

 private:
  ReasonCode code_ = ReasonCode::OK;
  std::string message_;
};

[[nodiscard]] inline bool operator==(const Status& a, const Status& b) noexcept {
  return a.code() == b.code();
}
[[nodiscard]] inline bool operator!=(const Status& a, const Status& b) noexcept {
  return !(a == b);
}

// Result<T> carries either a value or a non-OK Status. There is deliberately no
// implicit "default value on failure" path: a failed Result must be inspected
// through status().
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}  // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {  // NOLINT(google-explicit-constructor)
    if (status_.ok()) {
      status_ = Status(ReasonCode::INTERNAL_ERROR, "Result constructed from an OK status");
    }
  }

  [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] const Status& status() const noexcept { return status_; }

  [[nodiscard]] T& value() & { return require_value(); }
  [[nodiscard]] const T& value() const& { return require_value(); }
  [[nodiscard]] T&& value() && { return std::move(require_value()); }

  [[nodiscard]] T value_or(T fallback) const {
    return value_.has_value() ? *value_ : std::move(fallback);
  }

 private:
  [[nodiscard]] T& require_value() const {
    if (!value_.has_value()) {
      throw std::logic_error("Result::value() on failure: " + status_.to_string());
    }
    return const_cast<T&>(*value_);
  }

  std::optional<T> value_;
  Status status_;
};

// Propagate a Status-returning expression out of the current function.
#define SMF_RETURN_IF_ERROR(expr)                        \
  do {                                                   \
    const ::smf::Status smf_status_ = (expr);            \
    if (!smf_status_.ok()) return smf_status_;           \
  } while (false)

// Propagate a Result-returning expression's failure out of a Status-returning
// function.
#define SMF_RETURN_IF_FAILED(expr)                       \
  do {                                                   \
    const auto& smf_result_ = (expr);                    \
    if (!smf_result_.ok()) return smf_result_.status();  \
  } while (false)

}  // namespace smf

#endif  // SMF_STATUS_HPP
