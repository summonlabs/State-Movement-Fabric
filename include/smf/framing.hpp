// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Framed, versioned, integrity-checked transport.
//
// Wire layout of one frame:
//
//   offset size field
//   0      4    magic 'S','M','F','1'
//   4      1    protocol version
//   5      1    flags (bit0 authenticated, bit1 response, bit2 error)
//   6      2    reserved, must be zero
//   8      2    message type, little endian
//   10     2    reserved, must be zero
//   12     4    payload length, little endian
//   16     8    session sequence number, little endian
//   24     16   authentication tag (HMAC-SHA-256 truncated)
//   40     N    payload
//
// Every reserved field must be zero. A decoder rejects a non-zero reserved
// field, an unknown version, a payload longer than the configured bound, a
// sequence number that repeats or skips, and an authentication tag that does
// not verify over the first 24 header bytes plus the payload.

#ifndef SMF_FRAMING_HPP
#define SMF_FRAMING_HPP

#include <cstdint>
#include <string>

#include "smf/bytes.hpp"
#include "smf/digest.hpp"
#include "smf/status.hpp"
#include "smf/transport.hpp"

namespace smf {

enum class MessageType : std::uint16_t {
  INVALID = 0,

  HELLO = 1,
  HELLO_ACK = 2,
  HELLO_REJECT = 3,

  REGISTER = 10,
  REGISTER_ACK = 11,
  ANNOUNCE_OBJECT = 12,
  ANNOUNCE_ACK = 13,
  HEARTBEAT = 14,
  HEARTBEAT_ACK = 15,

  GRANT_TRANSFER = 20,
  GRANT_ACK = 21,
  EXECUTE_MOVEMENT = 22,
  ATTEMPT_RESULT = 23,
  CANCEL = 24,
  CANCEL_ACK = 25,

  COMMIT_REQUEST = 30,
  COMMIT_RESULT = 31,
  VERIFY_REQUEST = 32,
  VERIFY_RESPONSE = 33,
  AUTHORITY_QUERY = 34,
  AUTHORITY_REPORT = 35,
  CLEANUP_REQUEST = 36,
  CLEANUP_RESULT = 37,

  DATA_BEGIN = 40,
  DATA_BEGIN_ACK = 41,
  DATA_CHUNK = 42,
  DATA_CHUNK_ACK = 43,
  DATA_END = 44,
  DATA_RESULT = 45,
  DATA_ABORT = 46,

  SUBMIT_MOVEMENT = 50,
  MOVEMENT_ACCEPTED = 51,
  QUERY_MOVEMENT = 52,
  MOVEMENT_STATUS = 53,
  LIST_MOVEMENTS = 54,
  MOVEMENT_LIST = 55,
  CANCEL_MOVEMENT = 56,
  RECONCILE_MOVEMENT = 57,
  PROVENANCE_REQUEST = 58,
  PROVENANCE_REPORT = 59,
  TOPOLOGY_REQUEST = 60,
  TOPOLOGY_REPORT = 61,
  POLICY_REQUEST = 62,
  POLICY_REPORT = 63,
  SHUTDOWN = 64,
  SHUTDOWN_ACK = 65,

  ERROR = 99,
};

[[nodiscard]] const char* to_string(MessageType type) noexcept;
[[nodiscard]] bool message_type_from_value(std::uint16_t value, MessageType& out) noexcept;
[[nodiscard]] bool is_handshake_message(MessageType type) noexcept;

enum class FrameFlag : std::uint8_t {
  NONE = 0,
  AUTHENTICATED = 0x01,
  RESPONSE = 0x02,
  ERROR = 0x04,
};

[[nodiscard]] inline std::uint8_t operator|(FrameFlag a, FrameFlag b) noexcept {
  return static_cast<std::uint8_t>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}

inline constexpr std::size_t kFrameHeaderBytes = 40;
inline constexpr std::size_t kFrameAuthTagBytes = 16;

struct FrameHeader {
  std::uint8_t version = 1;
  std::uint8_t flags = 0;
  MessageType type = MessageType::INVALID;
  std::uint32_t payload_length = 0;
  std::uint64_t sequence = 0;
  Digest auth_tag;
};

struct Frame {
  FrameHeader header;
  Bytes payload;

  [[nodiscard]] bool authenticated() const noexcept {
    return (header.flags & static_cast<std::uint8_t>(FrameFlag::AUTHENTICATED)) != 0;
  }
  [[nodiscard]] bool is_error() const noexcept {
    return (header.flags & static_cast<std::uint8_t>(FrameFlag::ERROR)) != 0;
  }
};

// Packs a header into exactly kFrameHeaderBytes bytes. Reserved fields are
// always written as zero.
void encode_frame_header(const FrameHeader& header, ByteSpan out);

// Parses exactly kFrameHeaderBytes bytes. Rejects a wrong magic, an unsupported
// version, non-zero reserved fields, unknown flag bits, and a payload length
// above max_payload_bytes.
[[nodiscard]] Result<FrameHeader> decode_frame_header(ByteView in, std::uint32_t max_payload_bytes);

// The byte string covered by the authentication tag.
[[nodiscard]] Digest frame_auth_tag(ByteView session_key, const FrameHeader& header, ByteView payload);

// Sequence tracking, replay rejection, and authentication for one direction of
// one session.
class FrameCodec {
 public:
  FrameCodec() = default;

  void set_session_key(ByteView key);
  void clear_session_key();
  [[nodiscard]] bool has_session_key() const noexcept { return key_.has_value(); }

  // Builds a complete frame: header, tag, payload.
  [[nodiscard]] Result<Bytes> encode(MessageType type, std::uint8_t flags, ByteView payload,
                                     std::uint32_t max_payload_bytes);

  // Validates an already-received frame: reserved fields, authentication, and
  // sequence ordering.
  [[nodiscard]] Status verify(const FrameHeader& header, ByteView payload,
                              std::uint32_t max_payload_bytes);

  [[nodiscard]] std::uint64_t next_send_sequence() const noexcept { return send_sequence_; }
  [[nodiscard]] std::uint64_t next_expected_sequence() const noexcept { return expected_sequence_; }
  void reset_sequences() noexcept;

 private:
  std::optional<Digest> key_;
  std::uint64_t send_sequence_ = 1;
  std::uint64_t expected_sequence_ = 1;
};

// A framed conversation over one connection.
class FrameStream {
 public:
  FrameStream(TcpConnection connection, Millis io_budget_millis,
              std::uint32_t max_payload_bytes = static_cast<std::uint32_t>(1U << 20));

  [[nodiscard]] Status send(MessageType type, ByteView payload, std::uint8_t extra_flags = 0);
  [[nodiscard]] Result<Frame> receive();

  [[nodiscard]] FrameCodec& codec() noexcept { return codec_; }
  [[nodiscard]] const FrameCodec& codec() const noexcept { return codec_; }
  [[nodiscard]] TcpConnection& connection() noexcept { return connection_; }
  [[nodiscard]] const TcpConnection& connection() const noexcept { return connection_; }
  [[nodiscard]] std::uint32_t max_payload_bytes() const noexcept { return max_payload_bytes_; }
  [[nodiscard]] Millis io_budget_millis() const noexcept { return io_budget_millis_; }
  void set_io_budget_millis(Millis budget) noexcept { io_budget_millis_ = budget; }

  [[nodiscard]] Status shutdown();
  [[nodiscard]] bool is_open() const noexcept { return connection_.is_open(); }

  // Reads exactly count bytes or fails. Zero bytes read at the very start is an
  // orderly close; a short read after that is a truncation.
  [[nodiscard]] Status read_exactly(ByteSpan buffer, bool* closed_by_peer);

 private:
  TcpConnection connection_;
  FrameCodec codec_;
  Millis io_budget_millis_;
  std::uint32_t max_payload_bytes_;
};

}  // namespace smf

#endif  // SMF_FRAMING_HPP
