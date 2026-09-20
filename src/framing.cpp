// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/framing.hpp"

#include <cstring>

#include "smf/version.hpp"

namespace smf {
namespace {

constexpr char kFrameMagic[4] = {'S', 'M', 'F', '1'};
constexpr std::uint8_t kKnownFlags =
    static_cast<std::uint8_t>(FrameFlag::AUTHENTICATED) |
    static_cast<std::uint8_t>(FrameFlag::RESPONSE) | static_cast<std::uint8_t>(FrameFlag::ERROR);

void store_le(std::uint64_t value, Byte* out, std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    out[i] = static_cast<Byte>((value >> (8U * i)) & 0xFFU);
  }
}

[[nodiscard]] std::uint64_t load_le(const Byte* data, std::size_t width) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8U * i);
  }
  return value;
}

}  // namespace

const char* to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::INVALID:
      return "INVALID";
    case MessageType::HELLO:
      return "HELLO";
    case MessageType::HELLO_ACK:
      return "HELLO_ACK";
    case MessageType::HELLO_REJECT:
      return "HELLO_REJECT";
    case MessageType::REGISTER:
      return "REGISTER";
    case MessageType::REGISTER_ACK:
      return "REGISTER_ACK";
    case MessageType::ANNOUNCE_OBJECT:
      return "ANNOUNCE_OBJECT";
    case MessageType::ANNOUNCE_ACK:
      return "ANNOUNCE_ACK";
    case MessageType::HEARTBEAT:
      return "HEARTBEAT";
    case MessageType::HEARTBEAT_ACK:
      return "HEARTBEAT_ACK";
    case MessageType::GRANT_TRANSFER:
      return "GRANT_TRANSFER";
    case MessageType::GRANT_ACK:
      return "GRANT_ACK";
    case MessageType::EXECUTE_MOVEMENT:
      return "EXECUTE_MOVEMENT";
    case MessageType::ATTEMPT_RESULT:
      return "ATTEMPT_RESULT";
    case MessageType::CANCEL:
      return "CANCEL";
    case MessageType::CANCEL_ACK:
      return "CANCEL_ACK";
    case MessageType::COMMIT_REQUEST:
      return "COMMIT_REQUEST";
    case MessageType::COMMIT_RESULT:
      return "COMMIT_RESULT";
    case MessageType::VERIFY_REQUEST:
      return "VERIFY_REQUEST";
    case MessageType::VERIFY_RESPONSE:
      return "VERIFY_RESPONSE";
    case MessageType::AUTHORITY_QUERY:
      return "AUTHORITY_QUERY";
    case MessageType::AUTHORITY_REPORT:
      return "AUTHORITY_REPORT";
    case MessageType::CLEANUP_REQUEST:
      return "CLEANUP_REQUEST";
    case MessageType::CLEANUP_RESULT:
      return "CLEANUP_RESULT";
    case MessageType::DATA_BEGIN:
      return "DATA_BEGIN";
    case MessageType::DATA_BEGIN_ACK:
      return "DATA_BEGIN_ACK";
    case MessageType::DATA_CHUNK:
      return "DATA_CHUNK";
    case MessageType::DATA_CHUNK_ACK:
      return "DATA_CHUNK_ACK";
    case MessageType::DATA_END:
      return "DATA_END";
    case MessageType::DATA_RESULT:
      return "DATA_RESULT";
    case MessageType::DATA_ABORT:
      return "DATA_ABORT";
    case MessageType::SUBMIT_MOVEMENT:
      return "SUBMIT_MOVEMENT";
    case MessageType::MOVEMENT_ACCEPTED:
      return "MOVEMENT_ACCEPTED";
    case MessageType::QUERY_MOVEMENT:
      return "QUERY_MOVEMENT";
    case MessageType::MOVEMENT_STATUS:
      return "MOVEMENT_STATUS";
    case MessageType::LIST_MOVEMENTS:
      return "LIST_MOVEMENTS";
    case MessageType::MOVEMENT_LIST:
      return "MOVEMENT_LIST";
    case MessageType::CANCEL_MOVEMENT:
      return "CANCEL_MOVEMENT";
    case MessageType::RECONCILE_MOVEMENT:
      return "RECONCILE_MOVEMENT";
    case MessageType::PROVENANCE_REQUEST:
      return "PROVENANCE_REQUEST";
    case MessageType::PROVENANCE_REPORT:
      return "PROVENANCE_REPORT";
    case MessageType::TOPOLOGY_REQUEST:
      return "TOPOLOGY_REQUEST";
    case MessageType::TOPOLOGY_REPORT:
      return "TOPOLOGY_REPORT";
    case MessageType::POLICY_REQUEST:
      return "POLICY_REQUEST";
    case MessageType::POLICY_REPORT:
      return "POLICY_REPORT";
    case MessageType::SHUTDOWN:
      return "SHUTDOWN";
    case MessageType::SHUTDOWN_ACK:
      return "SHUTDOWN_ACK";
    case MessageType::ERROR:
      return "ERROR";
  }
  return "UNRECOGNIZED_MESSAGE_TYPE";
}

bool message_type_from_value(std::uint16_t value, MessageType& out) noexcept {
  if (value == 0) return false;
  if (value == 99) {
    out = MessageType::ERROR;
    return true;
  }
  if (value >= 1 && value <= 3) {
    out = static_cast<MessageType>(value);
    return true;
  }
  if (value >= 10 && value <= 15) {
    out = static_cast<MessageType>(value);
    return true;
  }
  if (value >= 20 && value <= 25) {
    out = static_cast<MessageType>(value);
    return true;
  }
  if (value >= 30 && value <= 37) {
    out = static_cast<MessageType>(value);
    return true;
  }
  if (value >= 40 && value <= 46) {
    out = static_cast<MessageType>(value);
    return true;
  }
  if (value >= 50 && value <= 65) {
    out = static_cast<MessageType>(value);
    return true;
  }
  return false;
}

bool is_handshake_message(MessageType type) noexcept {
  return type == MessageType::HELLO || type == MessageType::HELLO_ACK ||
         type == MessageType::HELLO_REJECT;
}

void encode_frame_header(const FrameHeader& header, ByteSpan out) {
  if (out.size() < kFrameHeaderBytes) return;
  std::memset(out.data(), 0, kFrameHeaderBytes);
  std::memcpy(out.data(), kFrameMagic, sizeof(kFrameMagic));
  out[4] = header.version;
  out[5] = header.flags;
  store_le(static_cast<std::uint64_t>(header.type), out.data() + 8, 2);
  store_le(header.payload_length, out.data() + 12, 4);
  store_le(header.sequence, out.data() + 16, 8);
  std::memcpy(out.data() + 24, header.auth_tag.data(), kFrameAuthTagBytes);
}

Result<FrameHeader> decode_frame_header(ByteView in, std::uint32_t max_payload_bytes) {
  if (in.size() != kFrameHeaderBytes) {
    return Status(ReasonCode::PROTOCOL_TRUNCATED, "frame header is not the fixed size");
  }
  if (std::memcmp(in.data(), kFrameMagic, sizeof(kFrameMagic)) != 0) {
    return Status(ReasonCode::PROTOCOL_MAGIC_MISMATCH, "frame magic does not match");
  }

  FrameHeader header;
  header.version = in[4];
  if (header.version != kProtocolVersion) {
    return Status(ReasonCode::PROTOCOL_VERSION_MISMATCH, "frame protocol version is not supported");
  }
  header.flags = in[5];
  if ((header.flags & static_cast<std::uint8_t>(~kKnownFlags)) != 0) {
    return Status(ReasonCode::PROTOCOL_FLAGS_INVALID, "frame carries unknown flag bits");
  }
  if (load_le(in.data() + 6, 2) != 0 || load_le(in.data() + 10, 2) != 0) {
    return Status(ReasonCode::PROTOCOL_RESERVED_NONZERO, "frame reserved fields must be zero");
  }

  const std::uint64_t raw_type = load_le(in.data() + 8, 2);
  if (raw_type > 0xFFFFU) {
    return Status(ReasonCode::PROTOCOL_MALFORMED, "frame message type is out of range");
  }
  MessageType type = MessageType::INVALID;
  if (!message_type_from_value(static_cast<std::uint16_t>(raw_type), type)) {
    return Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE, "frame message type is not recognized");
  }
  header.type = type;

  const std::uint64_t payload_length = load_le(in.data() + 12, 4);
  if (payload_length > max_payload_bytes) {
    return Status(ReasonCode::PROTOCOL_PAYLOAD_TOO_LARGE,
                  "frame declares a payload longer than the permitted bound");
  }
  header.payload_length = static_cast<std::uint32_t>(payload_length);
  header.sequence = load_le(in.data() + 16, 8);
  if (header.sequence == 0) {
    return Status(ReasonCode::PROTOCOL_CANONICAL_VIOLATION, "frame sequence numbers start at one");
  }
  // The wire tag is exactly kFrameAuthTagBytes wide. It is held in a 32-byte
  // Digest so that it travels through the same constant-time comparison as a
  // full tag, so the read must be the tag width and the remainder must stay
  // zero. Reading a full digest here would run past the fixed-size header.
  std::array<Byte, Digest::kBytes> tag{};
  std::memcpy(tag.data(), in.data() + 24, kFrameAuthTagBytes);
  header.auth_tag = Digest(tag);
  return header;
}

Digest frame_auth_tag(ByteView session_key, const FrameHeader& header, ByteView payload) {
  Bytes prefix(kFrameHeaderBytes, Byte{0});
  encode_frame_header(header, ByteSpan(prefix.data(), prefix.size()));
  HmacSha256 mac(session_key);
  mac.update(ByteView(prefix.data(), 24));
  mac.update(payload);
  return mac.finalize();
}

void FrameCodec::set_session_key(ByteView key) {
  std::array<Byte, Digest::kBytes> raw{};
  const std::size_t width = key.size() < Digest::kBytes ? key.size() : Digest::kBytes;
  for (std::size_t i = 0; i < width; ++i) raw[i] = key[i];
  key_ = Digest(raw);
}

void FrameCodec::clear_session_key() { key_.reset(); }

void FrameCodec::reset_sequences() noexcept {
  send_sequence_ = 1;
  expected_sequence_ = 1;
}

Result<Bytes> FrameCodec::encode(MessageType type, std::uint8_t flags, ByteView payload,
                                 std::uint32_t max_payload_bytes) {
  if (payload.size() > max_payload_bytes) {
    return Status(ReasonCode::PROTOCOL_PAYLOAD_TOO_LARGE, "outbound payload exceeds the frame bound");
  }
  if (is_handshake_message(type)) {
    if (key_.has_value()) {
      return Status(ReasonCode::PROTOCOL_STATE_VIOLATION,
                    "handshake messages are only exchanged before the session is keyed");
    }
  } else if (!key_.has_value()) {
    return Status(ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED,
                  "a session must be authenticated before any other message is sent");
  }

  FrameHeader header;
  header.version = kProtocolVersion;
  header.flags = flags;
  header.type = type;
  header.payload_length = static_cast<std::uint32_t>(payload.size());
  header.sequence = send_sequence_;

  if (key_.has_value()) {
    header.flags = static_cast<std::uint8_t>(header.flags |
                                             static_cast<std::uint8_t>(FrameFlag::AUTHENTICATED));
    header.auth_tag = frame_auth_tag(key_->view(), header, payload);
  }

  Bytes frame(kFrameHeaderBytes + payload.size());
  encode_frame_header(header, ByteSpan(frame.data(), kFrameHeaderBytes));
  if (!payload.empty()) {
    std::memcpy(frame.data() + kFrameHeaderBytes, payload.data(), payload.size());
  }
  ++send_sequence_;
  return frame;
}

Status FrameCodec::verify(const FrameHeader& header, ByteView payload, std::uint32_t max_payload_bytes) {
  if (payload.size() > max_payload_bytes) {
    return Status(ReasonCode::PROTOCOL_PAYLOAD_TOO_LARGE, "received payload exceeds the frame bound");
  }
  if (payload.size() != header.payload_length) {
    return Status(ReasonCode::PROTOCOL_TRUNCATED,
                  "received payload length does not match the declared length");
  }

  const bool authenticated =
      (header.flags & static_cast<std::uint8_t>(FrameFlag::AUTHENTICATED)) != 0;
  if (is_handshake_message(header.type)) {
    if (authenticated) {
      return Status(ReasonCode::PROTOCOL_STATE_VIOLATION,
                    "handshake messages must not be marked authenticated");
    }
  } else {
    if (!authenticated) {
      return Status(ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED,
                    "unauthenticated frame arrived outside the handshake");
    }
    if (!key_.has_value()) {
      return Status(ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED,
                    "authenticated frame arrived before the session key was established");
    }
    const Digest expected = frame_auth_tag(key_->view(), header, payload);
    if (!constant_time_equal(ByteView(expected.data(), kFrameAuthTagBytes),
                             ByteView(header.auth_tag.data(), kFrameAuthTagBytes))) {
      return Status(ReasonCode::PROTOCOL_AUTH_FAILED, "frame authentication tag did not verify");
    }
  }

  if (header.sequence < expected_sequence_) {
    return Status(ReasonCode::PROTOCOL_SEQUENCE_REPLAY,
                  "frame sequence number has already been consumed");
  }
  if (header.sequence > expected_sequence_) {
    return Status(ReasonCode::PROTOCOL_SEQUENCE_REGRESSION,
                  "frame sequence number skipped ahead of the expected value");
  }
  ++expected_sequence_;
  return Status::success();
}

FrameStream::FrameStream(TcpConnection connection, Millis io_budget_millis,
                         std::uint32_t max_payload_bytes)
    : connection_(std::move(connection)),
      io_budget_millis_(io_budget_millis),
      max_payload_bytes_(max_payload_bytes) {}

Status FrameStream::read_exactly(ByteSpan buffer, bool* closed_by_peer) {
  if (closed_by_peer != nullptr) *closed_by_peer = false;
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const auto received =
        connection_.receive_some(ByteSpan(buffer.data() + offset, buffer.size() - offset),
                                 io_budget_millis_);
    if (!received.ok()) return received.status();
    if (received.value() == 0) {
      if (offset == 0) {
        if (closed_by_peer != nullptr) *closed_by_peer = true;
        return Status(ReasonCode::CONNECTION_CLOSED, "peer closed the connection");
      }
      return Status(ReasonCode::PROTOCOL_TRUNCATED, "connection closed mid-frame");
    }
    offset += received.value();
  }
  return Status::success();
}

Status FrameStream::send(MessageType type, ByteView payload, std::uint8_t extra_flags) {
  const auto frame = codec_.encode(type, extra_flags, payload, max_payload_bytes_);
  if (!frame.ok()) return frame.status();
  return connection_.send_all(smf::as_bytes(frame.value()), io_budget_millis_);
}

Result<Frame> FrameStream::receive() {
  Bytes header_bytes(kFrameHeaderBytes);
  bool peer_closed = false;
  const Status header_status =
      read_exactly(ByteSpan(header_bytes.data(), header_bytes.size()), &peer_closed);
  if (!header_status.ok()) {
    if (peer_closed) {
      return Status(ReasonCode::CONNECTION_CLOSED, "peer closed the connection");
    }
    return header_status;
  }

  const auto header = decode_frame_header(smf::as_bytes(header_bytes), max_payload_bytes_);
  if (!header.ok()) return header.status();

  Frame frame;
  frame.header = header.value();
  frame.payload.resize(frame.header.payload_length);
  if (!frame.payload.empty()) {
    const Status payload_status =
        read_exactly(ByteSpan(frame.payload.data(), frame.payload.size()), &peer_closed);
    if (!payload_status.ok()) return payload_status;
  }

  const Status verified = codec_.verify(frame.header, smf::as_bytes(frame.payload), max_payload_bytes_);
  if (!verified.ok()) return verified;
  return frame;
}

Status FrameStream::shutdown() { return connection_.shutdown(); }

}  // namespace smf
