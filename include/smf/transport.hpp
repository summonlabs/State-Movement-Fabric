// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Platform socket layer.
//
// Design rules that the rest of the runtime depends on:
//   * sockets are non-blocking and every operation has an explicit budget, so
//     no read, write, or accept can block forever;
//   * a connection or listener can be closed from another thread, and doing so
//     releases any thread currently blocked in that operation instead of
//     leaving it stranded;
//   * nothing here allocates on behalf of a peer: receive_some() fills a caller
//     supplied bounded buffer and reports exactly how many bytes arrived;
//   * every failure maps to a deterministic ReasonCode, never to a bare bool.

#ifndef SMF_TRANSPORT_HPP
#define SMF_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "smf/bytes.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"

namespace smf {

// One-time process-wide socket subsystem initialisation. Safe to call from any
// thread at any time; the underlying initialisation happens exactly once.
[[nodiscard]] Status ensure_socket_runtime();

struct SocketAddress {
  std::string host;         // dotted quad or IPv6 literal
  std::uint16_t port = 0;

  // Accepts "host:port", "[v6host]:port", and ":port" (which means the IPv4
  // loopback). Rejects empty hosts other than the ":" form, ports outside
  // 1..65535, and any non-numeric port.
  [[nodiscard]] static Result<SocketAddress> parse(std::string_view text);
  [[nodiscard]] static Result<SocketAddress> loopback(std::uint16_t port);
  [[nodiscard]] std::string to_string() const;
};

// Reference-counted socket handle. A TcpConnection copy shares the descriptor,
// which is what lets a shutdown thread release a blocked reader without
// closing the descriptor out from under it.
class TcpConnection {
 public:
  TcpConnection() noexcept = default;
  ~TcpConnection();
  TcpConnection(const TcpConnection&) noexcept;
  TcpConnection& operator=(const TcpConnection&) noexcept;
  TcpConnection(TcpConnection&& other) noexcept;
  TcpConnection& operator=(TcpConnection&& other) noexcept;

  [[nodiscard]] static Result<TcpConnection> connect(const SocketAddress& address,
                                                     Millis budget_millis);
  [[nodiscard]] static Result<TcpConnection> adopt(void* native_handle, SocketAddress peer);

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] const SocketAddress& peer() const noexcept { return peer_; }
  [[nodiscard]] const SocketAddress& local() const noexcept { return local_; }

  // Writes the whole buffer or fails. Partial progress is never reported as
  // success: a partial write leaves the stream position undefined, so the
  // caller must treat any failure as fatal for this connection.
  [[nodiscard]] Status send_all(ByteView data, Millis budget_millis);

  // Reads whatever is available, up to buffer.size(). Returns the number of
  // bytes read; zero means the peer performed an orderly close. A budget of
  // zero polls once without waiting.
  [[nodiscard]] Result<std::size_t> receive_some(ByteSpan buffer, Millis budget_millis);

  // Unblocks any thread currently inside send_all() or receive_some() by
  // shutting the socket down in both directions. The descriptor stays valid
  // until the last reference is released, so the unblocked reader observes a
  // clean CONNECTION_CLOSED rather than a use-after-free.
  [[nodiscard]] Status shutdown();

  // Final release of this reference. Safe to call more than once.
  void close() noexcept;

  void set_no_delay(bool enabled) noexcept;
  void set_keep_alive(bool enabled) noexcept;

 private:
  struct State;
  std::shared_ptr<State> state_;
  SocketAddress peer_;
  SocketAddress local_;
};

class TcpListener {
 public:
  TcpListener() noexcept = default;
  ~TcpListener();
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;

  [[nodiscard]] static Result<TcpListener> bind(const SocketAddress& address);

  // Waits up to budget_millis for an inbound connection. Returns IO_TIMEOUT
  // when none arrived in the budget; the listener stays usable.
  [[nodiscard]] Result<TcpConnection> accept(Millis budget_millis);

  // Releases any thread blocked in accept().
  [[nodiscard]] Status close();

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] const SocketAddress& address() const noexcept { return address_; }

 private:
  struct State;
  std::shared_ptr<State> state_;
  SocketAddress address_;
};

// Last socket-level error on this thread, translated to a reason code.
[[nodiscard]] ReasonCode last_socket_error_code() noexcept;

}  // namespace smf

#endif  // SMF_TRANSPORT_HPP
