// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/transport.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace smf {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNativeSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNativeSocket = -1;
#endif

std::once_flag g_socket_once;
Status g_socket_status = Status::success();
bool g_socket_ready = false;

void close_native(NativeSocket socket) noexcept {
  if (socket == kInvalidNativeSocket) return;
#if defined(_WIN32)
  ::closesocket(socket);
#else
  ::close(socket);
#endif
}

[[nodiscard]] bool would_block() noexcept {
#if defined(_WIN32)
  const int error = WSAGetLastError();
  return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
  return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS;
#endif
}

[[nodiscard]] ReasonCode classify_socket_error() noexcept {
#if defined(_WIN32)
  switch (WSAGetLastError()) {
    case WSAECONNREFUSED:
      return ReasonCode::CONNECTION_REFUSED;
    case WSAECONNRESET:
      return ReasonCode::CONNECTION_RESET;
    case WSAECONNABORTED:
      return ReasonCode::CONNECTION_RESET;
    case WSAETIMEDOUT:
      return ReasonCode::IO_TIMEOUT;
    case WSAENETUNREACH:
    case WSAENETDOWN:
    case WSAEHOSTUNREACH:
      return ReasonCode::NETWORK_UNAVAILABLE;
    case WSAEADDRINUSE:
      return ReasonCode::BIND_FAILED;
    case WSAEADDRNOTAVAIL:
      return ReasonCode::ADDRESS_INVALID;
    default:
      return ReasonCode::IO_ERROR;
  }
#else
  switch (errno) {
    case ECONNREFUSED:
      return ReasonCode::CONNECTION_REFUSED;
    case ECONNRESET:
    case ECONNABORTED:
      return ReasonCode::CONNECTION_RESET;
    case ETIMEDOUT:
      return ReasonCode::IO_TIMEOUT;
    case ENETUNREACH:
    case ENETDOWN:
    case EHOSTUNREACH:
      return ReasonCode::NETWORK_UNAVAILABLE;
    case EADDRINUSE:
      return ReasonCode::BIND_FAILED;
    case EADDRNOTAVAIL:
      return ReasonCode::ADDRESS_INVALID;
    default:
      return ReasonCode::IO_ERROR;
  }
#endif
}

void set_non_blocking(NativeSocket socket) noexcept {
#if defined(_WIN32)
  u_long mode = 1;
  (void)ioctlsocket(socket, FIONBIO, &mode);
#else
  const int flags = ::fcntl(socket, F_GETFL, 0);
  if (flags >= 0) (void)::fcntl(socket, F_SETFL, flags | O_NONBLOCK);
#endif
}

void set_option(NativeSocket socket, int level, int name, int value) noexcept {
#if defined(_WIN32)
  (void)setsockopt(socket, level, name, reinterpret_cast<const char*>(&value), sizeof(value));
#else
  (void)setsockopt(socket, level, name, &value, sizeof(value));
#endif
}

// Polls one socket for readiness. Returns 1 when ready, 0 on timeout, -1 on
// error. A negative timeout means "wait indefinitely".
[[nodiscard]] int poll_socket(NativeSocket socket, bool for_read, int timeout_millis) noexcept {
#if defined(_WIN32)
  WSAPOLLFD entry{};
  entry.fd = socket;
  entry.events = static_cast<short>(for_read ? POLLRDNORM : POLLWRNORM);
  const int result = WSAPoll(&entry, 1, timeout_millis);
  if (result <= 0) return result;
  if ((entry.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (entry.revents & entry.events) == 0) {
    return 1;  // report readable/writable so the caller observes the real error
  }
  return (entry.revents & entry.events) != 0 ? 1 : 0;
#else
  struct pollfd entry{};
  entry.fd = socket;
  entry.events = static_cast<short>(for_read ? POLLIN : POLLOUT);
  const int result = ::poll(&entry, 1, timeout_millis);
  if (result <= 0) return result;
  return (entry.revents & static_cast<short>(entry.events)) != 0 ? 1 : 1;
#endif
}

[[nodiscard]] SocketAddress from_sockaddr(const sockaddr* address) {
  SocketAddress out;
  char host[INET6_ADDRSTRLEN] = {};
  if (address->sa_family == AF_INET) {
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
    (void)inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host));
    out.port = ntohs(v4->sin_port);
  } else if (address->sa_family == AF_INET6) {
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
    (void)inet_ntop(AF_INET6, &v6->sin6_addr, host, sizeof(host));
    out.port = ntohs(v6->sin6_port);
  }
  out.host = host;
  return out;
}

// Resolves a host into a sockaddr_storage. IPv4 and IPv6 literals are handled
// without a name lookup so that a loopback proof never depends on DNS.
[[nodiscard]] Status resolve(const std::string& host, std::uint16_t port, bool passive,
                             sockaddr_storage& storage, int& length) {
  std::memset(&storage, 0, sizeof(storage));
  length = 0;

  if (host.empty()) {
    auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    v4->sin_port = htons(port);
    length = static_cast<int>(sizeof(sockaddr_in));
    return Status::success();
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = passive ? AI_PASSIVE : 0;

  addrinfo* result = nullptr;
  const std::string port_text = std::to_string(port);
  const int status = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result);
  if (status != 0 || result == nullptr) {
    return Status(ReasonCode::ADDRESS_INVALID, "host could not be resolved: " + host);
  }
  std::memcpy(&storage, result->ai_addr, static_cast<std::size_t>(result->ai_addrlen));
  length = static_cast<int>(result->ai_addrlen);
  ::freeaddrinfo(result);
  if (length <= 0) {
    return Status(ReasonCode::ADDRESS_INVALID, "resolved address has no length");
  }
  return Status::success();
}

[[nodiscard]] Millis remaining_budget(Millis deadline) {
  const Millis now = system_clock().monotonic_millis();
  if (now >= deadline) return 0;
  return deadline - now;
}

}  // namespace

Status ensure_socket_runtime() {
  std::call_once(g_socket_once, []() {
#if defined(_WIN32)
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      g_socket_status = Status(ReasonCode::NETWORK_UNAVAILABLE, "WSAStartup failed");
      g_socket_ready = false;
      return;
    }
#endif
    g_socket_status = Status::success();
    g_socket_ready = true;
  });
  if (!g_socket_ready) return g_socket_status;
  return Status::success();
}

Result<SocketAddress> SocketAddress::parse(std::string_view text) {
  if (text.empty()) {
    return Status(ReasonCode::ADDRESS_INVALID, "address must not be empty");
  }
  for (const char c : text) {
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      return Status(ReasonCode::ADDRESS_INVALID, "address must not contain whitespace");
    }
  }

  std::string host;
  std::string port_text;

  if (text.front() == '[') {
    const std::size_t closing = text.find(']');
    if (closing == std::string_view::npos) {
      return Status(ReasonCode::ADDRESS_INVALID, "bracketed address is missing ']'");
    }
    host = std::string(text.substr(1, closing - 1));
    if (closing + 1 >= text.size() || text[closing + 1] != ':') {
      return Status(ReasonCode::ADDRESS_INVALID, "bracketed address is missing a port");
    }
    port_text = std::string(text.substr(closing + 2));
  } else {
    const std::size_t colon = text.rfind(':');
    if (colon == std::string_view::npos) {
      return Status(ReasonCode::ADDRESS_INVALID, "address must be host:port");
    }
    host = std::string(text.substr(0, colon));
    port_text = std::string(text.substr(colon + 1));
    if (host.find(':') != std::string::npos) {
      return Status(ReasonCode::ADDRESS_INVALID, "an IPv6 literal must be enclosed in brackets");
    }
  }

  if (port_text.empty()) {
    return Status(ReasonCode::ADDRESS_INVALID, "address must carry a port");
  }
  std::uint32_t port = 0;
  for (const char c : port_text) {
    if (c < '0' || c > '9') {
      return Status(ReasonCode::ADDRESS_INVALID, "port must be numeric");
    }
    port = (port * 10U) + static_cast<std::uint32_t>(c - '0');
    if (port > 65535U) {
      return Status(ReasonCode::ADDRESS_INVALID, "port is out of range");
    }
  }
  // Port zero is a valid request: it asks the operating system to choose an
  // ephemeral port when binding. Whether it is usable depends on the operation,
  // so the check lives in connect() rather than here.
  SocketAddress out;
  out.host = host;
  out.port = static_cast<std::uint16_t>(port);
  return out;
}

Result<SocketAddress> SocketAddress::loopback(std::uint16_t port) {
  SocketAddress out;
  out.host = "127.0.0.1";
  out.port = port;
  return out;
}

std::string SocketAddress::to_string() const {
  if (host.find(':') != std::string::npos) {
    return "[" + host + "]:" + std::to_string(port);
  }
  if (host.empty()) {
    return "127.0.0.1:" + std::to_string(port);
  }
  return host + ":" + std::to_string(port);
}

struct TcpConnection::State {
  NativeSocket socket = kInvalidNativeSocket;
  std::atomic<bool> closed{false};
  std::mutex mutex;

  ~State() {
    std::lock_guard<std::mutex> lock(mutex);
    if (socket != kInvalidNativeSocket) {
      close_native(socket);
      socket = kInvalidNativeSocket;
    }
  }
};

TcpConnection::~TcpConnection() = default;
TcpConnection::TcpConnection(const TcpConnection&) noexcept = default;
TcpConnection& TcpConnection::operator=(const TcpConnection&) noexcept = default;
TcpConnection::TcpConnection(TcpConnection&& other) noexcept
    : state_(std::move(other.state_)),
      peer_(std::move(other.peer_)),
      local_(std::move(other.local_)) {}
TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
  if (this != &other) {
    state_ = std::move(other.state_);
    peer_ = std::move(other.peer_);
    local_ = std::move(other.local_);
  }
  return *this;
}

bool TcpConnection::is_open() const noexcept {
  return state_ != nullptr && !state_->closed.load(std::memory_order_acquire) &&
         state_->socket != kInvalidNativeSocket;
}

Result<TcpConnection> TcpConnection::connect(const SocketAddress& address, Millis budget_millis) {
  if (address.port == 0) {
    return Status(ReasonCode::ADDRESS_INVALID, "port zero cannot be connected to");
  }
  SMF_RETURN_IF_ERROR(ensure_socket_runtime());

  sockaddr_storage storage{};
  int length = 0;
  SMF_RETURN_IF_ERROR(resolve(address.host, address.port, false, storage, length));
  if (length <= 0) {
    return Status(ReasonCode::ADDRESS_INVALID, "address could not be resolved");
  }

  const NativeSocket socket =
      ::socket(reinterpret_cast<sockaddr*>(&storage)->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidNativeSocket) {
    return Status(classify_socket_error(), "socket creation failed");
  }
  set_non_blocking(socket);

  const Millis deadline = system_clock().monotonic_millis() + budget_millis;
  const int connected = ::connect(socket, reinterpret_cast<sockaddr*>(&storage), length);
  if (connected != 0) {
    if (!would_block()) {
      const ReasonCode code = classify_socket_error();
      close_native(socket);
      return Status(code, "connect failed");
    }
    for (;;) {
      const Millis remaining = remaining_budget(deadline);
      if (remaining <= 0) {
        close_native(socket);
        return Status(ReasonCode::IO_TIMEOUT, "connect timed out");
      }
      const int slice = static_cast<int>(std::min<Millis>(remaining, 50));
      const int ready = poll_socket(socket, false, slice);
      if (ready < 0) {
        const ReasonCode code = classify_socket_error();
        close_native(socket);
        return Status(code, "poll during connect failed");
      }
      if (ready == 0) continue;

      int socket_error = 0;
#if defined(_WIN32)
      int option_length = static_cast<int>(sizeof(socket_error));
      if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error),
                     &option_length) != 0) {
#else
      socklen_t option_length = sizeof(socket_error);
      if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &socket_error, &option_length) != 0) {
#endif
        close_native(socket);
        return Status(ReasonCode::IO_ERROR, "could not read the connect result");
      }
      if (socket_error != 0) {
        close_native(socket);
#if defined(_WIN32)
        WSASetLastError(socket_error);
#else
        errno = socket_error;
#endif
        return Status(classify_socket_error(), "connect failed");
      }
      break;
    }
  }

  TcpConnection connection;
  connection.state_ = std::make_shared<State>();
  connection.state_->socket = socket;
  set_option(socket, IPPROTO_TCP, TCP_NODELAY, 1);

  sockaddr_storage local{};
#if defined(_WIN32)
  int local_length = static_cast<int>(sizeof(local));
#else
  socklen_t local_length = sizeof(local);
#endif
  if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &local_length) == 0) {
    connection.local_ = from_sockaddr(reinterpret_cast<sockaddr*>(&local));
  }
  connection.peer_ = address;
  return connection;
}

Result<TcpConnection> TcpConnection::adopt(void* native_handle, SocketAddress peer) {
  if (native_handle == nullptr) {
    return Status(ReasonCode::INVALID_ARGUMENT, "no native handle supplied");
  }
  TcpConnection connection;
  connection.state_ = std::make_shared<State>();
#if defined(_WIN32)
  connection.state_->socket = reinterpret_cast<NativeSocket>(native_handle);
#else
  connection.state_->socket = static_cast<NativeSocket>(reinterpret_cast<std::intptr_t>(native_handle));
#endif
  connection.peer_ = std::move(peer);
  set_non_blocking(connection.state_->socket);
  set_option(connection.state_->socket, IPPROTO_TCP, TCP_NODELAY, 1);
  return connection;
}

Status TcpConnection::send_all(ByteView data, Millis budget_millis) {
  if (state_ == nullptr) {
    return Status(ReasonCode::CONNECTION_CLOSED, "connection was never established");
  }
  const Millis deadline = system_clock().monotonic_millis() + budget_millis;
  std::size_t offset = 0;
  while (offset < data.size()) {
    if (state_->closed.load(std::memory_order_acquire)) {
      return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
    }
    const std::size_t remaining = data.size() - offset;
    const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 1U << 20));
#if defined(_WIN32)
    const int written = ::send(state_->socket, reinterpret_cast<const char*>(data.data() + offset),
                               chunk, 0);
#else
    const ssize_t written = ::send(state_->socket, data.data() + offset, static_cast<std::size_t>(chunk),
                                   MSG_NOSIGNAL);
#endif
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written == 0) {
      return Status(ReasonCode::CONNECTION_CLOSED, "peer closed during send");
    }
    if (!would_block()) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
      }
      return Status(classify_socket_error(), "send failed");
    }
    const Millis left = remaining_budget(deadline);
    if (left <= 0) {
      return Status(ReasonCode::IO_TIMEOUT, "send timed out");
    }
    const int slice = static_cast<int>(std::min<Millis>(left, 50));
    const int ready = poll_socket(state_->socket, false, slice);
    if (ready < 0) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
      }
      return Status(classify_socket_error(), "poll during send failed");
    }
  }
  return Status::success();
}

Result<std::size_t> TcpConnection::receive_some(ByteSpan buffer, Millis budget_millis) {
  if (state_ == nullptr) {
    return Status(ReasonCode::CONNECTION_CLOSED, "connection was never established");
  }
  if (buffer.empty()) return std::size_t{0};

  const Millis deadline = system_clock().monotonic_millis() + budget_millis;
  for (;;) {
    if (state_->closed.load(std::memory_order_acquire)) {
      return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
    }
    const int chunk = static_cast<int>(std::min<std::size_t>(buffer.size(), 1U << 20));
#if defined(_WIN32)
    const int received = ::recv(state_->socket, reinterpret_cast<char*>(buffer.data()), chunk, 0);
#else
    const ssize_t received = ::recv(state_->socket, buffer.data(), static_cast<std::size_t>(chunk), 0);
#endif
    if (received > 0) return static_cast<std::size_t>(received);
    if (received == 0) return std::size_t{0};  // orderly close by the peer
    if (!would_block()) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
      }
      return Status(classify_socket_error(), "receive failed");
    }
    const Millis left = remaining_budget(deadline);
    if (left <= 0) {
      return Status(ReasonCode::IO_TIMEOUT, "receive timed out");
    }
    const int slice = static_cast<int>(std::min<Millis>(left, 50));
    const int ready = poll_socket(state_->socket, true, slice);
    if (ready < 0) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::CONNECTION_CLOSED, "connection was shut down locally");
      }
      return Status(classify_socket_error(), "poll during receive failed");
    }
  }
}

Status TcpConnection::shutdown() {
  if (state_ == nullptr) {
    return Status(ReasonCode::CONNECTION_CLOSED, "connection was never established");
  }
  std::lock_guard<std::mutex> lock(state_->mutex);
  state_->closed.store(true, std::memory_order_release);
  if (state_->socket == kInvalidNativeSocket) {
    return Status(ReasonCode::CONNECTION_CLOSED, "connection is already closed");
  }
#if defined(_WIN32)
  (void)::shutdown(state_->socket, SD_BOTH);
#else
  (void)::shutdown(state_->socket, SHUT_RDWR);
#endif
  return Status::success();
}

void TcpConnection::close() noexcept { state_.reset(); }

void TcpConnection::set_no_delay(bool enabled) noexcept {
  if (state_ == nullptr || state_->socket == kInvalidNativeSocket) return;
  set_option(state_->socket, IPPROTO_TCP, TCP_NODELAY, enabled ? 1 : 0);
}

void TcpConnection::set_keep_alive(bool enabled) noexcept {
  if (state_ == nullptr || state_->socket == kInvalidNativeSocket) return;
  set_option(state_->socket, SOL_SOCKET, SO_KEEPALIVE, enabled ? 1 : 0);
}

struct TcpListener::State {
  NativeSocket socket = kInvalidNativeSocket;
  std::atomic<bool> closed{false};
  std::mutex mutex;

  ~State() {
    std::lock_guard<std::mutex> lock(mutex);
    if (socket != kInvalidNativeSocket) {
      close_native(socket);
      socket = kInvalidNativeSocket;
    }
  }
};

TcpListener::~TcpListener() = default;
TcpListener::TcpListener(TcpListener&& other) noexcept
    : state_(std::move(other.state_)), address_(std::move(other.address_)) {}
TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    state_ = std::move(other.state_);
    address_ = std::move(other.address_);
  }
  return *this;
}

Result<TcpListener> TcpListener::bind(const SocketAddress& address) {
  SMF_RETURN_IF_ERROR(ensure_socket_runtime());

  sockaddr_storage storage{};
  int length = 0;
  SMF_RETURN_IF_ERROR(resolve(address.host, address.port, true, storage, length));
  if (length <= 0) {
    return Status(ReasonCode::ADDRESS_INVALID, "bind address could not be resolved");
  }

  const NativeSocket socket =
      ::socket(reinterpret_cast<sockaddr*>(&storage)->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (socket == kInvalidNativeSocket) {
    return Status(classify_socket_error(), "listener socket creation failed");
  }
  set_option(socket, SOL_SOCKET, SO_REUSEADDR, 1);

  if (::bind(socket, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
    const ReasonCode code = classify_socket_error();
    close_native(socket);
    return Status(code, "bind failed for " + address.to_string());
  }
  if (::listen(socket, 64) != 0) {
    const ReasonCode code = classify_socket_error();
    close_native(socket);
    return Status(code == ReasonCode::IO_ERROR ? ReasonCode::LISTEN_FAILED : code, "listen failed");
  }
  set_non_blocking(socket);

  TcpListener listener;
  listener.state_ = std::make_shared<State>();
  listener.state_->socket = socket;

  sockaddr_storage bound{};
#if defined(_WIN32)
  int bound_length = static_cast<int>(sizeof(bound));
#else
  socklen_t bound_length = sizeof(bound);
#endif
  if (getsockname(socket, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
    listener.address_ = from_sockaddr(reinterpret_cast<sockaddr*>(&bound));
  } else {
    listener.address_ = address;
  }
  return listener;
}

Result<TcpConnection> TcpListener::accept(Millis budget_millis) {
  if (state_ == nullptr) {
    return Status(ReasonCode::SHUTTING_DOWN, "listener was never bound");
  }
  const Millis deadline = system_clock().monotonic_millis() + budget_millis;
  for (;;) {
    if (state_->closed.load(std::memory_order_acquire)) {
      return Status(ReasonCode::SHUTTING_DOWN, "listener was closed");
    }

    sockaddr_storage peer{};
#if defined(_WIN32)
    int peer_length = static_cast<int>(sizeof(peer));
#else
    socklen_t peer_length = sizeof(peer);
#endif
    const NativeSocket accepted =
        ::accept(state_->socket, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (accepted != kInvalidNativeSocket) {
      // adopt() performs the non-blocking and TCP_NODELAY configuration and
      // owns the descriptor from here on.
      auto connection = TcpConnection::adopt(
#if defined(_WIN32)
          reinterpret_cast<void*>(accepted),
#else
          reinterpret_cast<void*>(static_cast<std::intptr_t>(accepted)),
#endif
          from_sockaddr(reinterpret_cast<sockaddr*>(&peer)));
      if (!connection.ok()) {
        close_native(accepted);
        return connection.status();
      }
      return connection;
    }

    if (!would_block()) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::SHUTTING_DOWN, "listener was closed");
      }
      return Status(classify_socket_error(), "accept failed");
    }

    const Millis left = remaining_budget(deadline);
    if (left <= 0) {
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::SHUTTING_DOWN, "listener was closed");
      }
      return Status(ReasonCode::IO_TIMEOUT, "no inbound connection arrived within the budget");
    }
    // Short slices so that close() from another thread is observed promptly.
    const int slice = static_cast<int>(std::min<Millis>(left, 50));
    const int ready = poll_socket(state_->socket, true, slice);
    if (ready < 0) {
      // Closing the descriptor underneath a blocked accept surfaces here as a
      // poll failure; the local shutdown is the real cause.
      if (state_->closed.load(std::memory_order_acquire)) {
        return Status(ReasonCode::SHUTTING_DOWN, "listener was closed");
      }
      return Status(classify_socket_error(), "poll during accept failed");
    }
  }
}

Status TcpListener::close() {
  if (state_ == nullptr) {
    return Status(ReasonCode::SHUTTING_DOWN, "listener was never bound");
  }
  std::lock_guard<std::mutex> lock(state_->mutex);
  state_->closed.store(true, std::memory_order_release);
  if (state_->socket == kInvalidNativeSocket) {
    return Status(ReasonCode::SHUTTING_DOWN, "listener is already closed");
  }
#if defined(_WIN32)
  (void)::shutdown(state_->socket, SD_BOTH);
#else
  (void)::shutdown(state_->socket, SHUT_RDWR);
#endif
  close_native(state_->socket);
  state_->socket = kInvalidNativeSocket;
  return Status::success();
}

bool TcpListener::is_open() const noexcept {
  return state_ != nullptr && !state_->closed.load(std::memory_order_acquire) &&
         state_->socket != kInvalidNativeSocket;
}

ReasonCode last_socket_error_code() noexcept { return classify_socket_error(); }

}  // namespace smf
