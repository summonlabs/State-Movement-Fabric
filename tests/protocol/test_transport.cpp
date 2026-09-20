// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Proof obligations for the socket layer: real loopback TCP inside this
// process. The independent-operating-system-process proofs live in
// tests/multiprocess.

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "smf/digest.hpp"
#include "smf/transport.hpp"
#include "smf_test.hpp"

using smf::ByteSpan;
using smf::ByteView;
using smf::Bytes;
using smf::ReasonCode;
using smf::SocketAddress;
using smf::TcpConnection;
using smf::TcpListener;

namespace {

constexpr smf::Millis kBudget = 5000;

// Fails the enclosing proof with the exact reason code instead of throwing an
// exception type that would hide the cause.
template <class T>
[[nodiscard]] T unwrap(smf::Result<T> result) {
  if (!result.ok()) {
    smftest::fail(__FILE__, __LINE__, "unexpected failure: " + result.status().to_string());
  }
  return std::move(result).value();
}

void send_fully(TcpConnection& connection, ByteView payload) {
  const smf::Status status = connection.send_all(payload, kBudget);
  if (!status.ok()) {
    smftest::fail(__FILE__, __LINE__, "send_all failed: " + status.to_string());
  }
}

[[nodiscard]] Bytes receive_exactly(TcpConnection& connection, std::size_t count) {
  Bytes out(count);
  std::size_t offset = 0;
  while (offset < count) {
    const auto received =
        connection.receive_some(ByteSpan(out.data() + offset, count - offset), kBudget);
    if (!received.ok()) {
      smftest::fail(__FILE__, __LINE__, "receive_some failed: " + received.status().to_string());
    }
    if (received.value() == 0) {
      smftest::fail(__FILE__, __LINE__, "peer closed before the expected bytes arrived");
    }
    offset += received.value();
  }
  return out;
}

struct Pair {
  TcpListener listener;
  TcpConnection server;
  TcpConnection client;
};

// Binds an ephemeral port, connects a client, and accepts on a helper thread so
// that a single-threaded proof still exercises a real handshake.
[[nodiscard]] Pair make_pair() {
  const SocketAddress address = unwrap(SocketAddress::loopback(0));
  Pair pair;
  pair.listener = unwrap(TcpListener::bind(address));
  const SocketAddress bound = pair.listener.address();
  if (bound.port == 0) {
    smftest::fail(__FILE__, __LINE__, "bound listener reported port zero");
  }

  TcpConnection accepted;
  std::thread acceptor([&]() {
    auto result = pair.listener.accept(kBudget);
    if (result.ok()) accepted = std::move(result).value();
  });

  auto client = TcpConnection::connect(bound, kBudget);
  acceptor.join();
  if (!client.ok()) {
    smftest::fail(__FILE__, __LINE__, "client connect failed: " + client.status().to_string());
  }
  if (!accepted.is_open()) {
    smftest::fail(__FILE__, __LINE__, "server side did not accept the connection");
  }
  pair.server = std::move(accepted);
  pair.client = std::move(client).value();
  return pair;
}

}  // namespace

SMF_TEST(transport, address_parsing) {
  const SocketAddress plain = unwrap(SocketAddress::parse("127.0.0.1:8080"));
  SMF_CHECK_EQ(plain.host, std::string("127.0.0.1"));
  SMF_CHECK_EQ(plain.port, std::uint16_t{8080});
  SMF_CHECK_EQ(plain.to_string(), std::string("127.0.0.1:8080"));

  const SocketAddress v6 = unwrap(SocketAddress::parse("[::1]:9000"));
  SMF_CHECK_EQ(v6.host, std::string("::1"));
  SMF_CHECK_EQ(v6.port, std::uint16_t{9000});
  SMF_CHECK_EQ(v6.to_string(), std::string("[::1]:9000"));

  const SocketAddress loopback_default = unwrap(SocketAddress::parse(":1234"));
  SMF_CHECK_EQ(loopback_default.host, std::string(""));
  SMF_CHECK_EQ(loopback_default.to_string(), std::string("127.0.0.1:1234"));

  // Port zero asks the operating system for an ephemeral port when binding, so
  // the parser accepts it; connecting to it is what is refused.
  const SocketAddress ephemeral = unwrap(SocketAddress::parse("127.0.0.1:0"));
  SMF_CHECK_EQ(ephemeral.port, std::uint16_t{0});

  for (const char* candidate :
       {"", "127.0.0.1", "127.0.0.1:", "127.0.0.1:65536", "127.0.0.1:abc", "::1:80",
        " 127.0.0.1:80", "[::1:80", "host name:80"}) {
    SMF_CHECK_CODE(SocketAddress::parse(candidate), ReasonCode::ADDRESS_INVALID);
  }
}

SMF_TEST(transport, loopback_round_trip) {
  Pair pair = make_pair();

  const std::string message = "state movement fabric";
  send_fully(pair.client, smf::as_bytes(message));
  const Bytes received = receive_exactly(pair.server, message.size());
  SMF_CHECK_EQ(smf::as_string_view(smf::as_bytes(received)), std::string_view(message));

  const std::string reply = "ack";
  send_fully(pair.server, smf::as_bytes(reply));
  const Bytes reply_bytes = receive_exactly(pair.client, reply.size());
  SMF_CHECK_EQ(smf::as_string_view(smf::as_bytes(reply_bytes)), std::string_view(reply));
}

SMF_TEST(transport, large_transfer_preserves_bytes) {
  Pair pair = make_pair();

  smftest::Rng rng(0xFAB1CULL);
  const Bytes payload = rng.bytes(4U * 1024U * 1024U);
  const smf::Digest expected = smf::sha256(smf::as_bytes(payload));

  std::thread sender([&]() { send_fully(pair.client, smf::as_bytes(payload)); });
  const Bytes received = receive_exactly(pair.server, payload.size());
  sender.join();

  SMF_CHECK_EQ(received.size(), payload.size());
  SMF_CHECK_EQ(smf::sha256(smf::as_bytes(received)), expected);
}

SMF_TEST(transport, idle_accept_times_out_and_listener_survives) {
  TcpListener server = unwrap(TcpListener::bind(unwrap(SocketAddress::loopback(0))));

  const auto first = server.accept(60);
  SMF_CHECK_CODE(first, ReasonCode::IO_TIMEOUT);

  std::thread connector([&]() {
    auto client = TcpConnection::connect(server.address(), kBudget);
    if (client.ok()) {
      TcpConnection connection = std::move(client).value();
      (void)connection.send_all(smf::as_bytes(std::string_view("hi")), kBudget);
    }
  });
  const auto second = server.accept(kBudget);
  connector.join();
  SMF_CHECK_OK(second);
}

SMF_TEST(transport, closing_listener_releases_blocked_accept) {
  TcpListener server = unwrap(TcpListener::bind(unwrap(SocketAddress::loopback(0))));

  std::atomic<bool> finished{false};
  std::atomic<int> observed_code{0};
  std::thread acceptor([&]() {
    const auto result = server.accept(30000);
    observed_code.store(static_cast<int>(result.status().code()));
    finished.store(true);
  });

  // Give the acceptor time to reach the blocking call, then close underneath it.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  SMF_CHECK_OK(server.close());
  acceptor.join();

  SMF_CHECK(finished.load());
  const ReasonCode code = static_cast<ReasonCode>(observed_code.load());
  SMF_CHECK(code == ReasonCode::SHUTTING_DOWN || code == ReasonCode::CONNECTION_CLOSED ||
            code == ReasonCode::IO_TIMEOUT);
}

SMF_TEST(transport, shutdown_releases_blocked_receiver) {
  Pair pair = make_pair();

  std::atomic<bool> finished{false};
  std::atomic<int> observed_code{0};
  std::thread receiver([&]() {
    Bytes buffer(64);
    const auto result = pair.server.receive_some(ByteSpan(buffer.data(), buffer.size()), 30000);
    observed_code.store(static_cast<int>(result.ok() ? ReasonCode::OK : result.status().code()));
    finished.store(true);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  SMF_CHECK_OK(pair.server.shutdown());
  receiver.join();

  SMF_CHECK(finished.load());
  SMF_CHECK(static_cast<ReasonCode>(observed_code.load()) != ReasonCode::IO_TIMEOUT);
}

SMF_TEST(transport, connect_to_closed_port_fails_deterministically) {
  SocketAddress address;
  {
    TcpListener listener = unwrap(TcpListener::bind(unwrap(SocketAddress::loopback(0))));
    address = listener.address();
    SMF_CHECK_OK(listener.close());
  }

  const auto result = TcpConnection::connect(address, 2000);
  SMF_CHECK(!result.ok());
  const ReasonCode code = result.status().code();
  SMF_CHECK(code == ReasonCode::CONNECTION_REFUSED || code == ReasonCode::CONNECT_FAILED ||
            code == ReasonCode::IO_TIMEOUT || code == ReasonCode::CONNECTION_RESET);
}

SMF_TEST(transport, empty_buffer_and_peer_close) {
  Pair pair = make_pair();

  ByteSpan empty;
  const auto none = pair.server.receive_some(empty, 100);
  SMF_CHECK_OK(none);
  SMF_CHECK_EQ(none.value(), std::size_t{0});

  SMF_CHECK_OK(pair.client.shutdown());
  pair.client.close();

  Bytes buffer(16);
  const auto closed = pair.server.receive_some(ByteSpan(buffer.data(), buffer.size()), kBudget);
  SMF_CHECK_OK(closed);
  SMF_CHECK_EQ(closed.value(), std::size_t{0});
}

SMF_TEST(transport, random_payloads_over_loopback) {
  SMF_PROPERTY(60) {
    Pair pair = make_pair();
    const std::size_t length = ctx.rng.below(200000);
    const Bytes payload = ctx.rng.bytes(length);
    const smf::Digest expected = smf::sha256(smf::as_bytes(payload));

    std::thread sender([&]() {
      if (!payload.empty()) send_fully(pair.client, smf::as_bytes(payload));
    });
    Bytes received;
    if (length > 0) {
      received = receive_exactly(pair.server, length);
    }
    sender.join();

    SMF_CHECK_EQ(received.size(), length);
    SMF_CHECK_EQ(smf::sha256(smf::as_bytes(received)), expected);
  }
}

SMF_TEST(transport, repeated_open_close_cycles) {
  for (int iteration = 0; iteration < 200; ++iteration) {
    TcpListener server = unwrap(TcpListener::bind(unwrap(SocketAddress::loopback(0))));
    const SocketAddress bound = server.address();

    TcpConnection accepted;
    std::thread acceptor([&]() {
      auto result = server.accept(kBudget);
      if (result.ok()) accepted = std::move(result).value();
    });
    auto client = TcpConnection::connect(bound, kBudget);
    acceptor.join();
    SMF_REQUIRE(client.ok());
    SMF_REQUIRE(accepted.is_open());
    TcpConnection client_connection = std::move(client).value();

    const std::string token = std::to_string(iteration);
    send_fully(client_connection, smf::as_bytes(token));
    const Bytes received = receive_exactly(accepted, token.size());
    SMF_CHECK_EQ(smf::as_string_view(smf::as_bytes(received)), std::string_view(token));

    SMF_CHECK_OK(accepted.shutdown());
    client_connection.close();
    accepted.close();
    SMF_CHECK_OK(server.close());
  }
}
