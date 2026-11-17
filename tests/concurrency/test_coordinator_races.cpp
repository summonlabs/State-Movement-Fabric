// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Concurrency and lifecycle proofs.
//
// This suite exercises mutation against query, repeated start/stop, concurrent
// durable writes and reads, and repeated endpoint lifetime cycles. Where a
// barrier is needed it is built from a counted latch rather than from sleeping
// and hoping.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "smf/compatibility.hpp"
#include "smf/coordinator.hpp"
#include "smf/digest.hpp"
#include "smf/endpoint_agent.hpp"
#include "smf/framing.hpp"
#include "smf/movement_store.hpp"
#include "smf/session.hpp"
#include "smf/topology.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"
#include "smf_admin_client.hpp"
#include "smf_fixture.hpp"
#include "smf_test.hpp"

using smf::MovementRecord;
using smf::MovementStore;
using smf::MovementStoreOptions;
using smf::ReasonCode;

namespace {

// A deterministic barrier: every participant waits until all have arrived.
class Latch {
 public:
  explicit Latch(std::size_t participants) : remaining_(participants) {}

  void arrive_and_wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (--remaining_ == 0) {
      cv_.notify_all();
      return;
    }
    cv_.wait(lock, [this]() { return remaining_ == 0; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::size_t remaining_;
};

[[nodiscard]] smf::Bytes test_secret() {
  return smf::parse_shared_secret(
             "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
      .value();
}

[[nodiscard]] smf::CoordinatorConfig coordinator_config(const std::filesystem::path& state) {
  smf::CoordinatorConfig config;
  config.endpoint_id = smf::EndpointId::parse("coordinator").value();
  config.state_directory = state;
  config.shared_secret = test_secret();
  config.endpoint_listen = smf::SocketAddress::parse("127.0.0.1:0").value();
  config.admin_listen = smf::SocketAddress::parse("127.0.0.1:0").value();
  config.sync_store = false;
  config.worker_threads = 2;
  config.max_sessions = 16;
  return config;
}

}  // namespace

SMF_TEST(concurrency, repeated_coordinator_start_stop_advances_the_epoch) {
  smftest::TempDir dir("conc-restart");
  std::uint64_t previous = 0;
  for (int cycle = 0; cycle < 6; ++cycle) {
    auto started = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
    SMF_CHECK_OK(started);
    std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();
    const std::uint64_t epoch = coordinator->incarnation().epoch().value();
    SMF_CHECK(epoch > previous);
    previous = epoch;

    // A restarted coordinator never inherits liveness.
    SMF_CHECK_EQ(coordinator->topology_report().endpoints.size(), std::size_t{0});
    SMF_CHECK_OK(coordinator->stop());
  }
  SMF_CHECK_EQ(previous, std::uint64_t{6});
}

SMF_TEST(concurrency, shutdown_with_idle_clients_is_clean) {
  smftest::TempDir dir("conc-idle");
  auto started = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(started);
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  std::vector<std::unique_ptr<smftest::AdminClient>> clients;
  for (int i = 0; i < 6; ++i) {
    auto client = std::make_unique<smftest::AdminClient>();
    const smf::Status status = client->connect(coordinator->admin_address(), test_secret(),
                                               smf::EndpointId::parse("idle-cli").value());
    SMF_CHECK_OK(status);
    clients.push_back(std::move(client));
  }

  // Every idle client can be served before shutdown.
  for (auto& client : clients) {
    smf::PolicyRequest request;
    const auto answer = client->call<smf::PolicyRequest, smf::PolicyReport>(request);
    SMF_CHECK_OK(answer);
  }

  SMF_CHECK_OK(coordinator->request_shutdown());
  SMF_CHECK_OK(coordinator->stop());

  // The admin port is released: a fresh coordinator can bind the same directory.
  auto restarted = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(restarted);
  SMF_CHECK_OK(restarted.value()->stop());
}

SMF_TEST(concurrency, idle_clients_do_not_block_shutdown) {
  smftest::TempDir dir("conc-idle2");
  auto started = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(started);
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  std::vector<std::unique_ptr<smftest::AdminClient>> clients;
  for (int i = 0; i < 4; ++i) {
    auto client = std::make_unique<smftest::AdminClient>();
    SMF_CHECK_OK(client->connect(coordinator->admin_address(), test_secret(),
                                 smf::EndpointId::parse("idle-cli").value()));
    clients.push_back(std::move(client));
  }

  // Shutdown from another thread while the clients are connected but silent.
  // The clients stay silent for the whole I/O budget, which is three times the
  // wait below: a stop() that waits their reads out has not returned by then.
  std::promise<void> stopped;
  std::future<void> done = stopped.get_future();
  std::thread stopper([&]() {
    const smf::Status status = coordinator->stop();
    (void)status;
    stopped.set_value();
  });
  const bool returned = done.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
  stopper.join();

  SMF_CHECK(returned);
  SMF_CHECK(coordinator->stopping());
  // A client that tries to use the session now fails rather than hanging.
  smf::PolicyRequest request;
  const auto answer = clients.front()->call<smf::PolicyRequest, smf::PolicyReport>(request);
  SMF_CHECK(!answer.ok());
  clients.clear();
}

SMF_TEST(concurrency, store_handles_concurrent_put_get_and_list) {
  smftest::TempDir dir("conc-store");
  MovementStoreOptions options;
  options.directory = dir.path();
  options.sync_on_write = false;
  options.max_history_records = 100000;

  auto opened = MovementStore::open(options);
  SMF_CHECK_OK(opened);
  std::unique_ptr<MovementStore> store = std::move(opened).value();

  constexpr int kThreads = 8;
  constexpr int kPerThread = 250;
  Latch latch(kThreads);
  std::mutex collected_mutex;
  std::vector<smf::MovementId> collected;
  std::atomic<int> failures{0};

  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int thread = 0; thread < kThreads; ++thread) {
    workers.emplace_back([&, thread]() {
      std::vector<smf::MovementId> mine;
      mine.reserve(kPerThread);
      latch.arrive_and_wait();
      for (int i = 0; i < kPerThread; ++i) {
        const auto object = smftest::make_descriptor(
            smf::StateKind::KV, "conc/object-" + std::to_string(thread) + "-" + std::to_string(i), 1,
            4096, 4096);
        const MovementRecord record = smftest::make_record(object, "source-1", "dest-1");
        const smf::Status put = store->put(record);
        if (!put.ok()) {
          failures.fetch_add(1);
          continue;
        }
        mine.push_back(record.id);
        // Query while other threads are mutating.
        if ((i % 25) == 0) {
          const auto listed = store->list(10, 0);
          if (!listed.ok()) failures.fetch_add(1);
        }
      }
      std::lock_guard<std::mutex> lock(collected_mutex);
      collected.insert(collected.end(), mine.begin(), mine.end());
    });
  }
  for (std::thread& worker : workers) worker.join();

  SMF_CHECK_EQ(failures.load(), 0);
  SMF_CHECK_EQ(collected.size(), static_cast<std::size_t>(kThreads * kPerThread));
  SMF_CHECK_EQ(store->size(), collected.size());

  // Every accepted write is readable, and no identifier was duplicated.
  std::set<std::string> unique;
  for (const smf::MovementId& id : collected) unique.insert(id.hex());
  SMF_CHECK_EQ(unique.size(), collected.size());
  for (const smf::MovementId& id : collected) {
    const auto record = store->get(id);
    SMF_CHECK_OK(record);
    SMF_CHECK_EQ(record.value().id, id);
  }
}

SMF_TEST(concurrency, store_reopen_after_concurrent_writes_keeps_every_record) {
  smftest::TempDir dir("conc-reopen");
  MovementStoreOptions options;
  options.directory = dir.path();
  options.sync_on_write = false;
  options.max_history_records = 100000;

  std::vector<smf::MovementId> written;
  {
    auto opened = MovementStore::open(options);
    SMF_CHECK_OK(opened);
    std::unique_ptr<MovementStore> store = std::move(opened).value();
    constexpr int kThreads = 4;
    constexpr int kPerThread = 200;
    Latch latch(kThreads);
    std::mutex mutex;
    std::vector<std::thread> workers;
    for (int thread = 0; thread < kThreads; ++thread) {
      workers.emplace_back([&, thread]() {
        std::vector<smf::MovementId> mine;
        latch.arrive_and_wait();
        for (int i = 0; i < kPerThread; ++i) {
          const auto object = smftest::make_descriptor(
              smf::StateKind::ADAPTER,
              "reopen/object-" + std::to_string(thread) + "-" + std::to_string(i), 1, 4096, 4096);
          const MovementRecord record = smftest::make_record(object, "source-1", "dest-1");
          if (store->put(record).ok()) mine.push_back(record.id);
        }
        std::lock_guard<std::mutex> lock(mutex);
        written.insert(written.end(), mine.begin(), mine.end());
      });
    }
    for (std::thread& worker : workers) worker.join();
  }

  auto reopened = MovementStore::open(options);
  SMF_CHECK_OK(reopened);
  SMF_CHECK_EQ(reopened.value()->size(), written.size());
  for (const smf::MovementId& id : written) {
    SMF_CHECK(reopened.value()->contains(id));
  }
}

SMF_TEST(concurrency, compatibility_registry_is_consistent_under_concurrency) {
  smf::CompatibilityRegistry registry;
  constexpr int kThreads = 6;
  constexpr int kPerThread = 120;
  Latch latch(kThreads);
  std::atomic<int> failures{0};

  std::vector<std::thread> workers;
  for (int thread = 0; thread < kThreads; ++thread) {
    workers.emplace_back([&, thread]() {
      latch.arrive_and_wait();
      // Generation monotonicity is only a per-observer invariant: another
      // thread's later observation is not a regression this thread can see.
      std::uint64_t last_generation = 0;
      for (int i = 0; i < kPerThread; ++i) {
        const std::string name = "compat/object-" + std::to_string(thread) + "-" + std::to_string(i);
        const auto object =
            smftest::make_descriptor(smf::StateKind::TENSOR, name, 1, 4096, 4096);
        const auto destination = smf::EndpointId::parse("dest-1").value();

        smf::CompatibilityEvidence evidence;
        evidence.object_id = object.object_id;
        evidence.state_generation = object.generation;
        evidence.content_digest = object.content_digest;
        evidence.destination = destination;
        evidence.verdict = smf::CompatibilityVerdict::SUPPORTED;
        evidence.contract = "smf.compat.v1";
        evidence.attributes["dtype"] = "fp16";
        if (!registry.publish(evidence, smf::kEpoch2026).ok()) {
          failures.fetch_add(1);
          continue;
        }

        const auto queried = registry.query(object, destination);
        if (!queried.ok()) {
          failures.fetch_add(1);
          continue;
        }
        // A returned verdict must always be bound to the subject that was asked
        // about; a torn read would surface here.
        if (!queried.value().applies_to(object, destination)) {
          failures.fetch_add(1);
        }
        const std::uint64_t generation = registry.generation().value();
        if (generation < last_generation) failures.fetch_add(1);
        last_generation = generation;
      }
    });
  }
  for (std::thread& worker : workers) worker.join();

  SMF_CHECK_EQ(failures.load(), 0);
  SMF_CHECK_EQ(registry.size(), static_cast<std::size_t>(kThreads * kPerThread));

  // Nothing was ever inferred: an unpublished subject reports no evidence.
  const auto stranger =
      smftest::make_descriptor(smf::StateKind::TENSOR, "compat/never-published", 1, 4096, 4096);
  const auto absent = registry.query(stranger, smf::EndpointId::parse("dest-1").value());
  SMF_CHECK(!absent.ok());
  SMF_CHECK_EQ(absent.status().code(), ReasonCode::NO_EVIDENCE);
}

SMF_TEST(concurrency, topology_index_stays_consistent_across_lifecycle) {
  smf::TopologyView view;
  smf::IdIssuer issuer;
  const std::size_t cycles = 200;
  for (std::size_t cycle = 0; cycle < cycles; ++cycle) {
    const std::string name = "endpoint-" + std::to_string(cycle);
    const auto endpoint = smf::EndpointId::parse(name).value();
    smf::EndpointRegistration registration;
    registration.endpoint = endpoint;
    registration.incarnation =
        smf::EndpointIncarnation::make(endpoint, issuer.new_boot_id(), smf::IncarnationEpoch(1))
            .value();
    registration.service_address = smf::SocketAddress::parse("127.0.0.1:1000").value();
    registration.data_address = smf::SocketAddress::parse("127.0.0.1:1001").value();
    registration.contract = std::string(smf::kPeerContract);
    registration.capability_digest = smf::sha256(name);
    registration.registered_unix_millis = smf::kEpoch2026;
    registration.live = true;

    SMF_REQUIRE_OK(view.put(registration, 64));
    const auto found = view.find(endpoint);
    SMF_REQUIRE(found.ok());
    SMF_CHECK_EQ(found.value().endpoint, endpoint);
    SMF_REQUIRE_OK(view.remove(endpoint));
    SMF_CHECK(!view.contains(endpoint));
    SMF_CHECK_EQ(view.endpoints().size(), std::size_t{0});
  }

  // Re-registering a live endpoint replaces it rather than duplicating it.
  const auto endpoint = smf::EndpointId::parse("stable").value();
  for (int i = 0; i < 20; ++i) {
    smf::EndpointRegistration registration;
    registration.endpoint = endpoint;
    registration.incarnation =
        smf::EndpointIncarnation::make(endpoint, issuer.new_boot_id(),
                                       smf::IncarnationEpoch(static_cast<std::uint64_t>(i + 1)))
            .value();
    registration.service_address = smf::SocketAddress::parse("127.0.0.1:1000").value();
    registration.data_address = smf::SocketAddress::parse("127.0.0.1:1001").value();
    registration.contract = std::string(smf::kPeerContract);
    registration.capability_digest = smf::sha256("stable");
    registration.registered_unix_millis = smf::kEpoch2026;
    registration.live = true;
    SMF_REQUIRE_OK(view.put(registration, 64));
  }
  SMF_CHECK_EQ(view.endpoints().size(), std::size_t{1});

  // An older epoch never displaces a newer registration.
  {
    smf::EndpointRegistration stale;
    stale.endpoint = endpoint;
    stale.incarnation =
        smf::EndpointIncarnation::make(endpoint, issuer.new_boot_id(), smf::IncarnationEpoch(1))
            .value();
    stale.service_address = smf::SocketAddress::parse("127.0.0.1:1000").value();
    stale.data_address = smf::SocketAddress::parse("127.0.0.1:1001").value();
    stale.contract = std::string(smf::kPeerContract);
    stale.capability_digest = smf::sha256("stale");
    stale.registered_unix_millis = smf::kEpoch2026;
    stale.live = true;
    SMF_CHECK_CODE(view.put(stale, 64), ReasonCode::STALE_EPOCH);
    SMF_CHECK_EQ(view.find(endpoint).value().capability_digest, smf::sha256("stable"));
  }
}

SMF_TEST(concurrency, repeated_endpoint_start_stop_cycles) {
  smftest::TempDir dir("conc-endpoint");
  std::uint64_t previous = 0;
  for (int cycle = 0; cycle < 12; ++cycle) {
    smf::EndpointAgentConfig config;
    config.endpoint_id = smf::EndpointId::parse("cycler").value();
    config.store_root = dir.path();
    config.shared_secret = test_secret();
    config.coordinator_address = smf::SocketAddress::parse("127.0.0.1:1").value();
    config.sync_store = false;
    config.max_data_sessions = 2;

    auto started = smf::EndpointAgent::start(config);
    SMF_CHECK_OK(started);
    std::unique_ptr<smf::EndpointAgent> agent = std::move(started).value();
    SMF_CHECK(agent->data_address().port != 0);
    SMF_CHECK(agent->incarnation().epoch().value() > previous);
    previous = agent->incarnation().epoch().value();

    // The data listener must be released on stop, or the next cycle would leak
    // a session worker each time.
    SMF_CHECK_OK(agent->request_shutdown());
    SMF_CHECK_OK(agent->stop());
  }
  SMF_CHECK_EQ(previous, std::uint64_t{12});
}

namespace {

// An endpoint whose answers are scripted by the proof. It speaks the real
// control protocol over a real authenticated session; only what it answers,
// and when, is under the proof's control.
class ScriptedEndpoint {
 public:
  [[nodiscard]] smf::Status connect(
      const smf::SocketAddress& address, const smf::Bytes& secret, const smf::EndpointId& as,
      const smf::SocketAddress& data_address = smf::SocketAddress::parse("127.0.0.1:2").value()) {
    auto connection = smf::TcpConnection::connect(address, 10000);
    if (!connection.ok()) return connection.status();
    stream_ = std::make_unique<smf::FrameStream>(std::move(connection).value(), 10000, 4U << 20);

    smf::IdIssuer issuer;
    smf::PeerIdentity identity;
    identity.endpoint = as;
    identity.boot = issuer.new_boot_id();
    identity.epoch = smf::IncarnationEpoch(1);
    identity.role = smf::SessionRole::ENDPOINT;
    identity.contract = std::string(smf::kPeerContract);
    identity.capability_digest = smf::sha256(std::string_view("smf-test-scripted-endpoint"));

    const auto request = smf::make_hello_request(smf::as_bytes(secret), identity, issuer);
    if (!request.ok()) return request.status();
    {
      smf::CanonicalEncoder encoder;
      request.value().encode(encoder);
      SMF_RETURN_IF_ERROR(stream_->send(smf::MessageType::HELLO, encoder.view()));
    }
    const auto frame = stream_->receive();
    if (!frame.ok()) return frame.status();
    if (frame.value().header.type != smf::MessageType::HELLO_ACK) {
      return smf::Status(smf::ReasonCode::PROTOCOL_HANDSHAKE_FAILED,
                         "the coordinator refused the endpoint session");
    }
    const auto response = smf::decode_message<smf::HelloResponse>(frame.value());
    if (!response.ok()) return response.status();
    const auto key =
        smf::verify_hello_response(smf::as_bytes(secret), request.value(), response.value());
    if (!key.ok()) return key.status();
    stream_->codec().set_session_key(key.value().view());

    smf::RegisterRequest registration;
    registration.identity.endpoint = as;
    registration.identity.boot = identity.boot;
    registration.identity.epoch = identity.epoch;
    registration.identity.role = static_cast<std::uint8_t>(smf::SessionRole::ENDPOINT);
    registration.identity.contract = identity.contract;
    registration.identity.capability_digest = identity.capability_digest;
    registration.service_address = smf::SocketAddress::parse("127.0.0.1:1").value();
    registration.data_address = data_address;
    registration.inventory_digest = smf::sha256(std::string_view("empty-inventory"));
    SMF_RETURN_IF_ERROR(smf::send_message(*stream_, registration));
    const auto ack = smf::receive_message<smf::RegisterAck>(*stream_);
    return ack.ok() ? smf::Status::success() : ack.status();
  }

  template <class Message>
  [[nodiscard]] smf::Status send(const Message& message) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    return smf::send_message(*stream_, message);
  }

  [[nodiscard]] smf::Result<smf::Frame> receive() { return stream_->receive(); }

 private:
  std::unique_ptr<smf::FrameStream> stream_;
  std::mutex send_mutex_;
};

[[nodiscard]] smf::EndpointAgentConfig agent_config(const smf::Coordinator& coordinator,
                                                    const std::string& name,
                                                    const std::filesystem::path& root) {
  smf::EndpointAgentConfig config;
  config.endpoint_id = smf::EndpointId::parse(name).value();
  config.store_root = root;
  config.shared_secret = test_secret();
  config.coordinator_address = coordinator.endpoint_address();
  config.sync_store = false;
  config.max_data_sessions = 2;
  return config;
}

}  // namespace

SMF_TEST(concurrency, a_cancelled_movement_is_not_committed_by_a_late_transfer_result) {
  smftest::TempDir dir("conc-cancel-commit");
  smf::CoordinatorConfig config = coordinator_config(dir.path() / "state");
  config.io_budget_millis = 5000;
  auto started = smf::Coordinator::start(config);
  SMF_CHECK_OK(started);
  if (!started.ok()) return;
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  // A real source that holds the object.
  auto source_started =
      smf::EndpointAgent::start(agent_config(*coordinator, "race-source", dir.path() / "source"));
  SMF_CHECK_OK(source_started);
  if (!source_started.ok()) return;
  std::unique_ptr<smf::EndpointAgent> source = std::move(source_started).value();
  SMF_CHECK_OK(source->connect_to_coordinator());
  const smf::Bytes contents = smftest::pattern_bytes(0x5EED, 96U << 10);
  smf::StateObjectDescriptor object;
  SMF_CHECK_OK(source->publish_bytes(smf::StateKind::KV, "race/cancelled-object",
                                     smf::StateGeneration(1), smf::as_bytes(contents), "proof", true,
                                     &object));
  SMF_CHECK_OK(source->announce(object));

  // A destination that reports a finished transfer only when the proof says so,
  // and that answers every verification and commit request the way a
  // destination holding the bytes would.
  ScriptedEndpoint destination;
  const smf::EndpointId destination_id = smf::EndpointId::parse("race-destination").value();
  SMF_CHECK_OK(destination.connect(coordinator->endpoint_address(), test_secret(), destination_id));

  std::mutex mutex;
  std::condition_variable cv;
  bool execute_seen = false;
  smf::ExecuteMovement execute;
  std::atomic<int> commit_requests{0};

  // A failed check leaves the proof by exception. Whatever happens, the
  // coordinator is stopped first, which ends the responder's session, and the
  // responder is joined.
  std::thread responder;
  struct Teardown {
    smf::Coordinator& coordinator;
    std::thread& thread;
    ~Teardown() {
      const smf::Status stopped = coordinator.stop();
      (void)stopped;
      if (thread.joinable()) thread.join();
    }
  } teardown{*coordinator, responder};

  responder = std::thread([&]() {
    for (;;) {
      const auto frame = destination.receive();
      if (!frame.ok()) return;
      switch (frame.value().header.type) {
        case smf::MessageType::GRANT_TRANSFER: {
          const auto message = smf::decode_message<smf::GrantTransfer>(frame.value());
          if (!message.ok()) return;
          smf::GrantAck ack;
          ack.nonce = smf::Digest(message.value().grant.grant_nonce.bytes());
          ack.code = ReasonCode::OK;
          ack.detail = "grant accepted";
          if (!destination.send(ack).ok()) return;
          break;
        }
        case smf::MessageType::EXECUTE_MOVEMENT: {
          const auto message = smf::decode_message<smf::ExecuteMovement>(frame.value());
          if (!message.ok()) return;
          {
            std::lock_guard<std::mutex> lock(mutex);
            execute = message.value();
            execute_seen = true;
          }
          cv.notify_all();
          break;
        }
        case smf::MessageType::CANCEL: {
          const auto message = smf::decode_message<smf::CancelRequest>(frame.value());
          if (!message.ok()) return;
          smf::CancelAck ack;
          ack.movement_id = message.value().movement_id;
          ack.movement_generation = message.value().movement_generation;
          ack.code = ReasonCode::OK;
          ack.detail = "cancellation recorded";
          if (!destination.send(ack).ok()) return;
          break;
        }
        case smf::MessageType::VERIFY_REQUEST: {
          const auto message = smf::decode_message<smf::VerifyRequest>(frame.value());
          if (!message.ok()) return;
          smf::VerifyResponse response;
          response.movement_id = message.value().movement_id;
          response.object_id = message.value().object_id;
          response.object_generation = message.value().object_generation;
          response.code = ReasonCode::OK;
          response.stored_bytes = object.total_bytes;
          if (message.value().full_digest_requested) {
            response.stored_digest = object.content_digest;
          } else {
            const std::uint32_t index = message.value().chunk_index;
            const std::uint64_t offset = object.chunk_offset(index).value();
            const std::uint64_t length = object.chunk_length(index).value();
            response.chunk_index = index;
            response.chunk_payload.assign(
                contents.begin() + static_cast<std::ptrdiff_t>(offset),
                contents.begin() + static_cast<std::ptrdiff_t>(offset + length));
            response.chunk_digest = smf::compute_chunk_digest(
                object.object_id, object.generation, index, offset, length,
                smf::as_bytes(response.chunk_payload));
          }
          if (!destination.send(response).ok()) return;
          break;
        }
        case smf::MessageType::COMMIT_REQUEST: {
          const auto message = smf::decode_message<smf::CommitRequest>(frame.value());
          if (!message.ok()) return;
          commit_requests.fetch_add(1);
          smf::CommitResult result;
          result.movement_id = message.value().movement_id;
          result.movement_generation = message.value().movement_generation;
          result.code = ReasonCode::OK;
          result.marker_digest = smf::sha256(std::string_view("scripted-marker"));
          result.detail = "commit marker written";
          if (!destination.send(result).ok()) return;
          break;
        }
        default:
          break;
      }
    }
  });

  smf::SubmitMovement request;
  request.object_id = object.object_id;
  request.object_generation = object.generation;
  request.source = source->endpoint_id();
  request.destination = destination_id;
  const auto accepted = coordinator->submit(request);
  SMF_CHECK_OK(accepted);

  if (accepted.ok()) {
    {
      std::unique_lock<std::mutex> lock(mutex);
      cv.wait(lock, [&]() { return execute_seen; });
    }

    // The operator cancels while the transfer is running, and is told so.
    const auto cancelled = coordinator->cancel(accepted.value().movement_id);
    SMF_CHECK_OK(cancelled);
    if (cancelled.ok()) SMF_CHECK_EQ(cancelled.value().state, smf::MovementState::CANCELLED);

    // The destination had in fact finished, and its report arrives now.
    smf::AttemptResult result;
    result.movement_id = execute.movement_id;
    result.movement_generation = execute.movement_generation;
    result.attempt = execute.attempt;
    result.state = smf::MovementState::BYTES_ARRIVED;
    result.code = ReasonCode::OK;
    result.detail = "every chunk was written";
    result.verified_digest = object.content_digest;
    result.bytes = object.total_bytes;
    result.chunks = object.chunk_count;
    SMF_CHECK_OK(destination.send(result));

    coordinator->wait_for_idle();

    // What the operator was told is what the record says, and nothing was
    // committed on behalf of a cancelled movement.
    const auto record = coordinator->query(accepted.value().movement_id);
    SMF_CHECK_OK(record);
    if (record.ok()) SMF_CHECK_EQ(record.value().state, smf::MovementState::CANCELLED);
    SMF_CHECK_EQ(commit_requests.load(), 0);
    const smf::CoordinatorCounters counters = coordinator->counters();
    SMF_CHECK_EQ(counters.movements_committed, std::uint64_t{0});
    SMF_CHECK_EQ(counters.movements_cancelled, std::uint64_t{1});
  }
}

SMF_TEST(concurrency, a_movement_of_unknown_outcome_is_not_resolved_by_a_cancellation) {
  smftest::TempDir dir("conc-unknown-cancel");
  smf::CoordinatorConfig config = coordinator_config(dir.path() / "state");
  config.io_budget_millis = 5000;
  auto started = smf::Coordinator::start(config);
  SMF_CHECK_OK(started);
  if (!started.ok()) return;
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  auto source_started = smf::EndpointAgent::start(
      agent_config(*coordinator, "unknown-source", dir.path() / "source"));
  SMF_CHECK_OK(source_started);
  if (!source_started.ok()) return;
  std::unique_ptr<smf::EndpointAgent> source = std::move(source_started).value();
  SMF_CHECK_OK(source->connect_to_coordinator());
  const smf::Bytes contents = smftest::pattern_bytes(0xC0DE, 64U << 10);
  smf::StateObjectDescriptor object;
  SMF_CHECK_OK(source->publish_bytes(smf::StateKind::KV, "race/unknown-object",
                                     smf::StateGeneration(1), smf::as_bytes(contents), "proof", true,
                                     &object));
  SMF_CHECK_OK(source->announce(object));

  // A destination that accepts the grant, is told to start, and is then lost
  // without reporting anything: whether it took the object is not known.
  const smf::EndpointId destination_id = smf::EndpointId::parse("unknown-destination").value();
  smf::MovementId id;
  {
    ScriptedEndpoint destination;
    SMF_CHECK_OK(destination.connect(coordinator->endpoint_address(), test_secret(), destination_id));

    smf::SubmitMovement request;
    request.object_id = object.object_id;
    request.object_generation = object.generation;
    request.source = source->endpoint_id();
    request.destination = destination_id;
    const auto accepted = coordinator->submit(request);
    SMF_CHECK_OK(accepted);
    if (!accepted.ok()) return;
    id = accepted.value().movement_id;

    bool told_to_start = false;
    while (!told_to_start) {
      const auto frame = destination.receive();
      SMF_REQUIRE(frame.ok());
      if (frame.value().header.type == smf::MessageType::GRANT_TRANSFER) {
        const auto message = smf::decode_message<smf::GrantTransfer>(frame.value());
        SMF_REQUIRE(message.ok());
        smf::GrantAck ack;
        ack.nonce = smf::Digest(message.value().grant.grant_nonce.bytes());
        ack.code = ReasonCode::OK;
        ack.detail = "grant accepted";
        SMF_CHECK_OK(destination.send(ack));
      } else if (frame.value().header.type == smf::MessageType::EXECUTE_MOVEMENT) {
        told_to_start = true;
      }
    }
  }

  coordinator->wait_for_idle();
  const auto unknown = coordinator->query(id);
  SMF_CHECK_OK(unknown);
  if (unknown.ok()) SMF_CHECK_EQ(unknown.value().state, smf::MovementState::OUTCOME_UNKNOWN);

  // The operator cannot settle by decree what only the destination can prove.
  const auto cancelled = coordinator->cancel(id);
  SMF_CHECK(!cancelled.ok());
  SMF_CHECK_EQ(cancelled.status().code(), ReasonCode::OUTCOME_UNKNOWN);

  const auto after = coordinator->query(id);
  SMF_CHECK_OK(after);
  if (after.ok()) SMF_CHECK_EQ(after.value().state, smf::MovementState::OUTCOME_UNKNOWN);
  SMF_CHECK_EQ(coordinator->counters().movements_cancelled, std::uint64_t{0});

  SMF_CHECK_OK(source->stop());
  SMF_CHECK_OK(coordinator->stop());
}

// Regression: a transfer runs on a thread of the destination agent and works on
// that agent, so stop() has to end it and wait for it. The source here is
// scripted and its data listener accepts the destination's data session without
// ever answering, which leaves the transfer blocked in a read when the
// destination is stopped.
SMF_TEST(concurrency, stopping_a_destination_ends_its_running_transfer) {
  smftest::TempDir dir("conc-stop-transfer");
  auto started = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(started);
  if (!started.ok()) return;
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  auto listening = smf::TcpListener::bind(smf::SocketAddress::parse("127.0.0.1:0").value());
  SMF_CHECK_OK(listening);
  if (!listening.ok()) return;
  smf::TcpListener silent_data_listener = std::move(listening).value();

  ScriptedEndpoint source;
  const smf::EndpointId source_id = smf::EndpointId::parse("stop-source").value();
  SMF_CHECK_OK(source.connect(coordinator->endpoint_address(), test_secret(), source_id,
                              silent_data_listener.address()));
  const smf::StateObjectDescriptor object =
      smftest::make_descriptor(smf::StateKind::KV, "race/stop-transfer", 1, 64U << 10, 16U << 10);
  smf::AnnounceObject announce;
  announce.descriptor = object;
  SMF_CHECK_OK(source.send(announce));
  for (;;) {
    const auto frame = source.receive();
    SMF_REQUIRE(frame.ok());
    if (frame.value().header.type == smf::MessageType::ANNOUNCE_ACK) break;
  }

  auto destination_started = smf::EndpointAgent::start(
      agent_config(*coordinator, "stop-destination", dir.path() / "destination"));
  SMF_CHECK_OK(destination_started);
  if (!destination_started.ok()) return;
  std::unique_ptr<smf::EndpointAgent> destination = std::move(destination_started).value();
  SMF_CHECK_OK(destination->connect_to_coordinator());

  // A failed check leaves the proof by exception. Whatever happens, the
  // coordinator is stopped first, which ends the source's session, and the
  // responder is joined.
  std::thread responder;
  struct Teardown {
    smf::Coordinator& coordinator;
    std::thread& thread;
    ~Teardown() {
      const smf::Status stopped = coordinator.stop();
      (void)stopped;
      if (thread.joinable()) thread.join();
    }
  } teardown{*coordinator, responder};

  responder = std::thread([&]() {
    for (;;) {
      const auto frame = source.receive();
      if (!frame.ok()) return;
      if (frame.value().header.type != smf::MessageType::GRANT_TRANSFER) continue;
      const auto message = smf::decode_message<smf::GrantTransfer>(frame.value());
      if (!message.ok()) return;
      smf::GrantAck ack;
      ack.nonce = smf::Digest(message.value().grant.grant_nonce.bytes());
      ack.code = ReasonCode::OK;
      ack.detail = "grant accepted";
      if (!source.send(ack).ok()) return;
    }
  });

  smf::SubmitMovement request;
  request.object_id = object.object_id;
  request.object_generation = object.generation;
  request.source = source_id;
  request.destination = destination->endpoint_id();
  const auto accepted = coordinator->submit(request);
  SMF_CHECK_OK(accepted);
  if (!accepted.ok()) return;

  // The destination opens its data session and waits for an answer.
  auto data = silent_data_listener.accept(30000);
  SMF_CHECK_OK(data);
  if (!data.ok()) return;

  SMF_CHECK_OK(destination->stop());

  // The transfer has ended by the time stop() returns, so its end of the data
  // session is closed: what is left to read ends in a close, not in a wait.
  bool closed = false;
  smf::Bytes buffer(4096);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!closed && std::chrono::steady_clock::now() < deadline) {
    const auto got = data.value().receive_some(smf::ByteSpan(buffer), 250);
    closed = got.ok() ? got.value() == 0 : got.status().code() != ReasonCode::IO_TIMEOUT;
  }
  SMF_CHECK(closed);
}

SMF_TEST(concurrency, an_ended_session_does_not_take_down_its_successors_registration) {
  smftest::TempDir dir("conc-successor");
  smf::CoordinatorConfig config = coordinator_config(dir.path() / "state");
  config.max_sessions = 2;
  auto started = smf::Coordinator::start(config);
  SMF_CHECK_OK(started);
  if (!started.ok()) return;
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  auto first_started = smf::EndpointAgent::start(
      agent_config(*coordinator, "restarting-endpoint", dir.path() / "first"));
  SMF_CHECK_OK(first_started);
  if (!first_started.ok()) return;
  std::unique_ptr<smf::EndpointAgent> first = std::move(first_started).value();
  SMF_CHECK_OK(first->connect_to_coordinator());

  // The endpoint is restarted: its replacement registers under the same name
  // while the session of the process it replaces is still open.
  auto second_started = smf::EndpointAgent::start(
      agent_config(*coordinator, "restarting-endpoint", dir.path() / "second"));
  SMF_CHECK_OK(second_started);
  if (!second_started.ok()) return;
  std::unique_ptr<smf::EndpointAgent> second = std::move(second_started).value();
  SMF_CHECK_OK(second->connect_to_coordinator());

  // Only now does the old session end.
  SMF_CHECK_OK(first->stop());

  // The coordinator serves two sessions at most, so an operator session is
  // admitted only once it has finished tearing the old one down.
  bool torn_down = false;
  for (int attempt = 0; attempt < 500 && !torn_down; ++attempt) {
    smftest::AdminClient probe;
    torn_down = probe.connect(coordinator->admin_address(), test_secret(),
                              smf::EndpointId::parse("teardown-probe").value())
                    .ok();
    if (!torn_down) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  SMF_CHECK(torn_down);

  // The replacement is registered, connected and alive, and it will never
  // register again: it must still be live.
  const smf::TopologyReport report = coordinator->topology_report();
  SMF_CHECK_EQ(report.endpoints.size(), std::size_t{1});
  if (!report.endpoints.empty()) {
    SMF_CHECK(report.endpoints.front().live);
    SMF_CHECK(report.endpoints.front().incarnation == second->incarnation());
  }

  SMF_CHECK_OK(second->stop());
  SMF_CHECK_OK(coordinator->stop());
}

SMF_TEST(concurrency, endpoints_registering_at_once_all_appear_in_the_topology) {
  smftest::TempDir dir("conc-register");
  smf::CoordinatorConfig config = coordinator_config(dir.path() / "state");
  config.max_sessions = 64;
  auto started = smf::Coordinator::start(config);
  SMF_CHECK_OK(started);
  if (!started.ok()) return;
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  // A fleet starting together: every endpoint registers at the same moment
  // while an operator keeps reading the topology.
  constexpr int kEndpoints = 24;
  Latch latch(kEndpoints + 1);
  std::atomic<int> registered{0};
  std::atomic<bool> reading{true};
  std::vector<std::unique_ptr<ScriptedEndpoint>> endpoints;
  for (int index = 0; index < kEndpoints; ++index) {
    endpoints.push_back(std::make_unique<ScriptedEndpoint>());
  }
  std::vector<std::thread> threads;
  for (int index = 0; index < kEndpoints; ++index) {
    threads.emplace_back([&, index]() {
      latch.arrive_and_wait();
      const smf::Status status = endpoints[static_cast<std::size_t>(index)]->connect(
          coordinator->endpoint_address(), test_secret(),
          smf::EndpointId::parse("fleet-" + std::to_string(index)).value());
      if (status.ok()) registered.fetch_add(1);
    });
  }
  std::thread reader([&]() {
    latch.arrive_and_wait();
    while (reading.load()) {
      const smf::TopologyReport report = coordinator->topology_report();
      (void)report;
    }
  });
  for (std::thread& thread : threads) thread.join();
  reading.store(false);
  reader.join();

  SMF_CHECK_EQ(registered.load(), kEndpoints);
  const smf::TopologyReport report = coordinator->topology_report();
  SMF_CHECK_EQ(report.endpoints.size(), static_cast<std::size_t>(kEndpoints));
  std::set<std::string> names;
  for (const smf::EndpointRegistration& endpoint : report.endpoints) {
    SMF_CHECK(endpoint.live);
    names.insert(endpoint.endpoint.value());
  }
  SMF_CHECK_EQ(names.size(), static_cast<std::size_t>(kEndpoints));

  SMF_CHECK_OK(coordinator->stop());
}
