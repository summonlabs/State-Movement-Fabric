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
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "smf/compatibility.hpp"
#include "smf/coordinator.hpp"
#include "smf/endpoint_agent.hpp"
#include "smf/movement_store.hpp"
#include "smf/topology.hpp"
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
  std::thread stopper([&]() {
    const smf::Status status = coordinator->stop();
    (void)status;
  });
  stopper.join();

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
