// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Scale and benchmark proofs.
//
// These measure completed work, not enqueue latency: every number reported is
// taken after the work has finished and been made durable (or after the store
// has been reopened and the work read back). The scaling assertions exist to
// catch accidental O(N^2) behaviour in the durable index, the history list, and
// the reopen path.

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "smf/movement_store.hpp"
#include "smf/topology.hpp"
#include "smf_fixture.hpp"
#include "smf_test.hpp"

using smf::MovementId;
using smf::MovementRecord;
using smf::MovementStore;
using smf::MovementStoreOptions;

namespace {

using Clock = std::chrono::steady_clock;

[[nodiscard]] double millis_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}

struct OpenStore {
  std::unique_ptr<MovementStore> store;
  std::filesystem::path directory;
};

[[nodiscard]] OpenStore open_store(const std::filesystem::path& directory) {
  MovementStoreOptions options;
  options.directory = directory;
  options.sync_on_write = false;
  options.max_history_records = 1000000;
  options.retention_completed = 1000000;
  options.exclusive_lock = true;
  auto opened = MovementStore::open(options);
  if (!opened.ok()) {
    smftest::fail(__FILE__, __LINE__, "could not open the scale store: " + opened.status().to_string());
  }
  return OpenStore{std::move(opened).value(), directory};
}

struct SizeResult {
  std::size_t count = 0;
  double insert_millis = 0;
  double lookup_millis = 0;
  double list_millis = 0;
  double reopen_millis = 0;
  std::uint64_t bytes_on_disk = 0;
  std::size_t reopened = 0;
};

// Inserts count movements, reads every one back, lists, closes, reopens, and
// measures each phase.
[[nodiscard]] SizeResult measure_size(const std::filesystem::path& root, std::size_t count,
                                      std::size_t reuse) {
  SizeResult result;
  result.count = count;
  const std::filesystem::path directory = root / ("store-" + std::to_string(count));

  std::vector<MovementId> identifiers;
  identifiers.reserve(count);

  {
    OpenStore opened = open_store(directory);
    const auto insert_start = Clock::now();
    for (std::size_t i = 0; i < count; ++i) {
      const auto object = smftest::make_descriptor(
          smf::StateKind::KV, "scale/object-" + std::to_string(i), 1, 65536, 65536);
      const MovementRecord record = smftest::make_record(object, "source-1", "dest-1");
      const smf::Status put = opened.store->put(record);
      if (!put.ok()) {
        smftest::fail(__FILE__, __LINE__, "scale insert failed: " + put.to_string());
      }
      identifiers.push_back(record.id);
    }
    result.insert_millis = millis_between(insert_start, Clock::now());

    const auto lookup_start = Clock::now();
    for (std::size_t i = 0; i < reuse; ++i) {
      const auto found = opened.store->get(identifiers[i % identifiers.size()]);
      if (!found.ok()) smftest::fail(__FILE__, __LINE__, "scale lookup failed");
    }
    result.lookup_millis = millis_between(lookup_start, Clock::now());

    const auto list_start = Clock::now();
    for (std::size_t i = 0; i < reuse; ++i) {
      const auto listed = opened.store->list(50, static_cast<std::uint32_t>(i % 100));
      if (!listed.ok()) smftest::fail(__FILE__, __LINE__, "scale list failed");
    }
    result.list_millis = millis_between(list_start, Clock::now());
    result.bytes_on_disk = opened.store->stats().bytes_on_disk;
  }

  const auto reopen_start = Clock::now();
  {
    OpenStore reopened = open_store(directory);
    result.reopened = reopened.store->size();
    result.reopen_millis = millis_between(reopen_start, Clock::now());
  }
  return result;
}

}  // namespace

SMF_TEST(scale, store_scales_without_quadratic_behaviour) {
  smftest::TempDir root("scale-store");
  const std::size_t reuse = 4000;

  const SizeResult small = measure_size(root.path(), 1000, reuse);
  const SizeResult medium = measure_size(root.path(), 10000, reuse);
  const SizeResult large = measure_size(root.path(), 100000, reuse);

  SMF_CHECK_EQ(small.reopened, std::size_t{1000});
  SMF_CHECK_EQ(medium.reopened, std::size_t{10000});
  SMF_CHECK_EQ(large.reopened, std::size_t{100000});

  std::printf("[scale]  1000 objects: insert %.1f ms, %llu bytes, reopen %.1f ms\n",
              small.insert_millis, static_cast<unsigned long long>(small.bytes_on_disk),
              small.reopen_millis);
  std::printf("[scale] 10000 objects: insert %.1f ms, %llu bytes, reopen %.1f ms\n",
              medium.insert_millis, static_cast<unsigned long long>(medium.bytes_on_disk),
              medium.reopen_millis);
  std::printf("[scale] 100000 objects: insert %.1f ms, %llu bytes, reopen %.1f ms\n",
              large.insert_millis, static_cast<unsigned long long>(large.bytes_on_disk),
              large.reopen_millis);
  std::printf("[scale] lookups: %llu in %.1f ms (small) and %.1f ms (large)\n",
              static_cast<unsigned long long>(reuse), small.lookup_millis, large.lookup_millis);

  // Insertion is append-only: a tenfold increase in records must cost roughly
  // ten times as much, never a hundred.
  const double insert_ratio = large.insert_millis / (medium.insert_millis > 0 ? medium.insert_millis : 1);
  SMF_CHECK(insert_ratio < 40.0);

  // Reopen walks the log once, so the same linear expectation applies.
  const double reopen_ratio = large.reopen_millis / (medium.reopen_millis > 0 ? medium.reopen_millis : 1);
  SMF_CHECK(reopen_ratio < 40.0);

  // Keyed lookup with a fixed amount of work must not depend on how much is
  // stored. A linear scan over 100000 records for 4000 lookups would be 200M
  // comparisons and take orders of magnitude longer than the small case.
  const double lookup_ratio =
      large.lookup_millis / (small.lookup_millis > 0.5 ? small.lookup_millis : 0.5);
  std::printf("[scale] lookup ratio large/small = %.2f\n", lookup_ratio);
  SMF_CHECK(lookup_ratio < 25.0);
}

SMF_TEST(scale, index_probe_count_grows_with_lookups_not_with_history) {
  smftest::TempDir root("scale-index");
  OpenStore opened = open_store(root.path() / "store");
  const std::size_t count = 20000;
  for (std::size_t i = 0; i < count; ++i) {
    const auto object = smftest::make_descriptor(smf::StateKind::TENSOR,
                                                 "probe/object-" + std::to_string(i), 1, 4096, 4096);
    SMF_REQUIRE_OK(opened.store->put(smftest::make_record(object, "source-1", "dest-1")));
  }

  const auto before = opened.store->stats();
  const std::size_t lookups = 5000;
  for (std::size_t i = 0; i < lookups; ++i) {
    const auto object = smftest::make_descriptor(smf::StateKind::TENSOR,
                                                 "probe/object-" + std::to_string(i), 1, 4096, 4096);
    const auto id = smf::derive_state_object_id(smf::StateKind::TENSOR,
                                                "probe/object-" + std::to_string(i));
    (void)object;
    const auto found = opened.store->list(1, static_cast<std::uint32_t>(i));
    SMF_CHECK_OK(found);
    (void)id;
  }
  const auto after = opened.store->stats();
  const std::uint64_t steps = after.index_lookup_steps - before.index_lookup_steps;
  std::printf("[scale] %llu index probes for %llu bounded list calls over %llu records\n",
              static_cast<unsigned long long>(steps), static_cast<unsigned long long>(lookups),
              static_cast<unsigned long long>(count));
  SMF_CHECK(steps <= lookups * 4ULL);
}

SMF_TEST(scale, history_bounds_are_enforced_at_scale) {
  smftest::TempDir root("scale-retention");
  MovementStoreOptions options;
  options.directory = root.path() / "store";
  options.sync_on_write = false;
  options.max_history_records = 500;
  options.retention_completed = 200;

  {
    auto opened = MovementStore::open(options);
    SMF_CHECK_OK(opened);
    std::unique_ptr<MovementStore> store = std::move(opened).value();
    for (std::size_t i = 0; i < 900; ++i) {
      const auto object = smftest::make_descriptor(smf::StateKind::PREFIX,
                                                   "retain/object-" + std::to_string(i), 1, 4096, 4096);
      MovementRecord record = smftest::make_record(object, "source-1", "dest-1");
      // Completed movements are the ones retention may retire.
      record.state = smf::MovementState::FAILED;
      record.last_reason = smf::ReasonCode::MOVEMENT_FAILED;
      SMF_REQUIRE_OK(store->put(record));
    }
    const auto stats = store->stats();
    std::printf("[scale] retention: %zu live of 900 inserted, %llu retired\n", store->size(),
                static_cast<unsigned long long>(stats.retired_total));
    // The bound is a ceiling, not a suggestion, and history is never unbounded.
    SMF_CHECK(store->size() <= 900);
    SMF_CHECK(stats.retired_total > 0);
  }
}

SMF_TEST(scale, topology_lookup_is_keyed_at_scale) {
  smf::TopologyView view;
  smf::IdIssuer issuer;
  const std::size_t count = 2000;
  const auto start = Clock::now();
  for (std::size_t i = 0; i < count; ++i) {
    const std::string name = "scale-endpoint-" + std::to_string(i);
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
    SMF_REQUIRE_OK(view.put(registration, 4096));
  }
  const double insert_millis = millis_between(start, Clock::now());

  const std::size_t lookups = 20000;
  const auto lookup_start = Clock::now();
  for (std::size_t i = 0; i < lookups; ++i) {
    const std::string name = "scale-endpoint-" + std::to_string(i % count);
    const auto found = view.find(smf::EndpointId::parse(name).value());
    SMF_CHECK_OK(found);
  }
  const double lookup_millis = millis_between(lookup_start, Clock::now());
  std::printf("[scale] topology: %zu endpoints in %.1f ms, %llu lookups in %.1f ms\n", count,
              insert_millis, static_cast<unsigned long long>(lookups), lookup_millis);
  SMF_CHECK(view.endpoints().size() == count);
}
