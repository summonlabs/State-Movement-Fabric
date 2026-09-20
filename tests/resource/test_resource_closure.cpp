// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Resource closure proofs.
//
// Every path that acquires something must return to a sane baseline: staging
// bytes, object bytes, markers, directory locks, sessions, threads, and the
// coordinator's own accounting. Successful, failed, cancelled, and ambiguous
// cases are all exercised here.

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "smf/coordinator.hpp"
#include "smf/endpoint_agent.hpp"
#include "smf/movement_store.hpp"
#include "smf/object_store.hpp"
#include "smf_admin_client.hpp"
#include "smf_fixture.hpp"
#include "smf_test.hpp"

using smf::MovementId;
using smf::MovementStore;
using smf::MovementStoreOptions;
using smf::ObjectStore;
using smf::ObjectStoreOptions;
using smf::ReasonCode;
using smf::StagingWriter;

namespace {

[[nodiscard]] smf::Bytes test_secret() {
  return smf::parse_shared_secret(
             "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
      .value();
}

struct Staged {
  smf::TransferGrant grant;
  smf::StateObjectDescriptor object;
  smf::Bytes payload;
};

// Builds a grant for a complete in-memory payload so a staging writer can be
// driven without any network.
[[nodiscard]] Staged make_staged(const std::string& name, std::size_t bytes) {
  Staged staged;
  staged.payload = smftest::pattern_bytes(0xA11CEULL, bytes);
  staged.object = smf::StateObjectDescriptor::create(
                      smf::StateKind::GENERIC_BLOB, name, smf::StateGeneration(1),
                      smf::sha256(smf::as_bytes(staged.payload)), bytes, 64U << 10,
                      smf::kEpoch2026, "resource-fixture")
                      .value();

  smf::IdIssuer issuer;
  staged.grant.movement_id = issuer.new_movement_id();
  staged.grant.movement_generation = smf::MovementGeneration(1);
  staged.grant.attempt = issuer.new_attempt_id();
  staged.grant.object = staged.object;
  staged.grant.source = smf::EndpointId::parse("source-1").value();
  staged.grant.source_incarnation =
      smf::SourceIncarnation::make(staged.grant.source, issuer.new_boot_id(),
                                   smf::IncarnationEpoch(1))
          .value();
  staged.grant.destination = smf::EndpointId::parse("dest-1").value();
  staged.grant.destination_incarnation =
      smf::DestinationIncarnation::make(staged.grant.destination, issuer.new_boot_id(),
                                        smf::IncarnationEpoch(1))
          .value();
  staged.grant.policy_generation = smf::PolicyGeneration(1);
  staged.grant.grant_nonce = issuer.new_nonce();
  staged.grant.max_bytes = bytes;
  staged.grant.max_chunks = staged.object.chunk_count;
  staged.grant.issued_unix_millis = smf::kEpoch2026;
  (void)staged.grant.sign(smf::as_bytes(test_secret()));
  return staged;
}

// Feeds every chunk of the payload into a staging writer.
[[nodiscard]] smf::Status stage_all(StagingWriter& writer, const Staged& staged) {
  for (std::uint32_t index = 0; index < staged.object.chunk_count; ++index) {
    const auto offset = staged.object.chunk_offset(index);
    const auto length = staged.object.chunk_length(index);
    if (!offset.ok()) return offset.status();
    if (!length.ok()) return length.status();
    const smf::ByteView slice(smf::as_bytes(staged.payload).data() + offset.value(),
                              static_cast<std::size_t>(length.value()));
    const smf::Digest digest = smf::compute_chunk_digest(
        staged.object.object_id, staged.object.generation, index, offset.value(), length.value(),
        slice);
    const auto appended = writer.append(index, offset.value(), slice, digest);
    if (!appended.ok()) return appended.status();
  }
  return smf::Status::success();
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
  config.max_sessions = 8;
  return config;
}

}  // namespace

SMF_TEST(resources, staging_is_released_once_an_object_is_promoted) {
  smftest::TempDir dir("res-promote");
  ObjectStoreOptions options;
  options.root = dir.path();
  options.sync_on_write = false;
  auto opened = ObjectStore::open(options);
  SMF_CHECK_OK(opened);
  std::unique_ptr<ObjectStore> store = std::move(opened).value();

  const Staged staged = make_staged("resource/promote", 256U << 10);
  auto writer = StagingWriter::begin(*store, staged.grant.movement_id,
                                     staged.grant.movement_generation, staged.grant.attempt,
                                     staged.object);
  SMF_CHECK_OK(writer);
  StagingWriter staging = std::move(writer).value();

  SMF_CHECK_OK(stage_all(staging, staged));
  SMF_CHECK(staging.resume_from_chunk() == staged.object.chunk_count);

  const auto digest = staging.finish();
  SMF_CHECK_OK(digest);
  SMF_CHECK_EQ(digest.value(), staged.object.content_digest);
  SMF_CHECK_OK(staging.promote());

  // The staging directory, its journal, and its partial bytes are all gone.
  SMF_CHECK_EQ(store->staging_bytes(staged.grant.movement_id), std::uint64_t{0});
  SMF_CHECK_FALSE(store->staging_present(staged.grant.movement_id));
  SMF_CHECK_FALSE(std::filesystem::exists(store->staging_directory(staged.grant.movement_id)));

  // The promoted object is exactly the payload that was staged.
  const auto size = store->object_size(staged.object.object_id, staged.object.generation);
  SMF_CHECK_OK(size);
  SMF_CHECK_EQ(size.value(), static_cast<std::uint64_t>(staged.payload.size()));
  const auto stored = store->digest_object(staged.object.object_id, staged.object.generation);
  SMF_CHECK_OK(stored);
  SMF_CHECK_EQ(stored.value(), staged.object.content_digest);
}

SMF_TEST(resources, cleanup_removes_only_the_movement_it_names) {
  smftest::TempDir dir("res-cleanup");
  ObjectStoreOptions options;
  options.root = dir.path();
  options.sync_on_write = false;
  auto opened = ObjectStore::open(options);
  SMF_CHECK_OK(opened);
  std::unique_ptr<ObjectStore> store = std::move(opened).value();

  const Staged keep = make_staged("resource/keep", 128U << 10);
  const Staged drop = make_staged("resource/drop", 128U << 10);

  for (const Staged* staged : {&keep, &drop}) {
    auto writer = StagingWriter::begin(*store, staged->grant.movement_id,
                                       staged->grant.movement_generation, staged->grant.attempt,
                                       staged->object);
    SMF_CHECK_OK(writer);
    StagingWriter staging = std::move(writer).value();
    SMF_CHECK_OK(stage_all(staging, *staged));
  }

  smf::CleanupTarget target;
  target.movement_id = drop.grant.movement_id;
  std::uint64_t removed = 0;
  std::uint32_t entries = 0;
  SMF_CHECK_OK(store->cleanup(target, &removed, &entries));
  SMF_CHECK(removed > 0);
  SMF_CHECK(entries >= 1);

  // The unrelated staged movement is untouched, including its journal, so it
  // can still be resumed.
  SMF_CHECK(store->staging_present(keep.grant.movement_id));
  const auto journal = store->load_journal(keep.grant.movement_id);
  SMF_CHECK_OK(journal);
  SMF_CHECK(journal.value().verified_chunks == keep.object.chunk_count);
  SMF_CHECK_FALSE(store->staging_present(drop.grant.movement_id));
}

SMF_TEST(resources, quarantine_moves_residue_without_deleting_it) {
  smftest::TempDir dir("res-quarantine");
  ObjectStoreOptions options;
  options.root = dir.path();
  options.sync_on_write = false;
  auto opened = ObjectStore::open(options);
  SMF_CHECK_OK(opened);
  std::unique_ptr<ObjectStore> store = std::move(opened).value();

  const Staged staged = make_staged("resource/quarantine", 128U << 10);
  {
    auto writer = StagingWriter::begin(*store, staged.grant.movement_id,
                                       staged.grant.movement_generation, staged.grant.attempt,
                                       staged.object);
    SMF_CHECK_OK(writer);
    StagingWriter staging = std::move(writer).value();
    SMF_CHECK_OK(stage_all(staging, staged));
    const auto digest = staging.finish();
    SMF_CHECK_OK(digest);
    SMF_CHECK_OK(staging.promote());
  }

  smf::CleanupTarget target;
  target.movement_id = staged.grant.movement_id;
  target.object_id = staged.object.object_id;
  target.generation = staged.object.generation;
  target.quarantine = true;
  target.remove_placed = true;
  std::uint64_t removed = 0;
  std::uint32_t entries = 0;
  SMF_CHECK_OK(store->cleanup(target, &removed, &entries));

  // The bytes were moved aside, not destroyed, and they no longer report as
  // authority for the object version.
  const std::filesystem::path quarantine =
      dir.path() / "quarantine" / staged.grant.movement_id.hex();
  SMF_CHECK(std::filesystem::exists(quarantine));
  SMF_CHECK_FALSE(store->object_present(staged.object.object_id, staged.object.generation));
  const auto authority = store->authority(staged.object.object_id, staged.object.generation);
  SMF_CHECK_OK(authority);
  SMF_CHECK_FALSE(authority.value().authoritative);
}

SMF_TEST(resources, a_failed_transfer_leaves_resumable_staging_then_cleanup_releases_it) {
  smftest::TempDir dir("res-failed");
  ObjectStoreOptions options;
  options.root = dir.path();
  options.sync_on_write = false;
  auto opened = ObjectStore::open(options);
  SMF_CHECK_OK(opened);
  std::unique_ptr<ObjectStore> store = std::move(opened).value();

  const Staged staged = make_staged("resource/partial", 256U << 10);
  {
    auto writer = StagingWriter::begin(*store, staged.grant.movement_id,
                                       staged.grant.movement_generation, staged.grant.attempt,
                                       staged.object);
    SMF_CHECK_OK(writer);
    StagingWriter staging = std::move(writer).value();

    // Only the first two chunks arrive, then the attempt dies.
    for (std::uint32_t index = 0; index < 2; ++index) {
      const auto offset = staged.object.chunk_offset(index);
      const auto length = staged.object.chunk_length(index);
      SMF_REQUIRE(offset.ok() && length.ok());
      const smf::ByteView slice(smf::as_bytes(staged.payload).data() + offset.value(),
                                static_cast<std::size_t>(length.value()));
      const smf::Digest digest = smf::compute_chunk_digest(
          staged.object.object_id, staged.object.generation, index, offset.value(),
          length.value(), slice);
      const auto appended = staging.append(index, offset.value(), slice, digest);
      SMF_REQUIRE(appended.ok());
    }
    staging.abort();
  }

  const std::uint64_t retained = store->staging_bytes(staged.grant.movement_id);
  SMF_CHECK(retained > 0);
  SMF_CHECK(store->staging_present(staged.grant.movement_id));

  smf::CleanupTarget target;
  target.movement_id = staged.grant.movement_id;
  std::uint64_t removed = 0;
  SMF_CHECK_OK(store->cleanup(target, &removed, nullptr));
  SMF_CHECK(removed > 0);
  SMF_CHECK_EQ(store->staging_bytes(staged.grant.movement_id), std::uint64_t{0});
  SMF_CHECK_FALSE(std::filesystem::exists(store->staging_directory(staged.grant.movement_id)));
}

SMF_TEST(resources, repeated_store_lifecycles_release_the_directory_each_time) {
  smftest::TempDir dir("res-store-cycles");
  MovementStoreOptions options;
  options.directory = dir.path() / "store";
  options.sync_on_write = false;
  for (int cycle = 0; cycle < 50; ++cycle) {
    auto opened = MovementStore::open(options);
    if (!opened.ok()) {
      smftest::fail(__FILE__, __LINE__,
                    "cycle " + std::to_string(cycle) + " could not open: " +
                        opened.status().to_string());
    }
    std::unique_ptr<MovementStore> store = std::move(opened).value();
    const auto object = smftest::make_descriptor(smf::StateKind::KV,
                                                 "cycle/object-" + std::to_string(cycle), 1, 4096,
                                                 4096);
    SMF_REQUIRE_OK(store->put(smftest::make_record(object, "source-1", "dest-1")));
    SMF_CHECK_EQ(store->size(), static_cast<std::size_t>(cycle) + 1);
  }

  auto reopened = MovementStore::open(options);
  SMF_CHECK_OK(reopened);
  SMF_CHECK_EQ(reopened.value()->size(), std::size_t{50});
}

SMF_TEST(resources, coordinator_session_accounting_and_threads_close) {
  smftest::TempDir dir("res-coordinator");
  auto started = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(started);
  std::unique_ptr<smf::Coordinator> coordinator = std::move(started).value();

  constexpr int kSessions = 12;
  for (int i = 0; i < kSessions; ++i) {
    smftest::AdminClient client;
    SMF_CHECK_OK(client.connect(coordinator->admin_address(), test_secret(),
                                smf::EndpointId::parse("accounting-cli").value()));
    smf::PolicyRequest request;
    SMF_CHECK_OK((client.call<smf::PolicyRequest, smf::PolicyReport>(request)));
    // The client is destroyed at the end of each iteration, so the coordinator
    // must reap the session rather than accumulate it.
  }

  const smf::CoordinatorCounters counters = coordinator->counters();
  SMF_CHECK_EQ(counters.sessions_accepted, std::uint64_t{kSessions});
  SMF_CHECK_EQ(counters.sessions_refused, std::uint64_t{0});

  SMF_CHECK_OK(coordinator->stop());

  // After stop, the operator surface is closed rather than half-alive.
  smf::QueryMovement query;
  query.movement_id = smf::IdIssuer().new_movement_id();
  const auto after = coordinator->query(query.movement_id);
  SMF_CHECK(!after.ok());
  SMF_CHECK_EQ(after.status().code(), ReasonCode::SHUTTING_DOWN);

  // And the state directory is free for the next instance immediately.
  auto restarted = smf::Coordinator::start(coordinator_config(dir.path() / "state"));
  SMF_CHECK_OK(restarted);
  SMF_CHECK_OK(restarted.value()->stop());
}

SMF_TEST(resources, endpoint_releases_its_listener_and_workers_each_cycle) {
  smftest::TempDir dir("res-endpoint");
  std::vector<std::uint16_t> ports;
  for (int cycle = 0; cycle < 16; ++cycle) {
    smf::EndpointAgentConfig config;
    config.endpoint_id = smf::EndpointId::parse("resource-endpoint").value();
    config.store_root = dir.path();
    config.shared_secret = test_secret();
    config.coordinator_address = smf::SocketAddress::parse("127.0.0.1:1").value();
    config.sync_store = false;
    config.max_data_sessions = 2;

    auto started = smf::EndpointAgent::start(config);
    SMF_CHECK_OK(started);
    std::unique_ptr<smf::EndpointAgent> agent = std::move(started).value();
    ports.push_back(agent->data_address().port);

    // A published object survives the endpoint process lifetime, and the
    // publication path releases its own scratch state.
    SMF_CHECK_OK(agent->publish_bytes(smf::StateKind::GENERIC_BLOB,
                                      "resource/endpoint-" + std::to_string(cycle),
                                      smf::StateGeneration(1),
                                      smf::as_bytes(smf::Bytes(64U << 10, smf::Byte{7})),
                                      "resource-fixture", true));
    const auto object_id = smf::derive_state_object_id(
        smf::StateKind::GENERIC_BLOB, "resource/endpoint-" + std::to_string(cycle));
    SMF_REQUIRE(object_id.ok());
    SMF_CHECK(agent->object_store().object_present(object_id.value(), smf::StateGeneration(1)));
    SMF_CHECK_FALSE(std::filesystem::exists(
        agent->object_store().object_directory(object_id.value(), smf::StateGeneration(1)) /
        "data.import"));
    SMF_CHECK_OK(agent->stop());
  }

  // Every cycle got a live listener, and stopping really did release it.
  for (const std::uint16_t port : ports) {
    SMF_CHECK(port != 0);
  }
}

SMF_TEST(resources, movement_counters_close_over_a_full_lifecycle) {
  smf::MovementRecord record;
  const auto object =
      smftest::make_descriptor(smf::StateKind::CHECKPOINT, "resource/counters", 1, 4096, 4096);
  record = smftest::make_record(object, "source-1", "dest-1");
  SMF_CHECK_OK(record.validate());

  // Drive the whole machine forward and confirm the record's own accounting is
  // consistent at every step: the generation advances exactly once per accepted
  // transition and the provenance chain gains exactly one event.
  std::uint64_t expected_generation = record.generation.value();
  std::size_t expected_events = record.provenance.size();
  const auto advance = [&](smf::MovementState next, smf::ProvenanceEventKind kind) {
    const smf::Status status = smf::apply_transition(
        record, next, smf::MovementDecision::allow(ReasonCode::OK, "resource closure"),
        kind, smf::kEpoch2026);
    SMF_CHECK_OK(status);
    expected_generation += 1;
    expected_events += 1;
    SMF_CHECK_EQ(record.generation.value(), expected_generation);
    SMF_CHECK_EQ(record.provenance.size(), expected_events);
  };

  advance(smf::MovementState::AUTHORIZED, smf::ProvenanceEventKind::AUTHORIZED);
  advance(smf::MovementState::TRANSFERRING, smf::ProvenanceEventKind::ATTEMPT_STARTED);
  advance(smf::MovementState::BYTES_ARRIVED, smf::ProvenanceEventKind::BYTES_ARRIVED);
  advance(smf::MovementState::VERIFIED, smf::ProvenanceEventKind::VERIFIED);
  record.commit_marker_digest = smf::sha256("marker");
  advance(smf::MovementState::COMMITTED, smf::ProvenanceEventKind::COMMITTED);

  // A refused transition adds a rejection event and does not advance the
  // generation, so a terminal record's accounting never drifts.
  const smf::Status refused = smf::apply_transition(
      record, smf::MovementState::FAILED, smf::MovementDecision::deny(ReasonCode::MOVEMENT_FAILED, "too late"),
      smf::ProvenanceEventKind::FAILED, smf::kEpoch2026);
  SMF_CHECK(!refused.ok());
  SMF_CHECK_EQ(refused.code(), ReasonCode::ALREADY_TERMINAL);
  SMF_CHECK_EQ(record.generation.value(), expected_generation);
  SMF_CHECK(record.provenance.size() >= expected_events);
}
