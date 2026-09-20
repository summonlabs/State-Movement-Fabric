// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Distributed proof obligations. Every test here starts real coordinator and
// endpoint processes, moves real bytes over loopback TCP, and kills processes
// at chosen barriers. Nothing is simulated.

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "smf/digest.hpp"
#include "smf/fault_injection.hpp"
#include "smf/ids.hpp"
#include "smf/wire.hpp"
#include "smf_admin_client.hpp"
#include "smf_test.hpp"
#include "smf_test_process.hpp"

namespace {

using smftest::AdminClient;
using smftest::ChildProcess;
using smftest::ProcessSpec;

constexpr smf::Millis kReadyBudget = 20000;

[[nodiscard]] std::string random_key() {
  smf::IdIssuer issuer;
  return issuer.new_nonce().hex();
}

[[nodiscard]] smf::Bytes key_bytes(const std::string& key) {
  return smf::parse_shared_secret(key).value();
}

// A running fabric: one coordinator and two endpoints, with the handles needed
// to kill any of them at a chosen moment.
class Fabric {
 public:
  // Faults are per role: a barrier is only meaningful in the process that is
  // supposed to die at it.
  Fabric(std::string label, std::string source_faults = {}, std::string destination_faults = {},
         std::string coordinator_faults = {})
      : root_(label), key_(random_key()), source_faults_(std::move(source_faults)),
        destination_faults_(std::move(destination_faults)) {
    const std::filesystem::path binaries = smftest::binary_directory();
    if (binaries.empty()) {
      smftest::fail(__FILE__, __LINE__, "this configuration did not build the executables");
    }
    // A fixed payload so that the content digest is known before the transfer.
    payload_ = root_.file("payload.bin");
    smftest::Rng rng(0x51A7EULL);
    const smf::Bytes bytes = rng.bytes(3U * 1024U * 1024U);
    std::FILE* file = std::fopen(payload_.string().c_str(), "wb");
    if (file == nullptr) smftest::fail(__FILE__, __LINE__, "could not write the payload");
    std::fwrite(bytes.data(), 1, bytes.size(), file);
    std::fclose(file);
    expected_ = smf::sha256(smf::as_bytes(bytes));

    ProcessSpec coordinator;
    coordinator.program = smftest::executable("smf_coordinator");
    coordinator.working_directory = root_.path();
    coordinator.output_file = root_.file("coordinator.log");
    coordinator.environment["SMF_SHARED_KEY"] = key_;
    coordinator.arguments = {"--state", root_.file("coord-state").string(),
                             "--announce", root_.file("coordinator.json").string(),
                             "--log-level", "DEBUG"};
    if (!coordinator_faults.empty()) {
      coordinator.arguments.push_back("--fault-inject");
      coordinator.arguments.push_back(coordinator_faults);
    }
    coordinator_ = start_process(coordinator, "coordinator");

    const auto announced = wait_for_json(root_.file("coordinator.json"));
    coordinator_endpoint_ = announced.first;
    coordinator_admin_ = announced.second;

    source_ = start_endpoint("source-1", "src", true, source_faults_);
    destination_ = start_endpoint("dest-1", "dst", false, destination_faults_);
    SMF_REQUIRE(source_running());
    SMF_REQUIRE(destination_running());
  }

  ~Fabric() {
    kill_quietly(destination_);
    kill_quietly(source_);
    kill_quietly(coordinator_);
  }

  Fabric(const Fabric&) = delete;
  Fabric& operator=(const Fabric&) = delete;

  [[nodiscard]] const std::string& key() const noexcept { return key_; }
  [[nodiscard]] const std::filesystem::path& payload() const noexcept { return payload_; }
  [[nodiscard]] const smf::Digest& expected() const noexcept { return expected_; }
  [[nodiscard]] const std::filesystem::path& root() const noexcept { return root_.path(); }
  [[nodiscard]] const smf::SocketAddress& admin_address() const noexcept {
    return coordinator_admin_;
  }
  [[nodiscard]] ChildProcess& destination() noexcept { return destination_; }
  [[nodiscard]] ChildProcess& source() noexcept { return source_; }
  [[nodiscard]] ChildProcess& coordinator() noexcept { return coordinator_; }

  [[nodiscard]] bool source_running() { return source_.running(); }
  [[nodiscard]] bool destination_running() { return destination_.running(); }
  [[nodiscard]] bool coordinator_running() { return coordinator_.running(); }

  [[nodiscard]] std::string destination_log() const { return destination_.output(); }
  [[nodiscard]] std::string coordinator_log() const { return coordinator_.output(); }

  [[nodiscard]] std::filesystem::path destination_objects() const {
    return root_.path() / "dst" / "objects";
  }
  [[nodiscard]] std::filesystem::path destination_commits() const {
    return root_.path() / "dst" / "commits";
  }

  [[nodiscard]] AdminClient connect_admin() const {
    AdminClient client;
    const smf::EndpointId as = smf::EndpointId::parse("smf-test").value();
    const smf::Status status = client.connect(coordinator_admin_, key_bytes(key_), as);
    if (!status.ok()) {
      smftest::fail(__FILE__, __LINE__, "operator session failed: " + status.to_string());
    }
    return client;
  }

  // Restarts the coordinator against the same state directory. The caller is
  // responsible for reconnecting any operator client.
  void restart_coordinator() {
    kill_quietly(coordinator_);
    std::error_code error;
    std::filesystem::remove(root_.file("coordinator.json"), error);

    ProcessSpec spec;
    spec.program = smftest::executable("smf_coordinator");
    spec.working_directory = root_.path();
    spec.output_file = root_.file("coordinator-2.log");
    spec.environment["SMF_SHARED_KEY"] = key_;
    spec.arguments = {"--state", root_.file("coord-state").string(),
                      "--announce", root_.file("coordinator.json").string(),
                      "--log-level", "DEBUG"};
    coordinator_ = start_process(spec, "coordinator");
    const auto announced = wait_for_json(root_.file("coordinator.json"));
    coordinator_endpoint_ = announced.first;
    coordinator_admin_ = announced.second;

  }

  // Starts a fresh destination process against the same store, with no fault
  // injection: it registers again with a new boot id, which is how a restarted
  // peer is distinguished from the one that died.
  void restart_destination() {
    kill_quietly(destination_);
    destination_ = start_endpoint("dest-1", "dst", false, {});
  }

 private:
  // Registration and publication are observable through the endpoint's own
  // output, so a submission is never raced against a starting process.
  static void wait_for_log(ChildProcess& child, const std::string& needle, const char* what) {
    const bool seen = smftest::wait_until(
        [&]() { return child.output().find(needle) != std::string::npos; }, kReadyBudget);
    if (!seen) {
      const std::string log = child.output();
      smftest::fail(__FILE__, __LINE__,
                    std::string("the ") + what + " never reported '" + needle +
                        "'; its output was: " + (log.empty() ? std::string("<empty>")
                                                             : log.substr(0, 400)));
    }
  }

  static ChildProcess start_process(const ProcessSpec& spec, const char* what) {
    auto child = ChildProcess::spawn(spec);
    if (!child.ok()) {
      smftest::fail(__FILE__, __LINE__,
                    std::string("could not start the ") + what + ": " +
                        child.status().to_string());
    }
    return std::move(child).value();
  }

  [[nodiscard]] ChildProcess start_endpoint(const std::string& id, const std::string& store,
                                            bool publish,
                                            const std::string& faults) {
    ProcessSpec spec;
    spec.program = smftest::executable("smf_endpoint");
    spec.working_directory = root_.path();
    spec.output_file = root_.file(id + ".log");
    spec.environment["SMF_SHARED_KEY"] = key_;
    spec.arguments = {"--id", id, "--coordinator", coordinator_endpoint_.to_string(), "--store",
                      (root_.path() / store).string(), "--log-level", "DEBUG"};
    if (publish) {
      spec.arguments.push_back("--publish");
      spec.arguments.push_back("GENERIC_BLOB:demo/state:1:" + payload_.string());
    }
    if (!faults.empty()) {
      spec.arguments.push_back("--fault-inject");
      spec.arguments.push_back(faults);
    }
    ChildProcess child = start_process(spec, id.c_str());
    if (publish) {
      // Wait for the announcement the coordinator actually accepted, not for
      // the local placement that precedes it.
      wait_for_log(child, "announced", "source endpoint");
    } else {
      wait_for_log(child, "registered with topology generation", "destination endpoint");
    }
    return child;
  }

  [[nodiscard]] std::pair<smf::SocketAddress, smf::SocketAddress> wait_for_json(
      const std::filesystem::path& path) {
    std::string text;
    const bool arrived = smftest::wait_until(
        [&]() {
          std::error_code error;
          if (!std::filesystem::exists(path, error)) return false;
          std::FILE* file = std::fopen(path.string().c_str(), "rb");
          if (file == nullptr) return false;
          char buffer[256] = {};
          const std::size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, file);
          std::fclose(file);
          text.assign(buffer, read);
          return text.find('}') != std::string::npos;
        },
        kReadyBudget);
    if (!arrived) {
      const std::string log = coordinator_.output();
      smftest::fail(__FILE__, __LINE__,
                    "the coordinator never announced its addresses; its output was: " +
                        (log.empty() ? std::string("<empty>") : log.substr(0, 400)));
    }

    const auto extract = [&text](const std::string& field) {
      const std::string marker = "\"" + field + "\":\"";
      const std::size_t start = text.find(marker);
      if (start == std::string::npos) return std::string();
      const std::size_t begin = start + marker.size();
      const std::size_t end = text.find('"', begin);
      return text.substr(begin, end - begin);
    };
    const auto endpoint = smf::SocketAddress::parse(extract("endpoint"));
    const auto admin = smf::SocketAddress::parse(extract("admin"));
    if (!endpoint.ok() || !admin.ok()) {
      smftest::fail(__FILE__, __LINE__, "the coordinator announced an unparsable address");
    }
    return {endpoint.value(), admin.value()};
  }

  static void kill_quietly(ChildProcess& child) {
    if (child.running()) child.kill();
  }

  smftest::TempDir root_;
  std::string key_;
  std::string source_faults_;
  std::string destination_faults_;
  std::filesystem::path payload_;
  smf::Digest expected_;
  smf::SocketAddress coordinator_endpoint_;
  smf::SocketAddress coordinator_admin_;
  ChildProcess coordinator_;
  ChildProcess source_;
  ChildProcess destination_;
};

// Waits until a movement reaches a terminal state or the predicate holds.
[[nodiscard]] smf::MovementRecord poll_until(
    AdminClient& client, const smf::MovementId& id,
    const std::function<bool(const smf::MovementRecord&)>& predicate,
    smf::Millis budget = 30000) {
  smf::MovementRecord last;
  bool satisfied = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget);
  while (std::chrono::steady_clock::now() < deadline) {
    smf::QueryMovement request;
    request.movement_id = id;
    auto answer = client.call<smf::QueryMovement, smf::MovementStatus>(request);
    if (answer.ok()) {
      last = answer.value().record;
      if (predicate(last)) {
        satisfied = true;
        break;
      }
      if (last.is_terminal()) break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (!satisfied) {
    smftest::fail(__FILE__, __LINE__,
                  "the movement did not reach the expected condition; last state was " +
                      std::string(smf::to_string(last.state)) + " reason " +
                      smf::to_string(last.last_reason) + " detail " + last.last_detail);
  }
  return last;
}

[[nodiscard]] smf::MovementId submit_movement(AdminClient& client) {
  smf::SubmitMovement request;
  request.object_id = smf::derive_state_object_id(smf::StateKind::GENERIC_BLOB, "demo/state").value();
  request.object_generation = smf::StateGeneration(1);
  request.source = smf::EndpointId::parse("source-1").value();
  request.destination = smf::EndpointId::parse("dest-1").value();
  auto accepted = client.call<smf::SubmitMovement, smf::MovementAccepted>(request);
  if (!accepted.ok()) {
    smftest::fail(__FILE__, __LINE__,
                  "the coordinator refused the submission: " + accepted.status().to_string());
  }
  return accepted.value().movement_id;
}

// Reads the bytes the destination actually stored and hashes them here, in this
// process, so the assertion does not depend on any process's own report.
[[nodiscard]] smf::Result<smf::Digest> hash_destination_object(const Fabric& fabric,
                                                              std::uint64_t* bytes_out) {
  std::error_code error;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fabric.destination_objects(), error)) {
    if (!entry.is_regular_file()) continue;
    if (entry.path().filename() != "data") continue;
    std::FILE* file = std::fopen(entry.path().string().c_str(), "rb");
    if (file == nullptr) continue;
    smf::Sha256 hasher;
    smf::Bytes buffer(256U << 10);
    std::uint64_t total = 0;
    for (;;) {
      const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
      if (read == 0) break;
      hasher.update(smf::ByteView(buffer.data(), read));
      total += read;
    }
    std::fclose(file);
    if (bytes_out != nullptr) *bytes_out = total;
    return hasher.finalize();
  }
  return smf::Status(smf::ReasonCode::OBJECT_VERSION_NOT_FOUND,
                     "the destination stored no object bytes");
}

[[nodiscard]] std::size_t count_commit_markers(const Fabric& fabric) {
  std::error_code error;
  std::size_t count = 0;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fabric.destination_commits(), error)) {
    if (entry.is_regular_file() && entry.path().extension() == ".marker") ++count;
  }
  return count;
}

}  // namespace

SMF_TEST(multiprocess, movement_commits_end_to_end) {
  Fabric fabric("mp-commit");
  AdminClient client = fabric.connect_admin();
  const smf::MovementId id = submit_movement(client);

  const smf::MovementRecord record = poll_until(client, id, [](const smf::MovementRecord& r) {
    return r.state == smf::MovementState::COMMITTED;
  });

  SMF_CHECK_EQ(record.state, smf::MovementState::COMMITTED);
  SMF_CHECK_EQ(record.bytes_transferred, std::uint64_t{3U * 1024U * 1024U});
  SMF_CHECK(!record.commit_marker_digest.is_zero());
  SMF_CHECK_EQ(record.destination_verified_digest, fabric.expected());

  // Independent check: hash the destination's bytes from this process.
  std::uint64_t stored = 0;
  const auto digest = hash_destination_object(fabric, &stored);
  SMF_CHECK_OK(digest);
  SMF_CHECK_EQ(digest.value(), fabric.expected());
  SMF_CHECK_EQ(stored, std::uint64_t{3U * 1024U * 1024U});
  SMF_CHECK_EQ(count_commit_markers(fabric), std::size_t{1});
}

SMF_TEST(multiprocess, destination_bytes_without_marker_are_not_authority) {
  // The destination dies immediately after writing its commit marker, before it
  // can answer the coordinator. The coordinator must not assume either way.
  Fabric fabric("mp-unknown", {}, "destination.after_commit_marker=hold");
  AdminClient client = fabric.connect_admin();
  const smf::MovementId id = submit_movement(client);

  // Wait until the destination has parked at the barrier with its marker down.
  const bool parked = smftest::wait_until(
      [&]() { return count_commit_markers(fabric) == 1; }, 30000);
  if (!parked) {
    smftest::fail(__FILE__, __LINE__, "the destination never wrote its commit marker");
  }
  fabric.destination().kill();
  SMF_CHECK(!fabric.destination_running());

  const smf::MovementRecord unknown = poll_until(client, id, [](const smf::MovementRecord& r) {
    return r.state == smf::MovementState::OUTCOME_UNKNOWN || r.is_terminal();
  });
  SMF_CHECK_EQ(unknown.state, smf::MovementState::OUTCOME_UNKNOWN);

  // The bytes and the marker exist, but the coordinator has not confirmed them.
  std::uint64_t stored = 0;
  const auto digest = hash_destination_object(fabric, &stored);
  SMF_CHECK_OK(digest);
  SMF_CHECK_EQ(digest.value(), fabric.expected());
  SMF_CHECK_EQ(count_commit_markers(fabric), std::size_t{1});

  // Reconciliation against a dead destination resolves nothing.
  smf::ReconcileMovement reconcile;
  reconcile.movement_id = id;
  const auto refused = client.call<smf::ReconcileMovement, smf::MovementStatus>(reconcile);
  SMF_CHECK(!refused.ok());
  SMF_CHECK(refused.status().code() == smf::ReasonCode::REVALIDATION_REQUIRED ||
            refused.status().code() == smf::ReasonCode::ENDPOINT_NOT_LIVE);

  // Bring the destination back and reconcile again. The marker proves the
  // effect happened, so the movement commits and no second commit is written.
  fabric.restart_destination();
  SMF_CHECK(fabric.destination_running());

  smf::MovementRecord resolved;
  const bool committed = smftest::wait_until(
      [&]() {
        const auto answer = client.call<smf::ReconcileMovement, smf::MovementStatus>(reconcile);
        if (!answer.ok()) return false;
        resolved = answer.value().record;
        return resolved.state == smf::MovementState::COMMITTED;
      },
      30000);
  if (!committed) {
    smftest::fail(__FILE__, __LINE__,
                  "reconciliation did not resolve the movement; last state was " +
                      std::string(smf::to_string(resolved.state)));
  }
  SMF_CHECK_EQ(resolved.state, smf::MovementState::COMMITTED);
  SMF_CHECK_EQ(count_commit_markers(fabric), std::size_t{1});
  (void)unknown;
}

SMF_TEST(multiprocess, cancel_before_commit_leaves_no_authority) {
  Fabric fabric("mp-cancel", "source.after_chunk_send=hold");
  AdminClient client = fabric.connect_admin();
  const smf::MovementId id = submit_movement(client);

  // The source parks after its first chunk, so the transfer is genuinely in
  // flight when the operator cancels.
  const smf::MovementRecord transferring =
      poll_until(client, id, [](const smf::MovementRecord& r) {
        return r.state == smf::MovementState::TRANSFERRING;
      });

  smf::CancelMovement cancel;
  cancel.movement_id = id;
  const auto cancelled = client.call<smf::CancelMovement, smf::MovementStatus>(cancel);
  SMF_CHECK_OK(cancelled);
  SMF_CHECK_EQ(cancelled.value().record.state, smf::MovementState::CANCELLED);

  // The cancellation is durable: nothing later may resurrect the movement.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  smf::QueryMovement query;
  query.movement_id = id;
  const auto after = client.call<smf::QueryMovement, smf::MovementStatus>(query);
  SMF_CHECK_OK(after);
  SMF_CHECK_EQ(after.value().record.state, smf::MovementState::CANCELLED);

  // A cancelled movement is never authoritative, whatever residue remains.
  SMF_CHECK_EQ(count_commit_markers(fabric), std::size_t{0});
  (void)transferring;
}

SMF_TEST(multiprocess, coordinator_restart_is_conservative) {
  Fabric fabric("mp-restart", "source.after_chunk_send=hold");
  AdminClient client = fabric.connect_admin();
  const smf::MovementId id = submit_movement(client);
  (void)poll_until(client, id, [](const smf::MovementRecord& r) {
    return r.state == smf::MovementState::TRANSFERRING;
  });

  fabric.restart_coordinator();

  AdminClient restarted = fabric.connect_admin();
  smf::QueryMovement query;
  query.movement_id = id;
  const auto reloaded = restarted.call<smf::QueryMovement, smf::MovementStatus>(query);
  SMF_CHECK_OK(reloaded);

  // A restart never resurrects liveness: the movement returns conservatively.
  SMF_CHECK(reloaded.value().record.state == smf::MovementState::OUTCOME_UNKNOWN ||
            reloaded.value().record.state == smf::MovementState::FAILED);

  // Nothing is considered live until an endpoint registers again.
  smf::TopologyRequest topology;
  const auto report = restarted.call<smf::TopologyRequest, smf::TopologyReport>(topology);
  SMF_CHECK_OK(report);
  std::size_t live = 0;
  for (const smf::EndpointRegistration& endpoint : report.value().endpoints) {
    if (endpoint.live) ++live;
  }
  SMF_CHECK_EQ(live, std::size_t{0});
  SMF_CHECK_EQ(report.value().endpoints.size(), std::size_t{0});

  // The restarted coordinator advances its incarnation epoch.
  SMF_CHECK(report.value().coordinator.epoch().value() >= 2);

  // Nothing movable survives the restart. The inventory of announced versions
  // is dynamic evidence and is deliberately not restored, so the same
  // submission that was accepted before the restart is now refused. Neither the
  // old grants nor the old registrations carried across.
  smf::SubmitMovement resubmit;
  resubmit.object_id =
      smf::derive_state_object_id(smf::StateKind::GENERIC_BLOB, "demo/state").value();
  resubmit.object_generation = smf::StateGeneration(1);
  resubmit.source = smf::EndpointId::parse("source-1").value();
  resubmit.destination = smf::EndpointId::parse("dest-1").value();
  const auto refused =
      restarted.call<smf::SubmitMovement, smf::MovementAccepted>(resubmit);
  SMF_CHECK(!refused.ok());
  SMF_CHECK(refused.status().code() == smf::ReasonCode::OBJECT_NOT_FOUND ||
            refused.status().code() == smf::ReasonCode::ENDPOINT_NOT_LIVE);
}
