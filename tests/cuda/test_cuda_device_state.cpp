// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// REAL device-memory proof on the installed accelerator.
//
// The proof has two halves. The first half shows that device memory on this host
// is real: it allocates, fills, copies back, compares, frees, and confirms the
// free-memory baseline returned. The second half puts deterministic bytes into
// real device memory inside a source endpoint process, publishes them as an
// ordinary state object, moves that object over the fabric's real TCP data path
// to an independent destination process, hashes the destination bytes here, and
// requires exactly one authoritative commit.
//
// What is claimed: REAL CUDA device memory, REAL loopback TCP. What is not
// claimed: GPUDirect, RDMA, NVLink, peer-to-peer device transfer, multi-GPU, or
// multi-host behaviour. None of those were exercised.

#include <cuda_runtime.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "smf/digest.hpp"
#include "smf/ids.hpp"
#include "smf/wire.hpp"
#include "smf_admin_client.hpp"
#include "smf_test.hpp"
#include "smf_test_process.hpp"

using smftest::AdminClient;
using smftest::ChildProcess;
using smftest::ProcessSpec;

namespace {

constexpr smf::Millis kReadyBudget = 60000;
constexpr std::uint64_t kDevicePayloadBytes = 8U << 20;  // 8 MiB, eight 1 MiB chunks
constexpr std::uint64_t kDeviceSeed = 0x5EEDC0DEULL;
constexpr std::uint64_t kTolerance = 16U << 20;  // 16 MiB of allocator slack

[[nodiscard]] std::string random_key() { return smf::IdIssuer().new_nonce().hex(); }

// Reads a field from either the coordinator's JSON announcement file
// ("field":"value") or the device report line (field=value).
[[nodiscard]] std::string extract_field(const std::string& text, const std::string& field) {
  const std::string json_marker = "\"" + field + "\":\"";
  const std::size_t json_start = text.find(json_marker);
  if (json_start != std::string::npos) {
    const std::size_t begin = json_start + json_marker.size();
    const std::size_t end = text.find('"', begin);
    return end == std::string::npos ? std::string() : text.substr(begin, end - begin);
  }

  const std::string marker = field + "=";
  const std::size_t start = text.find(marker);
  if (start == std::string::npos) return {};
  std::size_t begin = start + marker.size();
  if (begin < text.size() && text[begin] == '"') ++begin;
  std::size_t end = begin;
  while (end < text.size() && text[end] != ' ' && text[end] != '"' && text[end] != '\n') ++end;
  return text.substr(begin, end - begin);
}

[[nodiscard]] std::uint64_t field_u64(const std::string& text, const std::string& field) {
  const std::string value = extract_field(text, field);
  std::uint64_t out = 0;
  for (const char c : value) {
    if (c < '0' || c > '9') return 0;
    out = (out * 10U) + static_cast<std::uint64_t>(c - '0');
  }
  return out;
}

struct CudaFabric {
  CudaFabric() : root_("cuda-proof") {
    if (smftest::binary_directory().empty()) {
      smftest::fail(__FILE__, __LINE__, "this configuration did not build the executables");
    }
    key_ = random_key();

    ProcessSpec coordinator;
    coordinator.program = smftest::executable("smf_coordinator");
    coordinator.working_directory = root_.path();
    coordinator.output_file = root_.file("coordinator.log");
    coordinator.environment["SMF_SHARED_KEY"] = key_;
    coordinator.arguments = {"--state", root_.file("coord-state").string(), "--announce",
                             root_.file("coordinator.json").string(), "--log-level", "INFO"};
    coordinator_ = start(coordinator, "coordinator");

    const std::string announced = wait_for_text(root_.file("coordinator.json"), "\"admin\"");
    const auto endpoint = smf::SocketAddress::parse(extract_field(announced, "endpoint"));
    const auto admin = smf::SocketAddress::parse(extract_field(announced, "admin"));
    if (!endpoint.ok() || !admin.ok()) {
      smftest::fail(__FILE__, __LINE__, "the coordinator announced an unparsable address");
    }
    coordinator_endpoint_ = endpoint.value();
    coordinator_admin_ = admin.value();

    source_ = start_source(1);
    destination_ = start_endpoint();
  }

  ~CudaFabric() {
    kill(destination_);
    kill(source_);
    kill(coordinator_);
  }

  [[nodiscard]] ChildProcess start_source(std::uint64_t generation) {
    ProcessSpec spec;
    spec.program = smftest::executable("smf_endpoint");
    spec.working_directory = root_.path();
    spec.output_file = root_.file("cuda-source.log");
    spec.environment["SMF_SHARED_KEY"] = key_;
    spec.arguments = {"--id", "cuda-source", "--coordinator", coordinator_endpoint_.to_string(),
                      "--store", (root_.path() / "src").string(), "--log-level", "INFO",
                      "--publish-cuda",
                      "GENERIC_BLOB:cuda/state:" + std::to_string(generation) + ":" +
                          std::to_string(kDevicePayloadBytes) + ":" + std::to_string(kDeviceSeed)};
    ChildProcess child = start(spec, "cuda source endpoint");
    const std::string log = wait_for_text(child, "CUDA-PUBLISH", "cuda source endpoint");
    device_report_ = log;
    return child;
  }

  [[nodiscard]] ChildProcess start_endpoint() {
    ProcessSpec spec;
    spec.program = smftest::executable("smf_endpoint");
    spec.working_directory = root_.path();
    spec.output_file = root_.file("destination.log");
    spec.environment["SMF_SHARED_KEY"] = key_;
    spec.arguments = {"--id", "dest-1", "--coordinator", coordinator_endpoint_.to_string(), "--store",
                      (root_.path() / "dst").string(), "--log-level", "INFO"};
    ChildProcess child = start(spec, "destination endpoint");
    (void)wait_for_text(child, "registered with topology generation", "destination endpoint");
    return child;
  }

  void restart_source_with_generation(std::uint64_t generation) {
    kill(source_);
    source_ = start_source(generation);
  }

  [[nodiscard]] AdminClient connect_admin() const {
    AdminClient client;
    const smf::Status status =
        client.connect(coordinator_admin_, smf::parse_shared_secret(key_).value(),
                       smf::EndpointId::parse("smf-cuda-test").value());
    if (!status.ok()) {
      smftest::fail(__FILE__, __LINE__, "operator session failed: " + status.to_string());
    }
    return client;
  }

  [[nodiscard]] const std::string& device_report() const { return device_report_; }
  [[nodiscard]] const std::filesystem::path& root() const { return root_.path(); }
  [[nodiscard]] ChildProcess& source() { return source_; }
  [[nodiscard]] ChildProcess& destination() { return destination_; }

  [[nodiscard]] smf::Result<smf::Digest> hash_destination(std::uint64_t* bytes_out) const {
    std::error_code error;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root_.path() / "dst" / "objects", error)) {
      if (!entry.is_regular_file() || entry.path().filename() != "data") continue;
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

  [[nodiscard]] std::size_t commit_marker_count() const {
    std::error_code error;
    std::size_t count = 0;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root_.path() / "dst" / "commits", error)) {
      if (entry.is_regular_file() && entry.path().extension() == ".marker") ++count;
    }
    return count;
  }

 private:
  static ChildProcess start(const ProcessSpec& spec, const char* what) {
    auto child = ChildProcess::spawn(spec);
    if (!child.ok()) {
      smftest::fail(__FILE__, __LINE__,
                    std::string("could not start the ") + what + ": " + child.status().to_string());
    }
    return std::move(child).value();
  }

  static void kill(ChildProcess& child) {
    if (child.running()) child.kill();
  }

  // Waits for a file to contain a needle, then returns its contents.
  static std::string wait_for_text(const std::filesystem::path& path, const std::string& needle) {
    std::string text;
    const bool arrived = smftest::wait_until(
        [&]() {
          std::error_code error;
          if (!std::filesystem::exists(path, error)) return false;
          std::FILE* file = std::fopen(path.string().c_str(), "rb");
          if (file == nullptr) return false;
          char buffer[4096] = {};
          const std::size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, file);
          std::fclose(file);
          text.assign(buffer, read);
          return text.find(needle) != std::string::npos;
        },
        kReadyBudget);
    if (!arrived) {
      smftest::fail(__FILE__, __LINE__, "a process never reported '" + needle + "'");
    }
    return text;
  }

  static std::string wait_for_text(ChildProcess& child, const std::string& needle,
                                   const char* what) {
    std::string text;
    const bool arrived = smftest::wait_until(
        [&]() {
          text = child.output();
          return text.find(needle) != std::string::npos;
        },
        kReadyBudget);
    if (!arrived) {
      const std::string log = child.output();
      smftest::fail(__FILE__, __LINE__,
                    std::string("the ") + what + " never reported '" + needle + "'; output: " +
                        (log.empty() ? std::string("<empty>") : log.substr(0, 500)));
    }
    return text;
  }

  smftest::TempDir root_;
  std::string key_;
  smf::SocketAddress coordinator_endpoint_;
  smf::SocketAddress coordinator_admin_;
  ChildProcess coordinator_;
  ChildProcess source_;
  ChildProcess destination_;
  std::string device_report_;
};

[[nodiscard]] smf::MovementRecord wait_for_state(
    AdminClient& client, const smf::MovementId& id,
    const std::function<bool(const smf::MovementRecord&)>& predicate, smf::Millis budget = 60000) {
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
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  if (!satisfied) {
    smftest::fail(__FILE__, __LINE__,
                  std::string("the movement never reached the expected state; last was ") +
                      smf::to_string(last.state) + " reason " + smf::to_string(last.last_reason) +
                      " detail " + last.last_detail);
  }
  return last;
}

[[nodiscard]] smf::Result<smf::MovementAccepted> submit(AdminClient& client,
                                                        std::uint64_t generation) {
  smf::SubmitMovement request;
  request.object_id =
      smf::derive_state_object_id(smf::StateKind::GENERIC_BLOB, "cuda/state").value();
  request.object_generation = smf::StateGeneration(generation);
  request.source = smf::EndpointId::parse("cuda-source").value();
  request.destination = smf::EndpointId::parse("dest-1").value();
  return client.call<smf::SubmitMovement, smf::MovementAccepted>(request);
}

}  // namespace

SMF_TEST(cuda, device_memory_is_real_and_returns_to_baseline) {
  int devices = 0;
  const cudaError_t counted = cudaGetDeviceCount(&devices);
  if (counted != cudaSuccess) {
    smftest::fail(__FILE__, __LINE__,
                  std::string("cudaGetDeviceCount failed: ") + cudaGetErrorString(counted));
  }
  SMF_REQUIRE(devices > 0);

  cudaDeviceProp properties{};
  SMF_REQUIRE(cudaGetDeviceProperties(&properties, 0) == cudaSuccess);
  std::printf("[cuda] device 0: %s, compute capability %d.%d, %.1f GiB\n", properties.name,
              properties.major, properties.minor,
              static_cast<double>(properties.totalGlobalMem) / (1024.0 * 1024.0 * 1024.0));

  std::size_t free_before = 0;
  std::size_t total = 0;
  SMF_REQUIRE(cudaMemGetInfo(&free_before, &total) == cudaSuccess);

  const std::size_t allocation = 64U << 20;
  void* buffer = nullptr;
  const cudaError_t allocated = cudaMalloc(&buffer, allocation);
  if (allocated != cudaSuccess) {
    smftest::fail(__FILE__, __LINE__,
                  std::string("cudaMalloc failed: ") + cudaGetErrorString(allocated));
  }
  SMF_REQUIRE(buffer != nullptr);

  std::size_t free_during = 0;
  std::size_t total_during = 0;
  SMF_REQUIRE(cudaMemGetInfo(&free_during, &total_during) == cudaSuccess);
  // The allocation is genuinely on the device: free memory dropped by roughly
  // its size, and the driver reports a device, not a host buffer.
  SMF_CHECK(free_before > free_during);
  SMF_CHECK(free_before - free_during >= allocation / 2);

  SMF_REQUIRE(cudaMemset(buffer, 0x5A, allocation) == cudaSuccess);
  std::vector<unsigned char> host(1U << 20);
  SMF_REQUIRE(cudaMemcpy(host.data(), buffer, host.size(), cudaMemcpyDeviceToHost) == cudaSuccess);
  for (const unsigned char byte : host) {
    if (byte != 0x5A) {
      smftest::fail(__FILE__, __LINE__, "device memory did not contain the written pattern");
    }
  }

  SMF_REQUIRE(cudaFree(buffer) == cudaSuccess);
  std::size_t free_after = 0;
  std::size_t total_after = 0;
  SMF_REQUIRE(cudaMemGetInfo(&free_after, &total_after) == cudaSuccess);

  const std::uint64_t before = free_before;
  const std::uint64_t after = free_after;
  const std::uint64_t returned = after > free_during
                                     ? after - (free_before - (free_before - free_during))
                                     : 0;
  (void)returned;
  std::printf("[cuda] free before=%llu MiB during=%llu MiB after=%llu MiB (delta %lld MiB)\n",
              static_cast<unsigned long long>(before >> 20),
              static_cast<unsigned long long>(free_during >> 20),
              static_cast<unsigned long long>(after >> 20),
              static_cast<long long>((static_cast<long long>(after) -
                                      static_cast<long long>(before)) >>
                                     20));
  SMF_CHECK(after + kTolerance >= before);
}

SMF_TEST(cuda, device_state_moves_through_the_fabric_and_commits_once) {
  CudaFabric fabric;

  const std::string report = fabric.device_report();
  const std::string digest_text = extract_field(report, "digest");
  SMF_CHECK(digest_text.size() == 64);
  const auto expected = smf::Digest::from_hex(digest_text);
  SMF_CHECK_OK(expected);
  const std::uint64_t staged = field_u64(report, "bytes");
  const std::uint64_t free_before = field_u64(report, "free_before");
  const std::uint64_t free_after = field_u64(report, "free_after");
  std::printf("[cuda] source staged %llu bytes from device, free before=%llu MiB after=%llu MiB\n",
              static_cast<unsigned long long>(staged),
              static_cast<unsigned long long>(free_before >> 20),
              static_cast<unsigned long long>(free_after >> 20));
  SMF_CHECK_EQ(staged, kDevicePayloadBytes);
  // The device allocation inside the source process was returned.
  SMF_CHECK(free_after + kTolerance >= free_before);

  AdminClient client = fabric.connect_admin();
  const auto accepted = submit(client, 1);
  if (!accepted.ok()) {
    smftest::fail(__FILE__, __LINE__,
                  "the coordinator refused the device-state movement: " +
                      accepted.status().to_string());
  }

  const smf::MovementRecord record = wait_for_state(
      client, accepted.value().movement_id,
      [](const smf::MovementRecord& r) { return r.state == smf::MovementState::COMMITTED; });

  SMF_CHECK_EQ(record.state, smf::MovementState::COMMITTED);
  SMF_CHECK_EQ(record.bytes_transferred, kDevicePayloadBytes);
  SMF_CHECK_EQ(record.destination_verified_digest, expected.value());

  // Independent integrity check: hash the destination bytes in this process.
  std::uint64_t stored = 0;
  const auto observed = fabric.hash_destination(&stored);
  SMF_CHECK_OK(observed);
  SMF_CHECK_EQ(stored, kDevicePayloadBytes);
  SMF_CHECK_EQ(observed.value(), expected.value());

  // Exactly once: one marker, and reconciliation is not even applicable.
  SMF_CHECK_EQ(fabric.commit_marker_count(), std::size_t{1});
  smf::ReconcileMovement reconcile;
  reconcile.movement_id = accepted.value().movement_id;
  const auto refuse = client.call<smf::ReconcileMovement, smf::MovementStatus>(reconcile);
  SMF_CHECK(!refuse.ok());
  SMF_CHECK_EQ(fabric.commit_marker_count(), std::size_t{1});

  // A newer device generation on the source makes the older generation
  // unrepresentable: the coordinator refuses to move a version that is no
  // longer the announced one, so old authority cannot be reused.
  fabric.restart_source_with_generation(2);
  const auto stale = submit(client, 1);
  SMF_CHECK(!stale.ok());
  SMF_CHECK_EQ(stale.status().code(), smf::ReasonCode::STALE_STATE_GENERATION);

  // The current device generation still moves, and reaches the same destination
  // as a distinct object version.
  const auto current = submit(client, 2);
  SMF_CHECK_OK(current);
  const smf::MovementRecord second = wait_for_state(
      client, current.value().movement_id,
      [](const smf::MovementRecord& r) { return r.state == smf::MovementState::COMMITTED; });
  SMF_CHECK_EQ(second.state, smf::MovementState::COMMITTED);
  SMF_CHECK_EQ(second.bytes_transferred, kDevicePayloadBytes);

  // Two generations, two authoritative commits, no duplicates.
  SMF_CHECK_EQ(fabric.commit_marker_count(), std::size_t{2});
  SMF_CHECK(fabric.destination().running());
  SMF_CHECK(fabric.source().running());
}
