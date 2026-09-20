// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// An endpoint process: it holds state objects, serves them to peers that
// present a coordinator-issued grant, and receives objects from peers under the
// same authority. It never decides on its own that an object may move, and it
// never decides on its own that received bytes are authoritative.

#ifndef SMF_ENDPOINT_AGENT_HPP
#define SMF_ENDPOINT_AGENT_HPP

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "smf/bytes.hpp"
#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/object_store.hpp"
#include "smf/policy.hpp"
#include "smf/session.hpp"
#include "smf/state_object.hpp"
#include "smf/status.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"

namespace smf {

struct EndpointAgentConfig {
  EndpointId endpoint_id;
  std::filesystem::path store_root;
  Bytes shared_secret;
  SocketAddress coordinator_address;
  // Where peers connect to pull objects from this endpoint.
  SocketAddress data_listen{std::string("127.0.0.1"), 0};
  // Free-form capability text, hashed into the identity the coordinator sees.
  std::string capability = "smf.endpoint.std";
  MovementPolicy policy;
  Millis io_budget_millis = 30000;
  // Bounded pool of data-session workers. Accepting beyond this bound produces
  // an explicit refusal rather than unbounded thread growth.
  std::uint32_t max_data_sessions = 8;
  std::uint32_t max_concurrent_movements = 4;
  bool allow_resume = true;
  bool sync_store = true;
};

struct EndpointCounters {
  std::uint64_t objects_published = 0;
  std::uint64_t transfers_served = 0;
  std::uint64_t transfers_received = 0;
  std::uint64_t chunks_written = 0;
  std::uint64_t duplicate_chunks = 0;
  std::uint64_t bytes_received = 0;
  std::uint64_t bytes_sent = 0;
  std::uint64_t refusals = 0;
  std::uint64_t sessions_accepted = 0;
  std::uint64_t sessions_refused = 0;
};

class EndpointAgent {
 public:
  ~EndpointAgent();
  EndpointAgent(const EndpointAgent&) = delete;
  EndpointAgent& operator=(const EndpointAgent&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<EndpointAgent>> start(
      const EndpointAgentConfig& config);

  // Connects, authenticates, and registers with the coordinator.
  [[nodiscard]] Status connect_to_coordinator();

  // Blocks until the endpoint is asked to stop.
  void run();

  // Signals every loop to stop without joining anything. Safe to call from any
  // thread, including the coordinator link reader.
  [[nodiscard]] Status request_shutdown();

  // request_shutdown() followed by joining every worker exactly once.
  [[nodiscard]] Status stop();
  [[nodiscard]] bool stopping() const noexcept { return stopping_.load(std::memory_order_acquire); }

  [[nodiscard]] const EndpointId& endpoint_id() const noexcept { return config_.endpoint_id; }
  [[nodiscard]] const EndpointIncarnation& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] SocketAddress data_address() const;
  [[nodiscard]] SocketAddress service_address() const { return service_address_; }
  [[nodiscard]] const MovementPolicy& policy() const noexcept { return config_.policy; }
  [[nodiscard]] PolicyGeneration policy_generation() const noexcept { return policy_generation_; }
  [[nodiscard]] TopologyGeneration topology_generation() const noexcept {
    return topology_generation_;
  }

  [[nodiscard]] ObjectStore& object_store() noexcept { return *store_; }
  [[nodiscard]] const ObjectStore& object_store() const noexcept { return *store_; }

  // Copies a file into the object store, verifies it, and marks it committed
  // locally, which makes it publishable as a source.
  [[nodiscard]] Status publish_file(StateKind kind, std::string name, StateGeneration generation,
                                    const std::filesystem::path& source_file,
                                    const std::string& producer, bool repeatable);

  [[nodiscard]] Status announce(const StateObjectDescriptor& descriptor);

  [[nodiscard]] EndpointCounters counters() const;

  // Serves one inbound data session to completion on the calling thread.
  [[nodiscard]] Status serve_data_connection(TcpConnection connection);

 private:
  EndpointAgent() = default;

  struct ControlLink;

  struct GrantEntry {
    TransferGrant grant;
    bool consumed = false;
    Millis received_unix_millis = 0;
  };

  [[nodiscard]] Status open_store();
  [[nodiscard]] Status start_data_listener();
  void accept_loop();
  void session_worker_loop();
  void control_reader_loop();

  [[nodiscard]] Status handle_control(const Frame& frame);
  [[nodiscard]] Status on_grant(const TransferGrant& grant);
  [[nodiscard]] Status on_execute(const ExecuteMovement& message);
  [[nodiscard]] Status on_commit_request(const CommitRequest& message);
  [[nodiscard]] Status on_verify_request(const VerifyRequest& message);
  [[nodiscard]] Status on_authority_query(const AuthorityQuery& message);
  [[nodiscard]] Status on_cleanup_request(const CleanupRequest& message);
  [[nodiscard]] Status on_cancel(const CancelRequest& message);

  void execute_movement_worker(MovementId movement_id, TransferAttemptId attempt, Nonce nonce);
  [[nodiscard]] Status run_transfer(const TransferGrant& grant, const TransferAttemptId& attempt);

  [[nodiscard]] Status send_control(MessageType type, const CanonicalEncoder& payload);
  [[nodiscard]] Status report_attempt_result(const MovementId& movement_id,
                                             MovementGeneration generation,
                                             const TransferAttemptId& attempt, MovementState state,
                                             ReasonCode code, const std::string& detail,
                                             const Digest& verified_digest, std::uint64_t bytes,
                                             std::uint32_t chunks, const Digest& marker);

  [[nodiscard]] std::shared_ptr<std::atomic<bool>> cancellation_flag(const MovementId& movement_id);
  void clear_cancellation(const MovementId& movement_id);

  EndpointAgentConfig config_;
  EndpointIncarnation incarnation_;
  SocketAddress service_address_;
  SocketAddress data_address_;
  PolicyGeneration policy_generation_{1};
  TopologyGeneration topology_generation_{1};
  std::unique_ptr<ObjectStore> store_;

  std::unique_ptr<ControlLink> control_;
  std::unique_ptr<TcpListener> data_listener_;

  std::thread accept_thread_;
  std::vector<std::thread> session_workers_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::deque<TcpConnection> session_queue_;

  mutable std::mutex grants_mutex_;
  std::map<Nonce, GrantEntry> grants_;

  mutable std::mutex cancels_mutex_;
  std::map<MovementId, std::shared_ptr<std::atomic<bool>>> cancellations_;

  mutable std::mutex counters_mutex_;
  EndpointCounters counters_;

  std::atomic<std::uint32_t> active_sessions_{0};
  std::atomic<std::uint32_t> active_movements_{0};
  std::atomic<bool> stopping_{false};
  std::once_flag stop_once_;
  std::mutex wake_mutex_;
  std::condition_variable wake_;
};

}  // namespace smf

#endif  // SMF_ENDPOINT_AGENT_HPP
