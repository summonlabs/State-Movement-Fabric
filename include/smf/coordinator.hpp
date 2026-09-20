// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator owns movement authority. It is the only component that may
// decide that a state object version may move, that bytes that arrived are
// verified, or that a movement is committed. Every one of those decisions is
// bound to the topology, policy, and compatibility generations that were
// current when it was made, and every one of them is durable before it is
// reported.

#ifndef SMF_COORDINATOR_HPP
#define SMF_COORDINATOR_HPP

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

#include "smf/compatibility.hpp"
#include "smf/framing.hpp"
#include "smf/ids.hpp"
#include "smf/movement.hpp"
#include "smf/movement_store.hpp"
#include "smf/policy.hpp"
#include "smf/session.hpp"
#include "smf/status.hpp"
#include "smf/topology.hpp"
#include "smf/transport.hpp"
#include "smf/wire.hpp"

namespace smf {

struct CoordinatorConfig {
  EndpointId endpoint_id;
  std::filesystem::path state_directory;
  Bytes shared_secret;
  SocketAddress endpoint_listen{std::string("127.0.0.1"), 0};
  // The operator channel. It is a separate listener so that it can be bound to
  // loopback while endpoints are reachable from elsewhere.
  SocketAddress admin_listen{std::string("127.0.0.1"), 0};
  MovementPolicy policy;
  Millis io_budget_millis = 30000;
  std::uint32_t max_sessions = 64;
  std::uint32_t worker_threads = 4;
  bool sync_store = true;
  bool exclusive_lock = true;
  std::uint32_t verify_sample_chunks = 3;
  // Optional compatibility provider. When absent, movement decisions record an
  // explicit COMPATIBILITY_UNKNOWN rather than assuming support.
  std::shared_ptr<CompatibilityProvider> compatibility;
};

struct CoordinatorCounters {
  std::uint64_t sessions_accepted = 0;
  std::uint64_t sessions_refused = 0;
  std::uint64_t movements_submitted = 0;
  std::uint64_t movements_rejected = 0;
  std::uint64_t movements_committed = 0;
  std::uint64_t movements_failed = 0;
  std::uint64_t movements_cancelled = 0;
  std::uint64_t movements_superseded = 0;
  std::uint64_t outcomes_unknown = 0;
  std::uint64_t reconciliations = 0;
  std::uint64_t verification_probes = 0;
  std::uint64_t stale_rejections = 0;
};

class Coordinator {
 public:
  ~Coordinator();
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<Coordinator>> start(const CoordinatorConfig& config);

  // Blocks until the coordinator is asked to stop.
  void run();
  [[nodiscard]] Status request_shutdown();
  [[nodiscard]] Status stop();
  [[nodiscard]] bool stopping() const noexcept { return stopping_.load(std::memory_order_acquire); }

  [[nodiscard]] SocketAddress endpoint_address() const;
  [[nodiscard]] SocketAddress admin_address() const;
  [[nodiscard]] const EndpointIncarnation& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] PolicyGeneration policy_generation() const noexcept { return policy_.generation; }
  [[nodiscard]] TopologyGeneration topology_generation() const;
  [[nodiscard]] Digest policy_digest() const { return policy_.digest(); }

  // ---- authoritative operations, also reachable over the admin channel ----
  [[nodiscard]] Result<MovementAccepted> submit(const SubmitMovement& request);
  [[nodiscard]] Result<MovementRecord> query(const MovementId& id) const;
  [[nodiscard]] Result<std::vector<MovementSummary>> list(std::uint32_t limit,
                                                          std::uint32_t offset) const;
  [[nodiscard]] Result<MovementRecord> cancel(const MovementId& id);
  [[nodiscard]] Result<MovementRecord> reconcile(const MovementId& id);
  [[nodiscard]] Result<ProvenanceReport> provenance(const MovementId& id) const;
  [[nodiscard]] TopologyReport topology_report() const;
  [[nodiscard]] PolicyReport policy_report() const;

  [[nodiscard]] CoordinatorCounters counters() const;
  [[nodiscard]] MovementStore& store() noexcept { return *store_; }

  // Test seam: block until no movement is actively being worked on.
  void wait_for_idle();

 private:
  Coordinator() = default;

  struct ControlLink {
    FrameStream stream;
    EndpointId endpoint;
    std::mutex send_mutex;
    std::thread reader;
    std::atomic<bool> alive{true};
    std::mutex pending_mutex;
    std::map<std::string, std::shared_ptr<std::promise<Frame>>> pending;

    explicit ControlLink(FrameStream connection) : stream(std::move(connection)) {}
  };

  [[nodiscard]] Status open_store();
  void recover_after_restart();
  void accept_loop(bool admin);
  [[nodiscard]] Status session_loop(TcpConnection connection, bool admin);
  [[nodiscard]] Status handle_endpoint_message(const std::shared_ptr<ControlLink>& link,
                                               const Frame& frame);
  [[nodiscard]] Status handle_admin_message(const std::shared_ptr<ControlLink>& link,
                                            const Frame& frame);
  [[nodiscard]] bool deliver(const std::shared_ptr<ControlLink>& link, const Frame& frame);

  [[nodiscard]] Result<std::shared_ptr<ControlLink>> find_link(const EndpointId& endpoint) const;
  // Reserves a response slot before the request is sent, so that a fast answer
  // can never arrive before anyone is listening for it.
  [[nodiscard]] Result<std::future<Frame>> reserve(const std::shared_ptr<ControlLink>& link,
                                                   const std::string& key);
  [[nodiscard]] Result<Frame> await(const std::shared_ptr<ControlLink>& link, const std::string& key,
                                    std::future<Frame>& future, const char* what);
  void release(const std::shared_ptr<ControlLink>& link, const std::string& key);
  [[nodiscard]] Result<Frame> request(const std::shared_ptr<ControlLink>& link, const std::string& key,
                                      MessageType type, const CanonicalEncoder& payload);
  [[nodiscard]] Status push(const std::shared_ptr<ControlLink>& link, MessageType type,
                            const CanonicalEncoder& payload);
  [[nodiscard]] Digest digest_of_capability() const;

  void worker_loop();
  void enqueue(const MovementId& id);
  [[nodiscard]] Status drive_movement(const MovementId& id);

  [[nodiscard]] Result<MovementRecord> authorize(const MovementRecord& record);
  [[nodiscard]] Result<Digest> verify_destination(const MovementRecord& record);
  [[nodiscard]] Status persist(MovementRecord& record);
  [[nodiscard]] Result<AttemptResult> await_attempt(const MovementRecord& record,
                                                    const TransferAttemptId& attempt);
  [[nodiscard]] Status classify_attempt_failure(MovementRecord& record, const AttemptResult& result);

  [[nodiscard]] MovementSummary to_summary(const MovementRecord& record) const;
  void count(const std::function<void(CoordinatorCounters&)>& update);

  CoordinatorConfig config_;
  EndpointIncarnation incarnation_;
  PolicySet policy_;
  std::unique_ptr<MovementStore> store_;
  TopologyView topology_;
  std::shared_ptr<CompatibilityProvider> compatibility_;
  CompatibilityGeneration compatibility_generation_{1};

  std::unique_ptr<TcpListener> endpoint_listener_;
  std::unique_ptr<TcpListener> admin_listener_;
  std::thread endpoint_accept_thread_;
  std::thread admin_accept_thread_;
  std::vector<std::thread> session_threads_;
  std::mutex sessions_mutex_;
  std::atomic<std::uint32_t> active_sessions_{0};

  mutable std::mutex links_mutex_;
  std::map<EndpointId, std::shared_ptr<ControlLink>> links_;

  // What sources have announced they hold. This is evidence about a source's
  // own store, not authority: it only says which version may be asked for.
  mutable std::mutex inventory_mutex_;
  std::map<StateObjectId, StateObjectDescriptor> inventory_;
  std::map<StateObjectId, EndpointId> inventory_source_;

  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::condition_variable idle_cv_;
  std::deque<MovementId> queue_;
  std::vector<std::thread> workers_;
  std::atomic<std::uint32_t> active_movements_{0};

  mutable std::mutex counters_mutex_;
  CoordinatorCounters counters_;

  std::atomic<bool> stopping_{false};
  std::once_flag stop_once_;
  std::mutex wake_mutex_;
  std::condition_variable wake_;
};

}  // namespace smf

#endif  // SMF_COORDINATOR_HPP
