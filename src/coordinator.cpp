// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/coordinator.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <system_error>

#include "file_utils.hpp"
#include "smf/chunk_plan.hpp"
#include "smf/fault_injection.hpp"
#include "smf/limits.hpp"
#include "smf/logging.hpp"
#include "smf/version.hpp"

namespace smf {
namespace {

[[nodiscard]] std::string key_for(MessageType type, const std::string& subject) {
  return std::string(to_string(type)) + ":" + subject;
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

Coordinator::~Coordinator() {
  const Status status = stop();
  (void)status;
}

Result<std::unique_ptr<Coordinator>> Coordinator::start(const CoordinatorConfig& config) {
  if (config.endpoint_id.empty()) {
    return Status(ReasonCode::INVALID_ID, "the coordinator needs an endpoint name");
  }
  if (config.shared_secret.size() != Digest::kBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT, "the shared secret must be exactly 32 bytes");
  }
  if (config.state_directory.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "the coordinator state directory must not be empty");
  }
  const Status policy_status = config.policy.validate();
  if (!policy_status.ok()) return policy_status;

  auto coordinator = std::unique_ptr<Coordinator>(new Coordinator());
  coordinator->config_ = config;
  coordinator->policy_.generation = PolicyGeneration(1);
  coordinator->policy_.policy = config.policy;

  SMF_RETURN_IF_ERROR(coordinator->open_store());

  // The epoch advances on every start, so a decision recorded by a previous
  // incarnation can never be mistaken for a current one.
  IncarnationEpoch epoch(1);
  if (const auto previous = coordinator->store_->load_coordinator_state(); previous.ok()) {
    const auto next = previous.value().epoch.next();
    if (next.ok()) epoch = next.value();
  }
  IdIssuer issuer;
  const auto incarnation = EndpointIncarnation::make(config.endpoint_id, issuer.new_boot_id(), epoch);
  if (!incarnation.ok()) return incarnation.status();
  coordinator->incarnation_ = incarnation.value();

  coordinator->topology_.set_coordinator(coordinator->incarnation_);

  CoordinatorPersistentState state;
  state.epoch = epoch;
  state.policy_generation = coordinator->policy_.generation;
  state.compatibility_generation = coordinator->compatibility_generation_;
  state.topology_generation = coordinator->topology_.generation();
  state.policy_digest = coordinator->policy_.digest();
  state.last_saved_unix_millis = system_clock().unix_millis();
  SMF_RETURN_IF_ERROR(coordinator->store_->save_coordinator_state(state));

  coordinator->compatibility_ = config.compatibility;

  // Listeners before recovery: recovery may want to reach a destination.
  {
    auto listener = TcpListener::bind(config.endpoint_listen);
    if (!listener.ok()) return listener.status();
    coordinator->endpoint_listener_ =
        std::make_unique<TcpListener>(std::move(listener).value());
  }
  {
    auto listener = TcpListener::bind(config.admin_listen);
    if (!listener.ok()) return listener.status();
    coordinator->admin_listener_ = std::make_unique<TcpListener>(std::move(listener).value());
  }

  coordinator->recover_after_restart();

  const std::uint32_t workers = config.worker_threads == 0 ? 1 : config.worker_threads;
  coordinator->workers_.reserve(workers);
  for (std::uint32_t i = 0; i < workers; ++i) {
    coordinator->workers_.emplace_back([instance = coordinator.get()]() { instance->worker_loop(); });
  }

  coordinator->endpoint_accept_thread_ =
      std::thread([instance = coordinator.get()]() { instance->accept_loop(false); });
  coordinator->admin_accept_thread_ =
      std::thread([instance = coordinator.get()]() { instance->accept_loop(true); });

  log_message(LogLevel::INFO, "coordinator",
              "listening for endpoints on " + coordinator->endpoint_address().to_string() +
                  " and for operators on " + coordinator->admin_address().to_string());
  return coordinator;
}

Status Coordinator::open_store() {
  MovementStoreOptions options;
  options.directory = config_.state_directory;
  options.max_history_records = config_.policy.max_history_records;
  options.max_store_bytes = config_.policy.max_store_bytes;
  options.retention_completed = 10;
  options.sync_on_write = config_.sync_store;
  options.exclusive_lock = config_.exclusive_lock;

  StoreRecoveryReport report;
  auto store = MovementStore::open(options, &report);
  if (!store.ok()) return store.status();
  store_ = std::move(store).value();

  if (report.partial_tail_truncated) {
    log_message(LogLevel::WARN, "coordinator",
                "discarded a torn tail of " + std::to_string(report.truncated_bytes) +
                    " bytes during recovery; every complete record before it was applied");
  }
  return Status::success();
}

void Coordinator::recover_after_restart() {
  // A restart invalidates every dynamic fact. Endpoints must re-register, the
  // topology generation advances, and no transfer grant survives. Movements
  // that were mid-flight therefore return conservatively.
  topology_.reset_dynamic_state();

  std::uint64_t revisited = 0;
  std::uint64_t unknown = 0;
  const auto listed = store_->list(config_.policy.max_history_records, 0);
  if (!listed.ok()) return;

  for (const MovementRecord& stored : listed.value()) {
    if (stored.is_terminal()) continue;
    ++revisited;

    MovementRecord record = stored;
    MovementDecision decision;
    ProvenanceEventKind kind = ProvenanceEventKind::OUTCOME_UNKNOWN;
    MovementState next = MovementState::OUTCOME_UNKNOWN;

    if (stored.state == MovementState::PLANNED) {
      // Nothing was ever dispatched, so no effect can have happened.
      next = MovementState::FAILED;
      kind = ProvenanceEventKind::FAILED;
      decision = MovementDecision::deny(ReasonCode::REVALIDATION_REQUIRED,
                                        "the coordinator restarted before the movement was authorized");
    } else {
      ++unknown;
      decision = MovementDecision::deny(
          ReasonCode::REVALIDATION_REQUIRED,
          "the coordinator restarted while the movement was in flight; the outcome must be "
          "reconciled rather than assumed");
    }

    const Status applied =
        apply_transition(record, next, decision, kind, system_clock().unix_millis());
    if (applied.ok()) {
      const Status saved = store_->put(record);
      (void)saved;
    }
  }

  if (revisited > 0) {
    log_message(LogLevel::WARN, "coordinator",
                "recovery revisited " + std::to_string(revisited) + " movement(s); " +
                    std::to_string(unknown) +
                    " now require reconciliation and no endpoint is considered live");
  }
}

SocketAddress Coordinator::endpoint_address() const {
  return endpoint_listener_ != nullptr ? endpoint_listener_->address() : SocketAddress{};
}

SocketAddress Coordinator::admin_address() const {
  return admin_listener_ != nullptr ? admin_listener_->address() : SocketAddress{};
}

TopologyGeneration Coordinator::topology_generation() const { return topology_.generation(); }

CoordinatorCounters Coordinator::counters() const {
  std::lock_guard<std::mutex> lock(counters_mutex_);
  return counters_;
}

void Coordinator::count(const std::function<void(CoordinatorCounters&)>& update) {
  std::lock_guard<std::mutex> lock(counters_mutex_);
  update(counters_);
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

void Coordinator::accept_loop(bool admin) {
  TcpListener* listener = admin ? admin_listener_.get() : endpoint_listener_.get();
  while (!stopping_.load(std::memory_order_acquire)) {
    if (listener == nullptr) return;
    auto connection = listener->accept(100);
    if (!connection.ok()) {
      if (stopping_.load(std::memory_order_acquire)) return;
      const ReasonCode code = connection.status().code();
      if (code == ReasonCode::IO_TIMEOUT || code == ReasonCode::SHUTTING_DOWN) continue;
      log_message(LogLevel::WARN, "coordinator", "accept failed: " + connection.status().to_string());
      continue;
    }

    if (active_sessions_.load(std::memory_order_acquire) >= config_.max_sessions) {
      count([](CoordinatorCounters& c) { c.sessions_refused += 1; });
      TcpConnection refused = std::move(connection).value();
      const Status shutdown_status = refused.shutdown();
      (void)shutdown_status;
      continue;
    }

    active_sessions_.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    session_threads_.emplace_back(
        [this, connection = std::move(connection).value(), admin]() mutable {
          const Status status = [&]() -> Status {
            return session_loop(std::move(connection), admin);
          }();
          if (!status.ok() && !stopping_.load(std::memory_order_acquire)) {
            log_message(LogLevel::DEBUG, "coordinator", "session ended: " + status.to_string());
          }
          active_sessions_.fetch_sub(1, std::memory_order_acq_rel);
        });
  }
}

Status Coordinator::session_loop(TcpConnection connection, bool admin) {
  FrameStream stream(std::move(connection), config_.io_budget_millis,
                     static_cast<std::uint32_t>(config_.policy.max_chunk_bytes + (64U << 10)));

  IdIssuer issuer;
  const auto hello_frame = stream.receive();
  if (!hello_frame.ok()) return hello_frame.status();
  if (hello_frame.value().header.type != MessageType::HELLO) {
    return Status(ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED, "sessions begin with a hello");
  }
  const auto hello = decode_message<HelloRequest>(hello_frame.value());
  if (!hello.ok()) return hello.status();

  const SessionRole required = admin ? SessionRole::ADMIN : SessionRole::ENDPOINT;
  if (hello.value().identity.role != required) {
    HelloResponse rejection;
    rejection.server_nonce = issuer.new_nonce();
    rejection.session_id = issuer.new_session_id();
    rejection.identity.endpoint = config_.endpoint_id;
    rejection.identity.boot = incarnation_.boot();
    rejection.identity.epoch = incarnation_.epoch();
    rejection.identity.role = required;
    rejection.identity.contract = std::string(kPeerContract);
    rejection.identity.capability_digest = digest_of_capability();
    rejection.server_mac = Digest();
    CanonicalEncoder encoder;
    rejection.encode(encoder);
    const Status sent = stream.send(MessageType::HELLO_REJECT, encoder.view());
    (void)sent;
    return Status(ReasonCode::NOT_AUTHORIZED,
                  "this listener serves a different session role than the one offered");
  }

  PeerIdentity self;
  self.endpoint = config_.endpoint_id;
  self.boot = incarnation_.boot();
  self.epoch = incarnation_.epoch();
  self.role = required;
  self.contract = std::string(kPeerContract);
  self.capability_digest = digest_of_capability();

  const SessionId session_id = issuer.new_session_id();
  const auto response =
      accept_hello_request(smf::as_bytes(config_.shared_secret), hello.value(), self, session_id, issuer);
  if (!response.ok()) {
    count([](CoordinatorCounters& c) { c.sessions_refused += 1; });
    return response.status();
  }
  {
    CanonicalEncoder encoder;
    response.value().encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::HELLO_ACK, encoder.view()));
  }
  stream.codec().set_session_key(
      derive_session_key(smf::as_bytes(config_.shared_secret), hello.value().client_nonce,
                         response.value().server_nonce)
          .view());
  count([](CoordinatorCounters& c) { c.sessions_accepted += 1; });

  auto link = std::make_shared<ControlLink>(std::move(stream));
  link->endpoint = hello.value().identity.endpoint;

  for (;;) {
    auto frame = link->stream.receive();
    if (!frame.ok()) {
      if (!stopping_.load(std::memory_order_acquire)) {
        log_message(LogLevel::DEBUG, "coordinator",
                    "session with " + link->endpoint.value() + " ended: " +
                        frame.status().to_string());
      }
      break;
    }

    if (deliver(link, frame.value())) {
      continue;
    }

    const Status handled = admin ? handle_admin_message(link, frame.value())
                                 : handle_endpoint_message(link, frame.value());
    if (!handled.ok()) {
      ErrorMessage error;
      error.code = handled.code();
      error.detail = handled.message();
      CanonicalEncoder encoder;
      error.encode(encoder);
      const Status sent = push(link, MessageType::ERROR, encoder);
      (void)sent;
    }
  }

  link->alive.store(false, std::memory_order_release);
  {
    std::lock_guard<std::mutex> lock(link->pending_mutex);
    for (auto& entry : link->pending) {
      if (entry.second) entry.second->set_value(Frame{});
    }
    link->pending.clear();
  }
  {
    std::lock_guard<std::mutex> lock(links_mutex_);
    for (auto it = links_.begin(); it != links_.end();) {
      it = (it->second == link) ? links_.erase(it) : std::next(it);
    }
  }
  if (!admin) {
    const Status removed = topology_.mark_dead(link->endpoint);
    (void)removed;
  }
  return Status::success();
}

bool Coordinator::deliver(const std::shared_ptr<ControlLink>& link, const Frame& frame) {
  std::string key;
  switch (frame.header.type) {
    case MessageType::GRANT_ACK: {
      const auto message = decode_message<GrantAck>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::GRANT_ACK, message.value().nonce.hex());
      break;
    }
    case MessageType::ATTEMPT_RESULT: {
      const auto message = decode_message<AttemptResult>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::ATTEMPT_RESULT, message.value().movement_id.hex());
      break;
    }
    case MessageType::COMMIT_RESULT: {
      const auto message = decode_message<CommitResult>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::COMMIT_RESULT, message.value().movement_id.hex());
      break;
    }
    case MessageType::VERIFY_RESPONSE: {
      const auto message = decode_message<VerifyResponse>(frame);
      if (!message.ok()) return false;
      const std::string subject =
          message.value().movement_id.hex() + ":" +
          (message.value().code == ReasonCode::OK && message.value().stored_chunks == 0 &&
                   message.value().chunk_index == 0 && !message.value().chunk_payload.empty()
               ? std::to_string(message.value().chunk_index)
               : std::to_string(message.value().chunk_index));
      key = key_for(MessageType::VERIFY_RESPONSE, message.value().movement_id.hex() + ":" +
                                                      std::to_string(message.value().chunk_index));
      (void)subject;
      break;
    }
    case MessageType::AUTHORITY_REPORT: {
      const auto message = decode_message<AuthorityReport>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::AUTHORITY_REPORT, message.value().movement_id.hex());
      break;
    }
    case MessageType::CLEANUP_RESULT: {
      const auto message = decode_message<CleanupResult>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::CLEANUP_RESULT, message.value().movement_id.hex());
      break;
    }
    case MessageType::CANCEL_ACK: {
      const auto message = decode_message<CancelAck>(frame);
      if (!message.ok()) return false;
      key = key_for(MessageType::CANCEL_ACK, message.value().movement_id.hex());
      break;
    }
    case MessageType::TOPOLOGY_REPORT:
    case MessageType::POLICY_REPORT:
    case MessageType::HEARTBEAT_ACK:
      key = to_string(frame.header.type);
      break;
    default:
      return false;
  }

  std::shared_ptr<std::promise<Frame>> promise;
  {
    std::lock_guard<std::mutex> lock(link->pending_mutex);
    const auto found = link->pending.find(key);
    if (found == link->pending.end()) return false;
    promise = found->second;
    link->pending.erase(found);
  }
  // Fulfilled with no lock held, so a waiter that wakes immediately cannot
  // race the reader back into this map.
  promise->set_value(frame);
  return true;
}

Result<std::shared_ptr<Coordinator::ControlLink>> Coordinator::find_link(
    const EndpointId& endpoint) const {
  std::lock_guard<std::mutex> lock(links_mutex_);
  const auto found = links_.find(endpoint);
  if (found == links_.end() || !found->second->alive.load(std::memory_order_acquire)) {
    return Status(ReasonCode::ENDPOINT_NOT_LIVE,
                  "no live control session exists for " + endpoint.value());
  }
  return found->second;
}

Status Coordinator::push(const std::shared_ptr<ControlLink>& link, MessageType type,
                         const CanonicalEncoder& payload) {
  if (!link->alive.load(std::memory_order_acquire)) {
    return Status(ReasonCode::ENDPOINT_NOT_LIVE, "the endpoint session has ended");
  }
  std::lock_guard<std::mutex> lock(link->send_mutex);
  return link->stream.send(type, payload.view());
}

Result<std::future<Frame>> Coordinator::reserve(const std::shared_ptr<ControlLink>& link,
                                                  const std::string& key) {
  auto promise = std::make_shared<std::promise<Frame>>();
  auto future = promise->get_future();
  std::lock_guard<std::mutex> lock(link->pending_mutex);
  if (link->pending.count(key) != 0) {
    return Status(ReasonCode::BUSY, "an identical request is already in flight");
  }
  link->pending.emplace(key, std::move(promise));
  return future;
}

void Coordinator::release(const std::shared_ptr<ControlLink>& link, const std::string& key) {
  std::lock_guard<std::mutex> lock(link->pending_mutex);
  link->pending.erase(key);
}

Result<Frame> Coordinator::await(const std::shared_ptr<ControlLink>& link, const std::string& key,
                                 std::future<Frame>& future, const char* what) {
  if (future.wait_for(std::chrono::milliseconds(config_.io_budget_millis)) !=
      std::future_status::ready) {
    release(link, key);
    return Status(ReasonCode::IO_TIMEOUT, std::string("the endpoint did not answer ") + what);
  }
  Frame frame = future.get();
  if (frame.header.type == MessageType::INVALID) {
    return Status(ReasonCode::CONNECTION_CLOSED, "the endpoint session ended before it answered");
  }
  return frame;
}

Result<Frame> Coordinator::request(const std::shared_ptr<ControlLink>& link, const std::string& key,
                                   MessageType type, const CanonicalEncoder& payload) {
  auto reserved = reserve(link, key);
  if (!reserved.ok()) return reserved.status();
  std::future<Frame> future = std::move(reserved).value();

  const Status sent = push(link, type, payload);
  if (!sent.ok()) {
    release(link, key);
    return sent;
  }
  return await(link, key, future, to_string(type));
}

Digest Coordinator::digest_of_capability() const {
  CanonicalEncoder encoder("SMF-COORDINATOR-CAPABILITY-v1");
  encoder.text(config_.endpoint_id.value());
  encoder.text(std::string(kVersionString));
  policy_.encode(encoder);
  return canonical_digest(encoder);
}

// ---------------------------------------------------------------------------
// Endpoint-facing messages
// ---------------------------------------------------------------------------

Status Coordinator::handle_endpoint_message(const std::shared_ptr<ControlLink>& link,
                                            const Frame& frame) {
  switch (frame.header.type) {
    case MessageType::REGISTER: {
      const auto message = decode_message<RegisterRequest>(frame);
      if (!message.ok()) return message.status();
      const auto& hint = message.value().identity;
      if (hint.contract != kPeerContract) {
        return Status(ReasonCode::ENDPOINT_CONTRACT_MISMATCH,
                      "the endpoint speaks a different peer contract");
      }
      if (hint.endpoint.value() == "local-origin") {
        return Status(ReasonCode::INVALID_ID, "that endpoint name is reserved");
      }

      const auto incarnation = EndpointIncarnation::make(
          hint.endpoint, hint.boot, hint.epoch);
      if (!incarnation.ok()) return incarnation.status();

      EndpointRegistration registration;
      registration.endpoint = hint.endpoint;
      registration.incarnation = incarnation.value();
      registration.service_address = message.value().service_address;
      registration.data_address = message.value().data_address;
      registration.contract = hint.contract;
      registration.capability_digest = hint.capability_digest;
      registration.registered_unix_millis = system_clock().unix_millis();
      registration.live = true;

      SMF_RETURN_IF_ERROR(topology_.put(registration, config_.policy.max_endpoints));
      const auto advanced = topology_.advance();
      if (!advanced.ok()) return advanced.status();

      {
        std::lock_guard<std::mutex> lock(links_mutex_);
        links_.insert_or_assign(hint.endpoint, link);
      }

      RegisterAck ack;
      ack.topology_generation = topology_.generation();
      ack.policy_generation = policy_.generation;
      ack.coordinator = incarnation_;
      ack.policy_digest = policy_.digest();
      ack.max_inflight_chunks = config_.policy.max_inflight_chunks;
      ack.max_chunk_bytes = config_.policy.max_chunk_bytes;
      ack.max_object_bytes = config_.policy.max_object_bytes;
      ack.io_budget_millis = static_cast<std::uint32_t>(
          std::min<Millis>(config_.io_budget_millis, 3600000));
      ack.transfer_budget_millis = config_.policy.transfer_budget_millis;

      CanonicalEncoder encoder;
      ack.encode(encoder);
      log_message(LogLevel::INFO, "coordinator",
                  "registered " + hint.endpoint.value() + " epoch " +
                      std::to_string(hint.epoch.value()) + " serving data on " +
                      message.value().data_address.to_string());
      return push(link, MessageType::REGISTER_ACK, encoder);
    }

    case MessageType::ANNOUNCE_OBJECT: {
      const auto message = decode_message<AnnounceObject>(frame);
      if (!message.ok()) return message.status();
      {
        std::lock_guard<std::mutex> lock(inventory_mutex_);
        const auto existing = inventory_.find(message.value().descriptor.object_id);
        if (existing != inventory_.end() &&
            existing->second.generation > message.value().descriptor.generation) {
          AnnounceAck ack;
          ack.code = ReasonCode::STALE_STATE_GENERATION;
          ack.detail = "a newer generation of this object is already announced";
          CanonicalEncoder encoder;
          ack.encode(encoder);
          return push(link, MessageType::ANNOUNCE_ACK, encoder);
        }
        inventory_.insert_or_assign(message.value().descriptor.object_id, message.value().descriptor);
        inventory_source_.insert_or_assign(message.value().descriptor.object_id, link->endpoint);
      }
      AnnounceAck ack;
      ack.code = ReasonCode::OK;
      ack.detail = "announced";
      CanonicalEncoder encoder;
      ack.encode(encoder);
      return push(link, MessageType::ANNOUNCE_ACK, encoder);
    }

    case MessageType::TOPOLOGY_REQUEST: {
      // A destination needs the source's data address before it can pull. The
      // answer is the coordinator's current view, never a peer's claim.
      const auto message = decode_message<TopologyRequest>(frame);
      if (!message.ok()) return message.status();
      CanonicalEncoder encoder;
      topology_report().encode(encoder);
      return push(link, MessageType::TOPOLOGY_REPORT, encoder);
    }

    case MessageType::POLICY_REQUEST: {
      const auto message = decode_message<PolicyRequest>(frame);
      if (!message.ok()) return message.status();
      CanonicalEncoder encoder;
      policy_report().encode(encoder);
      return push(link, MessageType::POLICY_REPORT, encoder);
    }

    case MessageType::HEARTBEAT: {
      CanonicalEncoder encoder("SMF-MSG-HEARTBEAT-ACK-v1");
      return push(link, MessageType::HEARTBEAT_ACK, encoder);
    }

    case MessageType::ERROR: {
      const auto message = decode_message<ErrorMessage>(frame);
      if (message.ok()) {
        log_message(LogLevel::DEBUG, "coordinator",
                    "endpoint " + link->endpoint.value() + " reported " +
                        to_string(message.value().code) + ": " + message.value().detail);
      }
      return Status::success();
    }

    // A response that no longer has a waiter is a late or duplicate completion
    // of an exchange that has already been resolved. It is recorded and
    // dropped; it is never re-applied and never treated as a violation.
    case MessageType::ATTEMPT_RESULT:
    case MessageType::COMMIT_RESULT:
    case MessageType::VERIFY_RESPONSE:
    case MessageType::AUTHORITY_REPORT:
    case MessageType::CLEANUP_RESULT:
    case MessageType::CANCEL_ACK:
    case MessageType::GRANT_ACK: {
      count([](CoordinatorCounters& c) { c.stale_rejections += 1; });
      log_message(LogLevel::DEBUG, "coordinator",
                  "dropped an unclaimed " + std::string(to_string(frame.header.type)) + " from " +
                      link->endpoint.value());
      return Status::success();
    }

    default:
      return Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE,
                    std::string("the coordinator does not accept ") + to_string(frame.header.type) +
                        " from an endpoint session");
  }
}

// ---------------------------------------------------------------------------
// Admin-facing messages
// ---------------------------------------------------------------------------

Status Coordinator::handle_admin_message(const std::shared_ptr<ControlLink>& link,
                                         const Frame& frame) {
  switch (frame.header.type) {
    case MessageType::SUBMIT_MOVEMENT: {
      const auto message = decode_message<SubmitMovement>(frame);
      if (!message.ok()) return message.status();
      const auto accepted = submit(message.value());
      CanonicalEncoder encoder;
      if (!accepted.ok()) {
        count([](CoordinatorCounters& c) { c.movements_rejected += 1; });
        ErrorMessage error;
        error.code = accepted.status().code();
        error.detail = accepted.status().message();
        error.encode(encoder);
        return push(link, MessageType::ERROR, encoder);
      }
      accepted.value().encode(encoder);
      return push(link, MessageType::MOVEMENT_ACCEPTED, encoder);
    }
    case MessageType::QUERY_MOVEMENT: {
      const auto message = decode_message<QueryMovement>(frame);
      if (!message.ok()) return message.status();
      const auto record = query(message.value().movement_id);
      CanonicalEncoder encoder;
      if (!record.ok()) {
        ErrorMessage error;
        error.code = record.status().code();
        error.detail = record.status().message();
        error.encode(encoder);
        return push(link, MessageType::ERROR, encoder);
      }
      MovementStatus status;
      status.record = record.value();
      status.encode(encoder);
      return push(link, MessageType::MOVEMENT_STATUS, encoder);
    }
    case MessageType::LIST_MOVEMENTS: {
      const auto message = decode_message<ListMovements>(frame);
      if (!message.ok()) return message.status();
      const auto records = list(message.value().limit, message.value().offset);
      if (!records.ok()) return records.status();
      MovementList payload;
      payload.movements = records.value();
      CanonicalEncoder encoder;
      payload.encode(encoder);
      return push(link, MessageType::MOVEMENT_LIST, encoder);
    }
    case MessageType::CANCEL_MOVEMENT: {
      const auto message = decode_message<CancelMovement>(frame);
      if (!message.ok()) return message.status();
      const auto record = cancel(message.value().movement_id);
      CanonicalEncoder encoder;
      if (!record.ok()) {
        ErrorMessage error;
        error.code = record.status().code();
        error.detail = record.status().message();
        error.encode(encoder);
        return push(link, MessageType::ERROR, encoder);
      }
      MovementStatus status;
      status.record = record.value();
      status.encode(encoder);
      return push(link, MessageType::MOVEMENT_STATUS, encoder);
    }
    case MessageType::RECONCILE_MOVEMENT: {
      const auto message = decode_message<ReconcileMovement>(frame);
      if (!message.ok()) return message.status();
      const auto record = reconcile(message.value().movement_id);
      CanonicalEncoder encoder;
      if (!record.ok()) {
        ErrorMessage error;
        error.code = record.status().code();
        error.detail = record.status().message();
        error.encode(encoder);
        return push(link, MessageType::ERROR, encoder);
      }
      MovementStatus status;
      status.record = record.value();
      status.encode(encoder);
      return push(link, MessageType::MOVEMENT_STATUS, encoder);
    }
    case MessageType::PROVENANCE_REQUEST: {
      const auto message = decode_message<ProvenanceRequest>(frame);
      if (!message.ok()) return message.status();
      const auto report = provenance(message.value().movement_id);
      CanonicalEncoder encoder;
      if (!report.ok()) {
        ErrorMessage error;
        error.code = report.status().code();
        error.detail = report.status().message();
        error.encode(encoder);
        return push(link, MessageType::ERROR, encoder);
      }
      report.value().encode(encoder);
      return push(link, MessageType::PROVENANCE_REPORT, encoder);
    }
    case MessageType::TOPOLOGY_REQUEST: {
      const auto message = decode_message<TopologyRequest>(frame);
      if (!message.ok()) return message.status();
      CanonicalEncoder encoder;
      topology_report().encode(encoder);
      return push(link, MessageType::TOPOLOGY_REPORT, encoder);
    }
    case MessageType::POLICY_REQUEST: {
      const auto message = decode_message<PolicyRequest>(frame);
      if (!message.ok()) return message.status();
      CanonicalEncoder encoder;
      policy_report().encode(encoder);
      return push(link, MessageType::POLICY_REPORT, encoder);
    }
    case MessageType::SHUTDOWN: {
      const auto message = decode_message<ShutdownRequest>(frame);
      if (!message.ok()) return message.status();
      ShutdownAck ack;
      ack.code = ReasonCode::OK;
      ack.detail = "shutting down";
      CanonicalEncoder encoder;
      ack.encode(encoder);
      const Status sent = push(link, MessageType::SHUTDOWN_ACK, encoder);
      (void)sent;
      return request_shutdown();
    }
    default:
      return Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE,
                    std::string("the coordinator does not accept ") + to_string(frame.header.type) +
                        " from an operator session");
  }
}

// ---------------------------------------------------------------------------
// Authoritative operations
// ---------------------------------------------------------------------------

Status Coordinator::require_running() const {
  if (store_ == nullptr) {
    return Status(ReasonCode::SHUTTING_DOWN,
                  "the coordinator has been stopped and no longer owns its state");
  }
  return Status::success();
}

Result<MovementAccepted> Coordinator::submit(const SubmitMovement& request) {
  SMF_RETURN_IF_ERROR(require_running());
  const Status valid = request.validate();
  if (!valid.ok()) return valid;

  StateObjectDescriptor object;
  {
    std::lock_guard<std::mutex> lock(inventory_mutex_);
    const auto found = inventory_.find(request.object_id);
    if (found == inventory_.end()) {
      return Status(ReasonCode::OBJECT_NOT_FOUND,
                    "no source has announced that state object");
    }
    if (found->second.generation != request.object_generation) {
      return Status(ReasonCode::STALE_STATE_GENERATION,
                    "the announced generation of that object is " +
                        std::to_string(found->second.generation.value()) + ", not " +
                        std::to_string(request.object_generation.value()));
    }
    const auto announcer = inventory_source_.find(request.object_id);
    if (announcer == inventory_source_.end() || announcer->second != request.source) {
      return Status(ReasonCode::NOT_AUTHORIZED,
                    "the named source is not the endpoint that announced this object version");
    }
    object = found->second;
  }

  if (object.total_bytes > config_.policy.max_object_bytes) {
    return Status(ReasonCode::POLICY_VIOLATION, "the object exceeds the configured size bound");
  }
  if (object.chunk_bytes < config_.policy.min_chunk_bytes ||
      object.chunk_bytes > config_.policy.max_chunk_bytes) {
    return Status(ReasonCode::POLICY_VIOLATION,
                  "the object's segmentation is outside the policy bounds");
  }

  // ---- authority checks: both endpoints must be live right now -------------
  const auto source_registration = topology_.find(request.source);
  if (!source_registration.ok()) return source_registration.status();
  const auto destination_registration = topology_.find(request.destination);
  if (!destination_registration.ok()) return destination_registration.status();
  if (!source_registration.value().live || !destination_registration.value().live) {
    return Status(ReasonCode::ENDPOINT_NOT_LIVE, "one of the endpoints is not currently live");
  }

  // ---- compatibility evidence --------------------------------------------
  CompatibilityVerdict verdict = CompatibilityVerdict::UNKNOWN;
  std::string compatibility_note =
      "no compatibility provider is configured, so the verdict is explicitly unknown";
  if (compatibility_ != nullptr) {
    const auto evidence = compatibility_->query(object, request.destination);
    if (!evidence.ok()) {
      if (config_.policy.require_compatibility_evidence) {
        return Status(ReasonCode::COMPATIBILITY_EVIDENCE_MISSING, evidence.status().message());
      }
      compatibility_note = "no evidence is published: " + evidence.status().message();
    } else if (!evidence.value().applies_to(object, request.destination)) {
      if (config_.policy.require_compatibility_evidence) {
        return Status(ReasonCode::COMPATIBILITY_STALE_EVIDENCE,
                      "the published evidence does not bind this object version at this "
                      "destination");
      }
      compatibility_note = "published evidence does not apply to this version and destination";
    } else {
      verdict = evidence.value().verdict;
      compatibility_note = std::string("compatibility verdict ") + to_string(verdict);
      compatibility_generation_ = evidence.value().generation;
      if (verdict == CompatibilityVerdict::UNSUPPORTED) {
        return Status(ReasonCode::COMPATIBILITY_UNSUPPORTED,
                      "published evidence says this destination cannot use this state version");
      }
      if (verdict == CompatibilityVerdict::UNKNOWN &&
          config_.policy.require_compatibility_evidence) {
        return Status(ReasonCode::COMPATIBILITY_UNKNOWN,
                      "published evidence is explicitly unknown, which is not support");
      }
    }
  }

  IdIssuer issuer;
  MovementRecord record;
  record.id = issuer.new_movement_id();
  record.generation = MovementGeneration(1);
  record.object = object;
  record.source = request.source;
  record.destination = request.destination;
  const auto source_incarnation = source_registration.value().incarnation.retag<SourceIncarnationTag>();
  const auto destination_incarnation =
      destination_registration.value().incarnation.retag<DestinationIncarnationTag>();
  record.source_incarnation = source_incarnation;
  record.destination_incarnation = destination_incarnation;
  record.compatibility_generation = compatibility_generation_;
  record.topology_generation = topology_.generation();
  record.policy_generation = policy_.generation;
  record.state = MovementState::PLANNED;
  record.last_reason = ReasonCode::OK;
  record.repeatable = object.repeatable;
  record.created_unix_millis = system_clock().unix_millis();
  record.updated_unix_millis = record.created_unix_millis;
  record.provenance.set_bound(config_.policy.max_provenance_events);

  const Status created = record.provenance.append(ProvenanceEventKind::CREATED, MovementState::PLANNED,
                                                  record.generation, ReasonCode::OK,
                                                  record.created_unix_millis, compatibility_note);
  if (!created.ok()) return created;

  const Status validated = record.validate();
  if (!validated.ok()) return validated;
  SMF_RETURN_IF_ERROR(store_->put(record));

  const Status authorized =
      apply_transition(record, MovementState::AUTHORIZED,
                       MovementDecision::allow(ReasonCode::OK,
                                               "authorized under topology generation " +
                                                   std::to_string(record.topology_generation.value()) +
                                                   " and policy generation " +
                                                   std::to_string(record.policy_generation.value())),
                       ProvenanceEventKind::AUTHORIZED, system_clock().unix_millis());
  if (!authorized.ok()) {
    count([](CoordinatorCounters& c) { c.movements_rejected += 1; });
    return authorized;
  }
  SMF_RETURN_IF_ERROR(store_->put(record));

  fault_point(fault_points::kCoordinatorAfterAuthorize);

  count([](CoordinatorCounters& c) { c.movements_submitted += 1; });
  enqueue(record.id);

  MovementAccepted accepted;
  accepted.movement_id = record.id;
  accepted.state = record.state;
  accepted.code = ReasonCode::OK;
  accepted.detail = compatibility_note;
  return accepted;
}

Result<MovementRecord> Coordinator::query(const MovementId& id) const {
  SMF_RETURN_IF_ERROR(require_running());
  return store_->get(id);
}

Result<std::vector<MovementSummary>> Coordinator::list(std::uint32_t limit,
                                                       std::uint32_t offset) const {
  SMF_RETURN_IF_ERROR(require_running());
  const std::uint32_t bounded = std::min<std::uint32_t>(limit, 256U);
  const auto records = store_->list(bounded, offset);
  if (!records.ok()) return records.status();
  std::vector<MovementSummary> summaries;
  summaries.reserve(records.value().size());
  for (const MovementRecord& record : records.value()) {
    summaries.push_back(to_summary(record));
  }
  return summaries;
}

MovementSummary Coordinator::to_summary(const MovementRecord& record) const {
  MovementSummary summary;
  summary.movement_id = record.id;
  summary.state = record.state;
  summary.object_id = record.object.object_id;
  summary.object_generation = record.object.generation;
  summary.source = record.source;
  summary.destination = record.destination;
  summary.last_reason = record.last_reason;
  summary.attempt_count = record.attempt_count;
  summary.bytes_transferred = record.bytes_transferred;
  return summary;
}

Result<MovementRecord> Coordinator::cancel(const MovementId& id) {
  SMF_RETURN_IF_ERROR(require_running());
  auto stored = store_->get(id);
  if (!stored.ok()) return stored.status();
  MovementRecord record = stored.value();

  if (record.is_terminal()) {
    return Status(ReasonCode::ALREADY_TERMINAL,
                  std::string("the movement is already ") + to_string(record.state));
  }

  record.cancel_requested = true;

  // Tell both endpoints before recording the decision, so that a transfer that
  // is already running stops at the next chunk boundary.
  const CancelRequest notice{record.id, record.generation};
  CanonicalEncoder encoder;
  notice.encode(encoder);
  for (const EndpointId& endpoint : {record.source, record.destination}) {
    const auto link = find_link(endpoint);
    if (!link.ok()) continue;
    const std::string key = key_for(MessageType::CANCEL_ACK, record.id.hex());
    const auto answer = request(link.value(), key, MessageType::CANCEL, encoder);
    (void)answer;
  }

  const Status applied = apply_transition(record, MovementState::CANCELLED,
                                          MovementDecision::deny(ReasonCode::CANCELLED_BY_OPERATOR,
                                                                 "cancelled by the operator"),
                                          ProvenanceEventKind::CANCELLED,
                                          system_clock().unix_millis());
  if (!applied.ok()) return applied;
  SMF_RETURN_IF_ERROR(store_->put(record));
  count([](CoordinatorCounters& c) { c.movements_cancelled += 1; });
  return record;
}

Result<MovementRecord> Coordinator::reconcile(const MovementId& id) {
  SMF_RETURN_IF_ERROR(require_running());
  auto stored = store_->get(id);
  if (!stored.ok()) return stored.status();
  MovementRecord record = stored.value();

  if (record.state != MovementState::OUTCOME_UNKNOWN) {
    return Status(ReasonCode::MOVEMENT_NOT_RECONCILABLE,
                  std::string("only an OUTCOME_UNKNOWN movement can be reconciled; this one is ") +
                      to_string(record.state));
  }

  count([](CoordinatorCounters& c) { c.reconciliations += 1; });

  const auto link = find_link(record.destination);
  if (!link.ok()) {
    // No destination to ask. The outcome stays unknown rather than being
    // resolved by assumption.
    return Status(ReasonCode::REVALIDATION_REQUIRED,
                  "the destination is not reachable, so the outcome remains unknown: " +
                      link.status().message());
  }

  AuthorityQuery query;
  query.movement_id = record.id;
  query.object_id = record.object.object_id;
  query.object_generation = record.object.generation;
  CanonicalEncoder encoder;
  query.encode(encoder);

  const std::string key = key_for(MessageType::AUTHORITY_REPORT, record.id.hex());
  const auto answer = request(link.value(), key, MessageType::AUTHORITY_QUERY, encoder);
  if (!answer.ok()) {
    return Status(ReasonCode::REVALIDATION_REQUIRED,
                  "the destination did not answer the authority query: " +
                      answer.status().message());
  }
  const auto report = decode_message<AuthorityReport>(answer.value());
  if (!report.ok()) return report.status();

  const bool marker_present = report.value().marker_present;
  const bool marker_is_mine = report.value().authoritative && report.value().verified &&
                              report.value().marker_present;

  if (marker_present && marker_is_mine) {
    const Status applied = apply_transition(
        record, MovementState::COMMITTED,
        MovementDecision::allow(ReasonCode::OK,
                                "reconciliation found a valid commit marker at the destination"),
        ProvenanceEventKind::RECONCILED, system_clock().unix_millis());
    if (!applied.ok()) return applied;
    record.commit_marker_digest = report.value().marker_digest;
    record.destination_verified_digest = record.object.content_digest;
    record.bytes_transferred = record.object.total_bytes;
    record.chunks_verified = record.object.chunk_count;
    SMF_RETURN_IF_ERROR(store_->put(record));
    count([](CoordinatorCounters& c) { c.movements_committed += 1; });
    return record;
  }

  if (!marker_present) {
    // The effect provably did not happen.
    const MovementState next =
        record.cancel_requested ? MovementState::CANCELLED : MovementState::FAILED;
    const ReasonCode code = record.cancel_requested ? ReasonCode::CANCELLED_BY_OPERATOR
                                                    : ReasonCode::REVALIDATION_REQUIRED;
    const Status applied = apply_transition(
        record, next,
        MovementDecision::deny(code, "reconciliation proved that no commit marker exists at the "
                                     "destination, so the movement did not take effect"),
        ProvenanceEventKind::RECONCILED, system_clock().unix_millis());
    if (!applied.ok()) return applied;
    SMF_RETURN_IF_ERROR(store_->put(record));
    count([next](CoordinatorCounters& c) {
      if (next == MovementState::CANCELLED) {
        c.movements_cancelled += 1;
      } else {
        c.movements_failed += 1;
      }
    });
    return record;
  }

  // A marker exists but its binding does not verify. That is not proof either
  // way, so the outcome stays unknown.
  return Status(ReasonCode::COMMIT_MARKER_INVALID,
                "a commit marker exists at the destination but its binding does not verify; the "
                "outcome remains unknown");
}

Result<ProvenanceReport> Coordinator::provenance(const MovementId& id) const {
  SMF_RETURN_IF_ERROR(require_running());
  const auto stored = store_->get(id);
  if (!stored.ok()) return stored.status();
  ProvenanceReport report;
  report.movement_id = id;
  report.code = ReasonCode::OK;
  report.events = stored.value().provenance.events();
  return report;
}

TopologyReport Coordinator::topology_report() const {
  TopologyReport report;
  report.topology_generation = topology_.generation();
  report.coordinator = incarnation_;
  report.endpoints = topology_.endpoints();
  return report;
}

PolicyReport Coordinator::policy_report() const {
  PolicyReport report;
  report.policy = policy_;
  report.policy_digest = policy_.digest();
  return report;
}

// ---------------------------------------------------------------------------
// Movement engine
// ---------------------------------------------------------------------------

void Coordinator::enqueue(const MovementId& id) {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    queue_.push_back(id);
  }
  queue_cv_.notify_one();
}

void Coordinator::wait_for_idle() {
  std::unique_lock<std::mutex> lock(queue_mutex_);
  idle_cv_.wait(lock, [this]() {
    return queue_.empty() && active_movements_.load(std::memory_order_acquire) == 0;
  });
}

void Coordinator::worker_loop() {
  for (;;) {
    MovementId id;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this]() {
        return stopping_.load(std::memory_order_acquire) || !queue_.empty();
      });
      if (queue_.empty()) {
        if (stopping_.load(std::memory_order_acquire)) return;
        continue;
      }
      id = queue_.front();
      queue_.pop_front();
    }

    active_movements_.fetch_add(1, std::memory_order_acq_rel);
    const Status status = drive_movement(id);
    if (!status.ok()) {
      log_message(LogLevel::DEBUG, "coordinator",
                  "movement " + id.hex().substr(0, 12) + " ended: " + status.to_string());
    }
    active_movements_.fetch_sub(1, std::memory_order_acq_rel);
    idle_cv_.notify_all();
  }
}

Status Coordinator::persist(MovementRecord& record) { return store_->put(record); }


Status Coordinator::drive_movement(const MovementId& id) {
  auto stored = store_->get(id);
  if (!stored.ok()) return stored.status();
  MovementRecord record = stored.value();
  if (record.is_terminal() || record.state == MovementState::OUTCOME_UNKNOWN) {
    return Status::success();
  }

  const auto fail = [&](ReasonCode code, const std::string& detail,
                        MovementState state) -> Status {
    const Status applied = apply_transition(record, state, MovementDecision::deny(code, detail),
                                            state == MovementState::CANCELLED
                                                ? ProvenanceEventKind::CANCELLED
                                                : (state == MovementState::SUPERSEDED
                                                       ? ProvenanceEventKind::SUPERSEDED
                                                       : ProvenanceEventKind::FAILED),
                                            system_clock().unix_millis());
    if (applied.ok()) {
      const Status saved = store_->put(record);
      (void)saved;
    }
    count([state](CoordinatorCounters& c) {
      if (state == MovementState::CANCELLED) {
        c.movements_cancelled += 1;
      } else if (state == MovementState::SUPERSEDED) {
        c.movements_superseded += 1;
      } else {
        c.movements_failed += 1;
      }
    });
    return applied;
  };

  if (record.cancel_requested) {
    return fail(ReasonCode::CANCELLED_BY_OPERATOR, "cancelled before the transfer started",
                MovementState::CANCELLED);
  }

  const auto source_link = find_link(record.source);
  if (!source_link.ok()) {
    return fail(ReasonCode::ENDPOINT_NOT_LIVE, source_link.status().message(),
                MovementState::FAILED);
  }
  const auto destination_link = find_link(record.destination);
  if (!destination_link.ok()) {
    return fail(ReasonCode::ENDPOINT_NOT_LIVE, destination_link.status().message(),
                MovementState::FAILED);
  }

  // The endpoint incarnations recorded at authorization time must still be the
  // ones that are live now: a restarted endpoint invalidates the decision.
  const auto current_source = topology_.find(record.source);
  const auto current_destination = topology_.find(record.destination);
  if (!current_source.ok() || !current_destination.ok()) {
    return fail(ReasonCode::STALE_INCARNATION, "an endpoint left the topology",
                MovementState::FAILED);
  }
  if (current_source.value().incarnation.retag<SourceIncarnationTag>() !=
          record.source_incarnation ||
      current_destination.value().incarnation.retag<DestinationIncarnationTag>() !=
          record.destination_incarnation) {
    return fail(ReasonCode::STALE_INCARNATION,
                "an endpoint restarted after the movement was authorized",
                MovementState::SUPERSEDED);
  }

  for (std::uint32_t attempt_number = 1;
       attempt_number <= config_.policy.max_attempts; ++attempt_number) {
    if (record.cancel_requested) {
      return fail(ReasonCode::CANCELLED_BY_OPERATOR, "cancelled between attempts",
                  MovementState::CANCELLED);
    }

    IdIssuer issuer;
    const TransferAttemptId attempt = issuer.new_attempt_id();
    SMF_RETURN_IF_ERROR(record_attempt_started(record, attempt, system_clock().unix_millis()));
    SMF_RETURN_IF_ERROR(store_->put(record));

    TransferGrant grant;
    grant.movement_id = record.id;
    grant.movement_generation = record.generation;
    grant.attempt = attempt;
    grant.object = record.object;
    grant.source = record.source;
    grant.source_incarnation = record.source_incarnation;
    grant.destination = record.destination;
    grant.destination_incarnation = record.destination_incarnation;
    grant.policy_generation = record.policy_generation;
    grant.grant_nonce = issuer.new_nonce();
    grant.max_bytes = record.object.total_bytes;
    grant.max_chunks = record.object.chunk_count;
    grant.issued_unix_millis = system_clock().unix_millis();
    grant.effect_class =
        record.repeatable ? EffectClass::REPEATABLE : EffectClass::NON_REPEATABLE;
    SMF_RETURN_IF_ERROR(grant.sign(smf::as_bytes(config_.shared_secret)));

    // The grant reaches both endpoints over their own authenticated sessions,
    // so it never travels through a peer and cannot be forged by one.
    const GrantTransfer grant_message{grant};
    CanonicalEncoder grant_encoder;
    grant_message.encode(grant_encoder);

    for (const auto& endpoint : {record.source, record.destination}) {
      const auto link = endpoint == record.source ? source_link : destination_link;
      const std::string key = key_for(MessageType::GRANT_ACK, grant.grant_nonce.hex());
      const auto answer = request(link.value(), key, MessageType::GRANT_TRANSFER, grant_encoder);
      if (!answer.ok()) {
        return fail(answer.status().code(),
                    "the grant could not be delivered: " + answer.status().message(),
                    MovementState::FAILED);
      }
      const auto ack = decode_message<GrantAck>(answer.value());
      if (!ack.ok()) return fail(ack.status().code(), ack.status().message(), MovementState::FAILED);
      if (ack.value().code != ReasonCode::OK) {
        return fail(ack.value().code, ack.value().detail, MovementState::FAILED);
      }
    }

    // Wait for the attempt result before asking the destination to start, so
    // that a destination that finishes instantly cannot report before anyone is
    // listening.
    const std::string result_key = key_for(MessageType::ATTEMPT_RESULT, record.id.hex());
    auto reserved = reserve(destination_link.value(), result_key);
    if (!reserved.ok()) return reserved.status();
    std::future<Frame> result_future = std::move(reserved).value();

    ExecuteMovement execute;
    execute.movement_id = record.id;
    execute.movement_generation = record.generation;
    execute.attempt = attempt;
    execute.nonce = Digest(grant.grant_nonce.bytes());
    execute.source = record.source;
    CanonicalEncoder execute_encoder;
    execute.encode(execute_encoder);

    const Status started = push(destination_link.value(), MessageType::EXECUTE_MOVEMENT,
                                execute_encoder);
    if (!started.ok()) {
      release(destination_link.value(), result_key);
      return fail(started.code(), started.message(), MovementState::FAILED);
    }

    const Status transfer = apply_transition(
        record, MovementState::TRANSFERRING,
        MovementDecision::allow(ReasonCode::OK,
                                "attempt " + std::to_string(attempt_number) + " dispatched"),
        ProvenanceEventKind::ATTEMPT_STARTED, system_clock().unix_millis());
    if (!transfer.ok()) {
      release(destination_link.value(), result_key);
      return transfer;
    }
    SMF_RETURN_IF_ERROR(store_->put(record));

    // A late report from an earlier attempt must never be consumed as this
    // attempt's outcome, so the result is matched on both movement and attempt
    // before it is believed. Anything else is recorded and waited past.
    AttemptResult result;
    bool accepted_result = false;
    std::uint32_t discarded = 0;
    while (!accepted_result) {
      const auto answer =
          await(destination_link.value(), result_key, result_future, "the attempt result");
      if (!answer.ok()) {
        return fail(answer.status().code(),
                    "the destination never reported an outcome: " + answer.status().message(),
                    MovementState::OUTCOME_UNKNOWN);
      }
      const auto decoded = decode_message<AttemptResult>(answer.value());
      if (!decoded.ok()) {
        return fail(decoded.status().code(), decoded.status().message(),
                    MovementState::OUTCOME_UNKNOWN);
      }
      if (decoded.value().movement_id != record.id || decoded.value().attempt != attempt) {
        ++discarded;
        const Status noted = record.provenance.append(
            ProvenanceEventKind::STALE_REJECTED, record.state, record.generation,
            ReasonCode::STALE_ATTEMPT, system_clock().unix_millis(),
            "discarded a completion that names a different movement or attempt");
        (void)noted;
        if (discarded >= 4) {
          return fail(ReasonCode::STALE_ATTEMPT,
                      "only stale completions arrived for this attempt",
                      MovementState::OUTCOME_UNKNOWN);
        }
        auto re_reserved = reserve(destination_link.value(), result_key);
        if (!re_reserved.ok()) return re_reserved.status();
        result_future = std::move(re_reserved).value();
        continue;
      }
      result = decoded.value();
      accepted_result = true;
    }

    if (result.state == MovementState::CANCELLED) {
      return fail(result.code, result.detail, MovementState::CANCELLED);
    }
    if (result.state != MovementState::BYTES_ARRIVED) {
      record.last_reason = result.code;
      record.last_detail = result.detail;
      if (attempt_number >= config_.policy.max_attempts) {
        return fail(result.code, "the last permitted attempt failed: " + result.detail,
                    MovementState::FAILED);
      }
      count([](CoordinatorCounters& c) { c.movements_failed += 1; });
      (void)record.provenance.append(ProvenanceEventKind::RETRY_SCHEDULED, record.state,
                                     record.generation, result.code, system_clock().unix_millis(),
                                     "retrying after: " + result.detail);
      const Status saved = store_->put(record);
      (void)saved;
      continue;
    }

    const Status arrived = apply_transition(
        record, MovementState::BYTES_ARRIVED,
        MovementDecision::allow(ReasonCode::OK,
                                "the destination reports verified bytes (not authority)"),
        ProvenanceEventKind::BYTES_ARRIVED, system_clock().unix_millis());
    if (!arrived.ok()) return arrived;
    record.bytes_transferred = result.bytes;
    record.chunks_verified = result.chunks;
    record.destination_verified_digest = result.verified_digest;
    SMF_RETURN_IF_ERROR(store_->put(record));

    // ---- independent verification --------------------------------------
    const auto verified = verify_destination(record);
    if (!verified.ok()) {
      if (attempt_number >= config_.policy.max_attempts) {
        return fail(verified.status().code(),
                    "independent verification failed on the last permitted attempt: " +
                        verified.status().message(),
                    MovementState::FAILED);
      }
      // Not authority: the destination's own report is never enough. Record the
      // refusal and transfer the version again.
      const Status noted = record.provenance.append(
          ProvenanceEventKind::RETRY_SCHEDULED, record.state, record.generation,
          verified.status().code(), system_clock().unix_millis(),
          "independent verification refused the bytes: " + verified.status().message());
      (void)noted;
      const Status saved_retry = store_->put(record);
      (void)saved_retry;
      count([](CoordinatorCounters& c) { c.movements_failed += 1; });
      continue;
    }

    const Status verified_transition = apply_transition(
        record, MovementState::VERIFIED,
        MovementDecision::allow(ReasonCode::OK,
                                "the coordinator re-hashed stored bytes and they match the "
                                "authorized content digest"),
        ProvenanceEventKind::VERIFIED, system_clock().unix_millis());
    if (!verified_transition.ok()) return verified_transition;
    record.source_verified_digest = verified.value();
    SMF_RETURN_IF_ERROR(store_->put(record));

    if (record.cancel_requested) {
      return fail(ReasonCode::CANCELLED_BY_OPERATOR, "cancelled at the commit barrier",
                  MovementState::CANCELLED);
    }

    fault_point(fault_points::kCoordinatorBeforeCommit);

    // ---- commit barrier -------------------------------------------------
    CommitRequest commit;
    commit.movement_id = record.id;
    commit.movement_generation = record.generation;
    commit.attempt = attempt;
    commit.object = record.object;
    commit.source = record.source;
    CanonicalEncoder commit_encoder;
    commit.encode(commit_encoder);

    const std::string commit_key = key_for(MessageType::COMMIT_RESULT, record.id.hex());
    const auto committed_answer = request(destination_link.value(), commit_key,
                                          MessageType::COMMIT_REQUEST, commit_encoder);
    if (!committed_answer.ok()) {
      // The commit may or may not have happened. It is never assumed.
      return fail(committed_answer.status().code(),
                  "the commit barrier was requested but not answered: " +
                      committed_answer.status().message() + "; reconcile before retrying",
                  MovementState::OUTCOME_UNKNOWN);
    }
    const auto committed = decode_message<CommitResult>(committed_answer.value());
    if (!committed.ok()) {
      return fail(committed.status().code(), committed.status().message(),
                  MovementState::OUTCOME_UNKNOWN);
    }
    if (committed.value().movement_id != record.id ||
        committed.value().movement_generation != record.generation) {
      return fail(ReasonCode::STALE_MOVEMENT_GENERATION,
                  "the commit result answered a different movement generation",
                  MovementState::OUTCOME_UNKNOWN);
    }
    if (committed.value().code != ReasonCode::OK) {
      return fail(committed.value().code, committed.value().detail, MovementState::FAILED);
    }

    const Status final_transition = apply_transition(
        record, MovementState::COMMITTED,
        MovementDecision::allow(ReasonCode::OK,
                                "the destination wrote and confirmed its commit marker"),
        ProvenanceEventKind::COMMITTED, system_clock().unix_millis());
    if (!final_transition.ok()) return final_transition;
    record.commit_marker_digest = committed.value().marker_digest;
    SMF_RETURN_IF_ERROR(store_->put(record));
    count([](CoordinatorCounters& c) { c.movements_committed += 1; });
    return Status::success();
  }

  return fail(ReasonCode::ATTEMPT_EXHAUSTED, "no attempts remain", MovementState::FAILED);
}

Result<Digest> Coordinator::verify_destination(const MovementRecord& record) {
  const auto link = find_link(record.destination);
  if (!link.ok()) return link.status();

  const auto ask = [&](bool full, std::uint32_t index) -> Result<VerifyResponse> {
    VerifyRequest request_message;
    request_message.movement_id = record.id;
    request_message.movement_generation = record.generation;
    request_message.object_id = record.object.object_id;
    request_message.object_generation = record.object.generation;
    request_message.full_digest_requested = full;
    request_message.chunk_index = index;
    request_message.chunk_bytes = record.object.chunk_bytes;
    CanonicalEncoder encoder;
    request_message.encode(encoder);

    const std::string key =
        key_for(MessageType::VERIFY_RESPONSE, record.id.hex() + ":" + std::to_string(index));
    const auto answer = request(link.value(), key, MessageType::VERIFY_REQUEST, encoder);
    if (!answer.ok()) return answer.status();
    auto response = decode_message<VerifyResponse>(answer.value());
    if (!response.ok()) return response.status();
    // The probe is only believed when it answers the exact question that was
    // asked: the same movement, the same object version.
    if (response.value().movement_id != record.id ||
        response.value().object_id != record.object.object_id ||
        response.value().object_generation != record.object.generation) {
      return Status(ReasonCode::STALE_ATTEMPT,
                    "a verification response named a different movement or object version");
    }
    if (response.value().code != ReasonCode::OK) {
      return Status(response.value().code, "the destination refused a verification probe");
    }
    return response;
  };

  const auto full = ask(true, 0);
  if (!full.ok()) return full.status();
  if (full.value().stored_digest != record.object.content_digest) {
    return Status(ReasonCode::CONTENT_DIGEST_MISMATCH,
                  "the destination's own full-content digest does not match the authorized one");
  }
  if (full.value().stored_bytes != record.object.total_bytes) {
    return Status(ReasonCode::BYTE_COUNT_MISMATCH,
                  "the destination reports a different stored byte count");
  }

  if (!config_.policy.verify_sample_chunks) {
    return full.value().stored_digest;
  }

  // The coordinator reads raw bytes back and hashes them itself. A destination
  // cannot satisfy this by reporting a number: it has to produce the bytes.
  const std::uint32_t wanted = config_.verify_sample_chunks == 0 ? 1 : config_.verify_sample_chunks;
  const std::vector<std::uint32_t> sample =
      verification_sample(record.id, record.object.chunk_count, wanted);
  for (const std::uint32_t index : sample) {
    const auto sample_answer = ask(false, index);
    if (!sample_answer.ok()) return sample_answer.status();

    const auto offset = record.object.chunk_offset(index);
    if (!offset.ok()) return offset.status();
    const auto length = record.object.chunk_length(index);
    if (!length.ok()) return length.status();

    if (sample_answer.value().chunk_payload.size() != length.value()) {
      return Status(ReasonCode::BYTE_COUNT_MISMATCH,
                    "a sampled chunk came back with the wrong length");
    }
    const Digest recomputed =
        compute_chunk_digest(record.object.object_id, record.object.generation, index,
                             offset.value(), length.value(),
                             smf::as_bytes(sample_answer.value().chunk_payload));
    if (recomputed != sample_answer.value().chunk_digest) {
      return Status(ReasonCode::CHUNK_DIGEST_MISMATCH,
                    "a sampled chunk does not hash to the digest the destination reported");
    }
    count([](CoordinatorCounters& c) { c.verification_probes += 1; });
  }

  return full.value().stored_digest;
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void Coordinator::run() {
  std::unique_lock<std::mutex> lock(wake_mutex_);
  wake_.wait(lock, [this]() { return stopping_.load(std::memory_order_acquire); });
}

Status Coordinator::request_shutdown() {
  if (stopping_.exchange(true, std::memory_order_acq_rel)) {
    return Status::success();
  }
  if (endpoint_listener_ != nullptr) {
    const Status status = endpoint_listener_->close();
    (void)status;
  }
  if (admin_listener_ != nullptr) {
    const Status status = admin_listener_->close();
    (void)status;
  }
  {
    std::lock_guard<std::mutex> lock(links_mutex_);
    for (auto& entry : links_) {
      if (entry.second) {
        entry.second->alive.store(false, std::memory_order_release);
        const Status status = entry.second->stream.shutdown();
        (void)status;
      }
    }
  }
  queue_cv_.notify_all();
  idle_cv_.notify_all();
  wake_.notify_all();
  return Status::success();
}

Status Coordinator::stop() {
  const Status signalled = request_shutdown();
  (void)signalled;

  std::call_once(stop_once_, [this]() {
    if (endpoint_accept_thread_.joinable()) endpoint_accept_thread_.join();
    if (admin_accept_thread_.joinable()) admin_accept_thread_.join();
    for (std::thread& worker : workers_) {
      if (worker.joinable()) worker.join();
    }
    workers_.clear();

    std::vector<std::thread> sessions;
    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      sessions.swap(session_threads_);
    }
    for (std::thread& session : sessions) {
      if (session.joinable()) session.join();
    }

    {
      std::lock_guard<std::mutex> lock(links_mutex_);
      links_.clear();
    }
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      queue_.clear();
    }

    // Release the durable store, and with it the exclusive lock on the state
    // directory, so a supervisor can hand the directory to a new instance the
    // moment this one reports that it has stopped.
    store_.reset();
  });
  return Status::success();
}

}  // namespace smf
