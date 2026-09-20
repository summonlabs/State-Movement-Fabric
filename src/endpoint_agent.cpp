// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/endpoint_agent.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <future>
#include <system_error>

#include "file_utils.hpp"
#include "smf/digest.hpp"
#include "smf/version.hpp"
#include "smf/fault_injection.hpp"
#include "smf/limits.hpp"
#include "smf/logging.hpp"
#include "smf/wire.hpp"

namespace smf {
namespace {

// Reserved identity used by the local publication path, so that a locally
// published object still has a distinct origin in its commit marker. It is not
// a registerable endpoint id at the coordinator.
constexpr std::string_view kLocalOrigin = "local-origin";

[[nodiscard]] std::string hex_prefix(const FixedId<MovementIdTag, 16>& id) {
  return id.hex().substr(0, 12);
}

[[nodiscard]] Digest capability_digest_for(const EndpointId& endpoint, const std::string& capability,
                                           const std::string& version) {
  CanonicalEncoder encoder("SMF-ENDPOINT-CAPABILITY-v1");
  encoder.text(endpoint.value());
  encoder.text(capability);
  encoder.text(version);
  return canonical_digest(encoder);
}

[[nodiscard]] Status read_entire_file(const std::filesystem::path& path, Bytes& out,
                                      std::uint64_t max_bytes) {
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(path, false));
  const auto size = handle.size();
  if (!size.ok()) return size.status();
  if (size.value() > max_bytes) {
    return Status(ReasonCode::PROTOCOL_BOUNDS_EXCEEDED, "message exceeds the configured bound");
  }
  out.assign(static_cast<std::size_t>(size.value()), Byte{0});
  if (!out.empty()) {
    const auto read = handle.read(ByteSpan(out.data(), out.size()));
    if (!read.ok()) return read.status();
    if (read.value() != out.size()) {
      return Status(ReasonCode::PROTOCOL_TRUNCATED, "message file was shorter than expected");
    }
  }
  return Status::success();
}

}  // namespace

// ---------------------------------------------------------------------------
// Control link
// ---------------------------------------------------------------------------

struct EndpointAgent::ControlLink {
  FrameStream stream;
  std::mutex send_mutex;
  std::thread reader;
  std::atomic<bool> alive{true};

  // Requests that a worker thread is waiting on. The reader thread completes
  // them; nothing is ever emitted while a lock is held by the completer.
  std::mutex pending_mutex;
  std::map<std::string, std::shared_ptr<std::promise<Frame>>> pending;

  explicit ControlLink(FrameStream connection) : stream(std::move(connection)) {}
};

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

EndpointAgent::~EndpointAgent() {
  const Status status = stop();
  (void)status;
}

Result<std::unique_ptr<EndpointAgent>> EndpointAgent::start(const EndpointAgentConfig& config) {
  if (config.endpoint_id.empty()) {
    return Status(ReasonCode::INVALID_ID, "endpoint id must not be empty");
  }
  if (config.shared_secret.size() != Digest::kBytes) {
    return Status(ReasonCode::INVALID_ARGUMENT,
                  "the shared secret must be exactly 32 bytes; generate one and distribute it");
  }
  if (config.store_root.empty()) {
    return Status(ReasonCode::INVALID_ARGUMENT, "the endpoint store root must not be empty");
  }
  const Status policy_status = config.policy.validate();
  if (!policy_status.ok()) return policy_status;

  auto agent = std::unique_ptr<EndpointAgent>(new EndpointAgent());
  agent->config_ = config;

  SMF_RETURN_IF_ERROR(agent->open_store());

  // The epoch is monotonic across restarts and the boot id is fresh on every
  // start, so a restarted process can never be mistaken for its predecessor.
  std::filesystem::path epoch_path = config.store_root / "incarnation.epoch";
  std::uint64_t epoch = 0;
  if (std::filesystem::exists(epoch_path)) {
    Bytes buffer;
    SMF_RETURN_IF_ERROR(read_entire_file(epoch_path, buffer, 64));
    std::string text(smf::as_string_view(smf::as_bytes(buffer)));
    for (const char c : text) {
      if (c < '0' || c > '9') break;
      epoch = (epoch * 10U) + static_cast<std::uint64_t>(c - '0');
    }
  }
  epoch += 1;
  {
    const std::string text = std::to_string(epoch);
    SMF_RETURN_IF_ERROR(atomic_replace_file(epoch_path, smf::as_bytes(std::string_view(text)), true));
  }

  IdIssuer issuer;
  const auto incarnation = EndpointIncarnation::make(config.endpoint_id, issuer.new_boot_id(),
                                                     IncarnationEpoch(epoch));
  if (!incarnation.ok()) return incarnation.status();
  agent->incarnation_ = incarnation.value();

  SMF_RETURN_IF_ERROR(agent->start_data_listener());
  return agent;
}

Status EndpointAgent::open_store() {
  ObjectStoreOptions options;
  options.root = config_.store_root;
  options.max_object_bytes = config_.policy.max_object_bytes;
  options.sync_on_write = config_.sync_store;
  options.allow_resume = config_.allow_resume;

  auto store = ObjectStore::open(options);
  if (!store.ok()) return store.status();
  store_ = std::move(store).value();
  return Status::success();
}

Status EndpointAgent::start_data_listener() {
  auto listener = TcpListener::bind(config_.data_listen);
  if (!listener.ok()) return listener.status();
  data_listener_ = std::make_unique<TcpListener>(std::move(listener).value());
  data_address_ = data_listener_->address();
  accept_thread_ = std::thread([this]() { accept_loop(); });
  // A fixed worker pool: connections beyond the pool plus the queue bound are
  // refused explicitly rather than growing threads without limit.
  const std::uint32_t workers = config_.max_data_sessions == 0 ? 1 : config_.max_data_sessions;
  session_workers_.reserve(workers);
  for (std::uint32_t i = 0; i < workers; ++i) {
    session_workers_.emplace_back([this]() { session_worker_loop(); });
  }
  log_message(LogLevel::INFO, "endpoint",
              config_.endpoint_id.value() + " serving data on " + data_address_.to_string());
  return Status::success();
}

SocketAddress EndpointAgent::data_address() const {
  return data_listener_ != nullptr ? data_listener_->address() : data_address_;
}

Status EndpointAgent::connect_to_coordinator() {
  if (control_ != nullptr) {
    return Status(ReasonCode::ALREADY_TERMINAL, "the endpoint is already registered");
  }

  auto connection = TcpConnection::connect(config_.coordinator_address, config_.io_budget_millis);
  if (!connection.ok()) return connection.status();

  FrameStream stream(std::move(connection).value(), config_.io_budget_millis,
                     static_cast<std::uint32_t>(config_.policy.max_chunk_bytes + (64U << 10)));

  IdIssuer issuer;
  PeerIdentity identity;
  identity.endpoint = config_.endpoint_id;
  identity.boot = incarnation_.boot();
  identity.epoch = incarnation_.epoch();
  identity.role = SessionRole::ENDPOINT;
  identity.contract = std::string(kPeerContract);
  identity.capability_digest =
      capability_digest_for(config_.endpoint_id, config_.capability, std::string(kVersionString));

  const auto request = make_hello_request(smf::as_bytes(config_.shared_secret), identity, issuer);
  if (!request.ok()) return request.status();

  {
    CanonicalEncoder encoder;
    request.value().encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::HELLO, encoder.view()));
  }

  const auto response_frame = stream.receive();
  if (!response_frame.ok()) return response_frame.status();
  if (response_frame.value().header.type != MessageType::HELLO_ACK) {
    return Status(ReasonCode::PROTOCOL_HANDSHAKE_FAILED, "the coordinator did not answer the hello");
  }
  const auto response = decode_message<HelloResponse>(response_frame.value());
  if (!response.ok()) return response.status();

  const auto key = verify_hello_response(smf::as_bytes(config_.shared_secret), request.value(),
                                         response.value());
  if (!key.ok()) return key.status();
  stream.codec().set_session_key(key.value().view());

  service_address_ = stream.connection().local();

  // Registration is exchanged on this thread before the reader thread exists.
  // Two threads reading the same stream would race for the acknowledgement.
  RegisterRequest registration;
  registration.identity.endpoint = config_.endpoint_id;
  registration.identity.boot = incarnation_.boot();
  registration.identity.epoch = incarnation_.epoch();
  registration.identity.role = static_cast<std::uint8_t>(SessionRole::ENDPOINT);
  registration.identity.contract = std::string(kPeerContract);
  registration.identity.capability_digest = identity.capability_digest;
  registration.service_address = service_address_;
  registration.data_address = data_address();
  registration.inventory_digest = sha256(std::string_view("empty-inventory"));

  {
    CanonicalEncoder encoder;
    registration.encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::REGISTER, encoder.view()));
  }

  const auto ack_frame = stream.receive();
  if (!ack_frame.ok()) return ack_frame.status();
  if (ack_frame.value().header.type != MessageType::REGISTER_ACK) {
    const auto rejection = decode_message<ErrorMessage>(ack_frame.value());
    if (rejection.ok()) return rejection.value().code == ReasonCode::OK
                                 ? Status(ReasonCode::NOT_AUTHORIZED, rejection.value().detail)
                                 : Status(rejection.value().code, rejection.value().detail);
    return Status(ReasonCode::NOT_AUTHORIZED, "the coordinator refused the registration");
  }
  const auto ack = decode_message<RegisterAck>(ack_frame.value());
  if (!ack.ok()) return ack.status();
  policy_generation_ = ack.value().policy_generation;
  topology_generation_ = ack.value().topology_generation;

  // Only now does a second thread start reading the stream.
  control_ = std::make_unique<ControlLink>(std::move(stream));
  control_->reader = std::thread([this]() { control_reader_loop(); });

  log_message(LogLevel::INFO, "endpoint",
              config_.endpoint_id.value() + " registered with topology generation " +
                  std::to_string(ack.value().topology_generation.value()));
  fault_point(fault_points::kEndpointAfterRegister);
  return Status::success();
}

void EndpointAgent::run() {
  std::unique_lock<std::mutex> lock(wake_mutex_);
  wake_.wait(lock, [this]() { return stopping_.load(std::memory_order_acquire); });
}

Status EndpointAgent::request_shutdown() {
  if (stopping_.exchange(true, std::memory_order_acq_rel)) {
    return Status::success();
  }

  // Stop accepting, then release everything that could be blocked. Nothing here
  // joins: this is safe to call from the coordinator link reader.
  if (data_listener_ != nullptr) {
    const Status closed = data_listener_->close();
    (void)closed;
  }
  if (control_ != nullptr) {
    control_->alive.store(false, std::memory_order_release);
    const Status shutdown_status = control_->stream.shutdown();
    (void)shutdown_status;
    std::lock_guard<std::mutex> lock(control_->pending_mutex);
    for (auto& entry : control_->pending) {
      if (entry.second) {
        entry.second->set_value(Frame{});
      }
    }
    control_->pending.clear();
  }
  queue_cv_.notify_all();
  wake_.notify_all();
  return Status::success();
}

Status EndpointAgent::stop() {
  const Status signalled = request_shutdown();
  (void)signalled;

  std::call_once(stop_once_, [this]() {
    if (accept_thread_.joinable()) accept_thread_.join();
    for (std::thread& worker : session_workers_) {
      if (worker.joinable()) worker.join();
    }
    session_workers_.clear();
    if (control_ != nullptr) {
      if (control_->reader.joinable()) control_->reader.join();
      control_.reset();
    }
    std::lock_guard<std::mutex> lock(queue_mutex_);
    session_queue_.clear();
  });
  return Status::success();
}

EndpointCounters EndpointAgent::counters() const {
  std::lock_guard<std::mutex> lock(counters_mutex_);
  return counters_;
}

// ---------------------------------------------------------------------------
// Data listener
// ---------------------------------------------------------------------------

void EndpointAgent::accept_loop() {
  while (!stopping_.load(std::memory_order_acquire)) {
    if (data_listener_ == nullptr) return;
    auto connection = data_listener_->accept(100);
    if (!connection.ok()) {
      if (stopping_.load(std::memory_order_acquire)) return;
      if (connection.status().code() == ReasonCode::IO_TIMEOUT ||
          connection.status().code() == ReasonCode::SHUTTING_DOWN) {
        continue;
      }
      log_message(LogLevel::WARN, "endpoint", "accept failed: " + connection.status().to_string());
      continue;
    }

    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      if (session_queue_.size() >= config_.max_data_sessions) {
        std::lock_guard<std::mutex> counters_lock(counters_mutex_);
        counters_.sessions_refused += 1;
        // Refusing by closing is explicit: the peer observes a closed
        // connection and reports it, rather than waiting in an unbounded queue.
        TcpConnection refused = std::move(connection).value();
        const Status shutdown_status = refused.shutdown();
        (void)shutdown_status;
        continue;
      }
      session_queue_.push_back(std::move(connection).value());
    }
    queue_cv_.notify_one();
  }
}

void EndpointAgent::session_worker_loop() {
  for (;;) {
    TcpConnection connection;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this]() {
        return stopping_.load(std::memory_order_acquire) || !session_queue_.empty();
      });
      if (session_queue_.empty()) {
        if (stopping_.load(std::memory_order_acquire)) return;
        continue;
      }
      connection = std::move(session_queue_.front());
      session_queue_.pop_front();
    }

    active_sessions_.fetch_add(1, std::memory_order_acq_rel);
    const Status status = serve_data_connection(std::move(connection));
    if (!status.ok() && !stopping_.load(std::memory_order_acquire)) {
      log_message(LogLevel::DEBUG, "endpoint", "data session ended: " + status.to_string());
    }
    active_sessions_.fetch_sub(1, std::memory_order_acq_rel);
  }
}

Status EndpointAgent::serve_data_connection(TcpConnection connection) {
  FrameStream stream(std::move(connection), config_.io_budget_millis,
                     static_cast<std::uint32_t>(config_.policy.max_chunk_bytes + (64U << 10)));

  IdIssuer issuer;
  // The data plane authenticates exactly like the control plane, so the source
  // knows which endpoint is asking and can check it against the grant.
  const auto hello_frame = stream.receive();
  if (!hello_frame.ok()) return hello_frame.status();
  if (hello_frame.value().header.type != MessageType::HELLO) {
    return Status(ReasonCode::PROTOCOL_HANDSHAKE_REQUIRED, "data sessions begin with a hello");
  }
  const auto hello = decode_message<HelloRequest>(hello_frame.value());
  if (!hello.ok()) return hello.status();

  PeerIdentity self;
  self.endpoint = config_.endpoint_id;
  self.boot = incarnation_.boot();
  self.epoch = incarnation_.epoch();
  self.role = SessionRole::ENDPOINT;
  self.contract = std::string(kPeerContract);
  self.capability_digest =
      capability_digest_for(config_.endpoint_id, config_.capability, std::string(kVersionString));

  const SessionId session_id = issuer.new_session_id();
  const auto response = accept_hello_request(smf::as_bytes(config_.shared_secret), hello.value(), self,
                                             session_id, issuer);
  if (!response.ok()) {
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.sessions_refused += 1;
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
  {
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.sessions_accepted += 1;
  }

  const auto begin_frame = stream.receive();
  if (!begin_frame.ok()) return begin_frame.status();
  if (begin_frame.value().header.type != MessageType::DATA_BEGIN) {
    return Status(ReasonCode::PROTOCOL_STATE_VIOLATION, "expected a data begin");
  }
  const auto begin = decode_message<DataBegin>(begin_frame.value());
  if (!begin.ok()) return begin.status();

  // ---- authority check -------------------------------------------------
  TransferGrant grant;
  bool found_grant = false;
  {
    std::lock_guard<std::mutex> lock(grants_mutex_);
    const auto entry = grants_.find(Nonce::from_digest(begin.value().nonce));
    if (entry != grants_.end()) {
      grant = entry->second.grant;
      found_grant = !entry->second.consumed;
      if (found_grant) entry->second.consumed = true;  // single use
    }
  }

  const auto refuse = [&](ReasonCode code, const std::string& detail) -> Status {
    DataBeginAck ack;
    ack.nonce = begin.value().nonce;
    ack.code = code;
    ack.detail = detail;
    ack.resume_from_chunk = 0;
    ack.resume_from_offset = 0;
    CanonicalEncoder encoder;
    ack.encode(encoder);
    const Status sent = stream.send(MessageType::DATA_BEGIN_ACK, encoder.view());
    (void)sent;
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.refusals += 1;
    return Status(code, detail);
  };

  if (!found_grant) {
    return refuse(ReasonCode::AUTHORITY_MISMATCH,
                  "no live transfer grant matches that nonce; grants are single use and never "
                  "survive a coordinator restart");
  }
  SMF_RETURN_IF_ERROR(grant.verify_signature(smf::as_bytes(config_.shared_secret)));
  if (grant.source != config_.endpoint_id) {
    return refuse(ReasonCode::AUTHORITY_MISMATCH, "the grant does not name this endpoint as source");
  }
  if (grant.destination != begin.value().destination ||
      grant.destination_incarnation != begin.value().destination_incarnation) {
    return refuse(ReasonCode::STALE_INCARNATION, "the grant binds a different destination");
  }
  if (hello.value().identity.endpoint != grant.destination) {
    return refuse(ReasonCode::PROTOCOL_AUTH_FAILED,
                  "the authenticated peer is not the destination named by the grant");
  }
  if (grant.object.object_id != begin.value().object.object_id ||
      grant.object.generation != begin.value().object.generation ||
      grant.object.content_digest != begin.value().object.content_digest) {
    return refuse(ReasonCode::AUTHORITY_MISMATCH, "the grant binds a different object version");
  }
  if (grant.policy_generation != policy_generation_) {
    return refuse(ReasonCode::STALE_POLICY_GENERATION,
                  "the grant was issued under a different policy generation");
  }
  if (!store_->object_present(grant.object.object_id, grant.object.generation)) {
    return refuse(ReasonCode::OBJECT_VERSION_NOT_FOUND,
                  "this endpoint does not hold the requested object version");
  }

  // Resumption is accepted only when the destination's declared prefix matches
  // the object the grant authorizes.
  std::uint32_t start_chunk = 0;
  std::uint64_t start_offset = 0;
  if (begin.value().resume_from_chunk > 0 &&
      begin.value().resume_from_chunk <= grant.object.chunk_count) {
    const auto offset = grant.object.chunk_offset(begin.value().resume_from_chunk);
    if (offset.ok() && offset.value() == begin.value().resume_from_offset) {
      start_chunk = begin.value().resume_from_chunk;
      start_offset = begin.value().resume_from_offset;
    }
  }

  {
    DataBeginAck ack;
    ack.nonce = begin.value().nonce;
    ack.code = ReasonCode::OK;
    ack.resume_from_chunk = start_chunk;
    ack.resume_from_offset = start_offset;
    CanonicalEncoder encoder;
    ack.encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::DATA_BEGIN_ACK, encoder.view()));
  }

  // ---- transfer --------------------------------------------------------
  FileHandle object_file;
  SMF_RETURN_IF_ERROR(object_file.open(
      store_->object_data_path(grant.object.object_id, grant.object.generation), false));

  const std::shared_ptr<std::atomic<bool>> cancelled = cancellation_flag(grant.movement_id);

  const std::uint32_t window = config_.policy.max_inflight_chunks;
  Bytes buffer(static_cast<std::size_t>(grant.object.chunk_bytes));
  std::uint64_t sent_bytes = 0;
  std::uint32_t sent_chunks = 0;

  for (std::uint32_t index = start_chunk; index < grant.object.chunk_count; ++index) {
    if (stopping_.load(std::memory_order_acquire) ||
        (cancelled != nullptr && cancelled->load(std::memory_order_acquire))) {
      DataAbort abort;
      abort.movement_id = grant.movement_id;
      abort.attempt = grant.attempt;
      abort.code = ReasonCode::CANCELLED_BY_OPERATOR;
      abort.detail = "the movement was cancelled while it was being served";
      CanonicalEncoder encoder;
      abort.encode(encoder);
      const Status sent = stream.send(MessageType::DATA_ABORT, encoder.view());
      (void)sent;
      return Status(ReasonCode::CANCELLED_BY_OPERATOR, abort.detail);
    }

    const auto offset = grant.object.chunk_offset(index);
    if (!offset.ok()) return offset.status();
    const auto length = grant.object.chunk_length(index);
    if (!length.ok()) return length.status();

    SMF_RETURN_IF_ERROR(object_file.seek(offset.value()));
    const auto read = object_file.read(ByteSpan(buffer.data(), static_cast<std::size_t>(length.value())));
    if (!read.ok()) return read.status();
    if (read.value() != static_cast<std::size_t>(length.value())) {
      return Status(ReasonCode::STORE_TRUNCATED, "the stored object ended inside a chunk");
    }

    DataChunk chunk;
    chunk.movement_id = grant.movement_id;
    chunk.attempt = grant.attempt;
    chunk.chunk_index = index;
    chunk.chunk_offset = offset.value();
    chunk.chunk_length = length.value();
    chunk.chunk_digest = compute_chunk_digest(grant.object.object_id, grant.object.generation, index,
                                              offset.value(), length.value(),
                                              ByteView(buffer.data(), static_cast<std::size_t>(length.value())));
    chunk.payload.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length.value()));

    CanonicalEncoder encoder;
    chunk.encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::DATA_CHUNK, encoder.view()));
    sent_bytes += length.value();
    sent_chunks += 1;

    fault_point(fault_points::kSourceAfterChunkSend);

    if ((sent_chunks % window) == 0) {
      const auto ack_frame = stream.receive();
      if (!ack_frame.ok()) return ack_frame.status();
      if (ack_frame.value().header.type != MessageType::DATA_CHUNK_ACK) {
        return Status(ReasonCode::PROTOCOL_STATE_VIOLATION, "expected a chunk acknowledgement");
      }
    }
  }

  fault_point(fault_points::kSourceBeforeEnd);

  DataEnd end;
  end.movement_id = grant.movement_id;
  end.attempt = grant.attempt;
  end.total_chunks = grant.object.chunk_count;
  end.total_bytes = grant.object.total_bytes;
  end.content_digest = grant.object.content_digest;
  {
    CanonicalEncoder encoder;
    end.encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::DATA_END, encoder.view()));
  }

  const auto result_frame = stream.receive();
  if (!result_frame.ok()) return result_frame.status();
  if (result_frame.value().header.type != MessageType::DATA_RESULT) {
    return Status(ReasonCode::PROTOCOL_STATE_VIOLATION, "expected a data result");
  }
  const auto result = decode_message<DataResult>(result_frame.value());
  if (!result.ok()) return result.status();

  {
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.transfers_served += 1;
    counters_.bytes_sent += sent_bytes;
  }

  if (result.value().code != ReasonCode::OK) {
    return Status(result.value().code, result.value().detail);
  }
  return Status::success();
}

// ---------------------------------------------------------------------------
// Control plane
// ---------------------------------------------------------------------------

Status EndpointAgent::send_control(MessageType type, const CanonicalEncoder& payload) {
  if (control_ == nullptr || !control_->alive.load(std::memory_order_acquire)) {
    return Status(ReasonCode::CONNECTION_CLOSED, "the coordinator link is not available");
  }
  std::lock_guard<std::mutex> lock(control_->send_mutex);
  return control_->stream.send(type, payload.view());
}

void EndpointAgent::control_reader_loop() {
  while (!stopping_.load(std::memory_order_acquire)) {
    auto frame = control_->stream.receive();
    if (!frame.ok()) {
      if (!stopping_.load(std::memory_order_acquire)) {
        log_message(LogLevel::WARN, "endpoint",
                    "coordinator link ended: " + frame.status().to_string());
      }
      // Release every worker that is waiting on an answer that can no longer
      // arrive, so shutdown never leaves a thread blocked.
      std::lock_guard<std::mutex> lock(control_->pending_mutex);
      for (auto& entry : control_->pending) {
        if (entry.second) entry.second->set_value(Frame{});
      }
      control_->pending.clear();
      break;
    }

    // Complete a waiting request first: worker threads are blocked on these.
    const std::string key = std::string(to_string(frame.value().header.type));
    std::shared_ptr<std::promise<Frame>> promise;
    {
      std::lock_guard<std::mutex> lock(control_->pending_mutex);
      const auto found = control_->pending.find(key);
      if (found != control_->pending.end()) {
        promise = found->second;
        control_->pending.erase(found);
      }
    }
    if (promise) {
      promise->set_value(std::move(frame).value());
      continue;
    }

    const Status handled = handle_control(frame.value());
    if (!handled.ok()) {
      log_message(LogLevel::DEBUG, "endpoint", "control message refused: " + handled.to_string());
      ErrorMessage error;
      error.code = handled.code();
      error.detail = handled.message();
      CanonicalEncoder encoder;
      error.encode(encoder);
      const Status sent = send_control(MessageType::ERROR, encoder);
      (void)sent;
    }
  }
}

std::shared_ptr<std::atomic<bool>> EndpointAgent::cancellation_flag(const MovementId& movement_id) {
  std::lock_guard<std::mutex> lock(cancels_mutex_);
  const auto found = cancellations_.find(movement_id);
  if (found != cancellations_.end()) {
    return found->second;
  }
  auto flag = std::make_shared<std::atomic<bool>>(false);
  cancellations_.emplace(movement_id, flag);
  return flag;
}

void EndpointAgent::clear_cancellation(const MovementId& movement_id) {
  std::lock_guard<std::mutex> lock(cancels_mutex_);
  cancellations_.erase(movement_id);
}

Status EndpointAgent::handle_control(const Frame& frame) {
  switch (frame.header.type) {
    case MessageType::GRANT_TRANSFER: {
      const auto message = decode_message<GrantTransfer>(frame);
      if (!message.ok()) return message.status();
      return on_grant(message.value().grant);
    }
    case MessageType::EXECUTE_MOVEMENT: {
      const auto message = decode_message<ExecuteMovement>(frame);
      if (!message.ok()) return message.status();
      return on_execute(message.value());
    }
    case MessageType::COMMIT_REQUEST: {
      const auto message = decode_message<CommitRequest>(frame);
      if (!message.ok()) return message.status();
      return on_commit_request(message.value());
    }
    case MessageType::VERIFY_REQUEST: {
      const auto message = decode_message<VerifyRequest>(frame);
      if (!message.ok()) return message.status();
      return on_verify_request(message.value());
    }
    case MessageType::AUTHORITY_QUERY: {
      const auto message = decode_message<AuthorityQuery>(frame);
      if (!message.ok()) return message.status();
      return on_authority_query(message.value());
    }
    case MessageType::CLEANUP_REQUEST: {
      const auto message = decode_message<CleanupRequest>(frame);
      if (!message.ok()) return message.status();
      return on_cleanup_request(message.value());
    }
    case MessageType::CANCEL: {
      const auto message = decode_message<CancelRequest>(frame);
      if (!message.ok()) return message.status();
      return on_cancel(message.value());
    }
    case MessageType::HEARTBEAT: {
      CanonicalEncoder encoder("SMF-MSG-HEARTBEAT-ACK-v1");
      return send_control(MessageType::HEARTBEAT_ACK, encoder);
    }

    // Acknowledgements and error reports are informational here. They are
    // recorded and never treated as a protocol violation.
    case MessageType::ANNOUNCE_ACK:
    case MessageType::GRANT_ACK:
    case MessageType::CANCEL_ACK:
    case MessageType::SHUTDOWN_ACK:
      return Status::success();

    case MessageType::ERROR: {
      const auto message = decode_message<ErrorMessage>(frame);
      if (message.ok()) {
        log_message(LogLevel::DEBUG, "endpoint",
                    "the coordinator reported " + std::string(to_string(message.value().code)) +
                        ": " + message.value().detail);
      }
      return Status::success();
    }
    case MessageType::SHUTDOWN: {
      // Signal only: this runs on the reader thread, which stop() would join.
      return request_shutdown();
    }
    default:
      return Status(ReasonCode::PROTOCOL_UNKNOWN_MESSAGE,
                    std::string("the endpoint does not accept ") +
                        to_string(frame.header.type) + " on the coordinator link");
  }
}

Status EndpointAgent::on_grant(const TransferGrant& grant) {
  SMF_RETURN_IF_ERROR(grant.verify_signature(smf::as_bytes(config_.shared_secret)));
  const Status valid = grant.validate();
  if (!valid.ok()) return valid;
  if (grant.policy_generation != policy_generation_) {
    return Status(ReasonCode::STALE_POLICY_GENERATION,
                  "the grant was issued under a different policy generation");
  }
  if (grant.source != config_.endpoint_id && grant.destination != config_.endpoint_id) {
    return Status(ReasonCode::AUTHORITY_MISMATCH, "the grant does not involve this endpoint");
  }

  GrantEntry entry;
  entry.grant = grant;
  entry.received_unix_millis = system_clock().unix_millis();
  {
    std::lock_guard<std::mutex> lock(grants_mutex_);
    if (grants_.size() >= config_.policy.max_movements_in_flight * 2U) {
      return Status(ReasonCode::RESOURCE_EXHAUSTED, "too many live transfer grants");
    }
    grants_.insert_or_assign(grant.grant_nonce, entry);
  }

  GrantAck ack;
  ack.nonce = Digest(grant.grant_nonce.bytes());
  ack.code = ReasonCode::OK;
  ack.detail = "grant recorded";
  CanonicalEncoder encoder;
  ack.encode(encoder);
  return send_control(MessageType::GRANT_ACK, encoder);
}

Status EndpointAgent::on_execute(const ExecuteMovement& message) {
  TransferGrant grant;
  {
    std::lock_guard<std::mutex> lock(grants_mutex_);
    const auto entry = grants_.find(Nonce::from_digest(message.nonce));
    if (entry == grants_.end()) {
      return Status(ReasonCode::AUTHORITY_MISMATCH, "no grant matches that nonce");
    }
    grant = entry->second.grant;
  }
  if (grant.destination != config_.endpoint_id) {
    return Status(ReasonCode::NOT_AUTHORIZED, "this endpoint is not the destination of the grant");
  }
  if (grant.movement_id != message.movement_id || grant.attempt != message.attempt) {
    return Status(ReasonCode::AUTHORITY_MISMATCH, "the execute request does not match the grant");
  }
  if (active_sessions_.load(std::memory_order_acquire) >= config_.max_concurrent_movements +
                                                          config_.max_data_sessions) {
    return Status(ReasonCode::RESOURCE_EXHAUSTED, "too many concurrent movements");
  }

  {
    std::lock_guard<std::mutex> lock(cancels_mutex_);
    cancellations_.insert_or_assign(message.movement_id,
                                    std::make_shared<std::atomic<bool>>(false));
  }

  // The transfer runs on its own thread so the control link keeps answering.
  std::thread worker([this, movement_id = message.movement_id, attempt = message.attempt,
                      nonce = Nonce::from_digest(message.nonce)]() {
    execute_movement_worker(movement_id, attempt, nonce);
  });
  worker.detach();
  return Status::success();
}

void EndpointAgent::execute_movement_worker(MovementId movement_id, TransferAttemptId attempt,
                                            Nonce nonce) {
  TransferGrant grant;
  {
    std::lock_guard<std::mutex> lock(grants_mutex_);
    const auto entry = grants_.find(nonce);
    if (entry == grants_.end()) {
      return;
    }
    grant = entry->second.grant;
  }

  const Status status = run_transfer(grant, attempt);
  if (!status.ok()) {
    log_message(LogLevel::WARN, "endpoint",
                "transfer " + movement_id.hex().substr(0, 12) + " failed: " + status.to_string());
    const Status reported =
        report_attempt_result(movement_id, grant.movement_generation, attempt,
                              status.code() == ReasonCode::CANCELLED_BY_OPERATOR
                                  ? MovementState::CANCELLED
                                  : MovementState::FAILED,
                              status.code(), status.message(), Digest(), 0, 0, Digest());
    (void)reported;
  }
}

Status EndpointAgent::run_transfer(const TransferGrant& grant, const TransferAttemptId& attempt) {
  // Resolve where the source is serving data. The topology answer is the only
  // place a peer address comes from; it is never taken from the grant.
  CanonicalEncoder topology_request_encoder;
  TopologyRequest topology_request;
  topology_request.encode(topology_request_encoder);

  auto promise = std::make_shared<std::promise<Frame>>();
  auto future = promise->get_future();
  {
    std::lock_guard<std::mutex> lock(control_->pending_mutex);
    if (control_->pending.count("TOPOLOGY_REPORT") != 0) {
      return Status(ReasonCode::BUSY, "another topology query is already in flight");
    }
    control_->pending.emplace("TOPOLOGY_REPORT", promise);
  }
  const Status sent = send_control(MessageType::TOPOLOGY_REQUEST, topology_request_encoder);
  if (!sent.ok()) {
    std::lock_guard<std::mutex> lock(control_->pending_mutex);
    control_->pending.erase("TOPOLOGY_REPORT");
    return sent;
  }

  if (future.wait_for(std::chrono::milliseconds(config_.io_budget_millis)) !=
      std::future_status::ready) {
    std::lock_guard<std::mutex> lock(control_->pending_mutex);
    control_->pending.erase("TOPOLOGY_REPORT");
    return Status(ReasonCode::IO_TIMEOUT, "the coordinator did not answer the topology query");
  }
  auto topology_frame = future.get();
  if (topology_frame.header.type != MessageType::TOPOLOGY_REPORT) {
    return Status(ReasonCode::IO_TIMEOUT, "the coordinator link closed before the answer arrived");
  }
  const auto topology = decode_message<TopologyReport>(topology_frame);
  if (!topology.ok()) return topology.status();

  SocketAddress source_address;
  bool found = false;
  for (const EndpointRegistration& registration : topology.value().endpoints) {
    if (registration.endpoint == grant.source) {
      source_address = registration.data_address;
      found = true;
      break;
    }
  }
  if (!found) {
    return Status(ReasonCode::ENDPOINT_NOT_FOUND,
                  "the coordinator does not list the source endpoint");
  }

  // ---- open the staging writer first: it decides where to resume ----
  auto writer = StagingWriter::begin(*store_, grant.movement_id, grant.movement_generation, attempt,
                                     grant.object);
  if (!writer.ok()) return writer.status();
  StagingWriter staging = std::move(writer).value();

  auto connection = TcpConnection::connect(source_address, config_.io_budget_millis);
  if (!connection.ok()) return connection.status();

  FrameStream stream(std::move(connection).value(), config_.io_budget_millis,
                     static_cast<std::uint32_t>(config_.policy.max_chunk_bytes + (64U << 10)));

  IdIssuer issuer;
  PeerIdentity self;
  self.endpoint = config_.endpoint_id;
  self.boot = incarnation_.boot();
  self.epoch = incarnation_.epoch();
  self.role = SessionRole::ENDPOINT;
  self.contract = std::string(kPeerContract);
  self.capability_digest =
      capability_digest_for(config_.endpoint_id, config_.capability, std::string(kVersionString));

  const auto hello = make_hello_request(smf::as_bytes(config_.shared_secret), self, issuer);
  if (!hello.ok()) return hello.status();
  {
    CanonicalEncoder encoder;
    hello.value().encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::HELLO, encoder.view()));
  }
  const auto hello_ack_frame = stream.receive();
  if (!hello_ack_frame.ok()) return hello_ack_frame.status();
  if (hello_ack_frame.value().header.type != MessageType::HELLO_ACK) {
    return Status(ReasonCode::SOURCE_REJECTED, "the source refused the data session");
  }
  const auto hello_ack = decode_message<HelloResponse>(hello_ack_frame.value());
  if (!hello_ack.ok()) return hello_ack.status();
  const auto key = verify_hello_response(smf::as_bytes(config_.shared_secret), hello.value(),
                                         hello_ack.value());
  if (!key.ok()) return key.status();
  stream.codec().set_session_key(key.value().view());

  DataBegin begin;
  begin.nonce = Digest(grant.grant_nonce.bytes());
  begin.movement_id = grant.movement_id;
  begin.movement_generation = grant.movement_generation;
  begin.attempt = attempt;
  begin.object = grant.object;
  begin.destination = config_.endpoint_id;
  begin.destination_incarnation = grant.destination_incarnation;
  begin.resume_from_chunk = staging.resume_from_chunk();
  begin.resume_from_offset =
      staging.resume_from_chunk() == 0 ? 0 : staging.journal().verified_bytes;
  {
    CanonicalEncoder encoder;
    begin.encode(encoder);
    SMF_RETURN_IF_ERROR(stream.send(MessageType::DATA_BEGIN, encoder.view()));
  }

  const auto ack_frame = stream.receive();
  if (!ack_frame.ok()) return ack_frame.status();
  const auto ack = decode_message<DataBeginAck>(ack_frame.value());
  if (!ack.ok()) return ack.status();
  if (ack.value().code != ReasonCode::OK) {
    return Status(ack.value().code, ack.value().detail);
  }
  if (ack.value().resume_from_chunk != staging.resume_from_chunk()) {
    // The source refused the resume point, so the staged bytes are not usable.
    staging.abort();
    clear_cancellation(grant.movement_id);
    return Status(ReasonCode::RESUME_INCOMPATIBLE,
                  "the source refused the resume point declared by the destination");
  }

  const std::shared_ptr<std::atomic<bool>> cancel_flag = cancellation_flag(grant.movement_id);

  std::uint32_t received = 0;
  std::uint32_t duplicates = 0;
  std::uint32_t since_ack = 0;

  for (;;) {
    if (stopping_.load(std::memory_order_acquire) ||
        (cancel_flag != nullptr && cancel_flag->load(std::memory_order_acquire))) {
      staging.abort();
      return Status(ReasonCode::CANCELLED_BY_OPERATOR, "the movement was cancelled");
    }

    const auto frame = stream.receive();
    if (!frame.ok()) {
      // The prefix stays journalled, so a later attempt can resume from it.
      staging.abort();
      return frame.status();
    }

    if (frame.value().header.type == MessageType::DATA_ABORT) {
      const auto abort = decode_message<DataAbort>(frame.value());
      staging.abort();
      if (abort.ok()) return Status(abort.value().code, abort.value().detail);
      return Status(ReasonCode::SOURCE_REJECTED, "the source aborted the transfer");
    }
    if (frame.value().header.type == MessageType::DATA_END) {
      const auto end = decode_message<DataEnd>(frame.value());
      if (!end.ok()) {
        staging.abort();
        return end.status();
      }
      if (end.value().movement_id != grant.movement_id || end.value().attempt != attempt) {
        staging.abort();
        return Status(ReasonCode::AUTHORITY_MISMATCH,
                      "the transfer end names a different movement or attempt");
      }
      if (end.value().content_digest != grant.object.content_digest) {
        staging.abort();
        return Status(ReasonCode::CONTENT_DIGEST_MISMATCH,
                      "the source declared a content digest the grant does not authorize");
      }
      break;
    }
    if (frame.value().header.type != MessageType::DATA_CHUNK) {
      staging.abort();
      return Status(ReasonCode::PROTOCOL_STATE_VIOLATION, "expected a data chunk");
    }

    const auto chunk = decode_message<DataChunk>(frame.value());
    if (!chunk.ok()) {
      staging.abort();
      return chunk.status();
    }
    if (chunk.value().movement_id != grant.movement_id || chunk.value().attempt != attempt) {
      staging.abort();
      return Status(ReasonCode::AUTHORITY_MISMATCH, "a chunk arrived for a different attempt");
    }

    const bool duplicate = chunk.value().chunk_index < staging.resume_from_chunk();
    const auto appended =
        staging.append(chunk.value().chunk_index, chunk.value().chunk_offset,
                       smf::as_bytes(chunk.value().payload), chunk.value().chunk_digest);
    if (!appended.ok()) {
      staging.abort();
      return appended.status();
    }
    if (duplicate) {
      ++duplicates;
    } else {
      ++received;
    }
    ++since_ack;

    if (since_ack >= config_.policy.max_inflight_chunks) {
      since_ack = 0;
      DataChunkAck chunk_ack;
      chunk_ack.movement_id = grant.movement_id;
      chunk_ack.attempt = attempt;
      chunk_ack.highest_contiguous_index = staging.resume_from_chunk() - 1U;
      chunk_ack.duplicates_ignored = duplicates;
      CanonicalEncoder encoder;
      chunk_ack.encode(encoder);
      SMF_RETURN_IF_ERROR(stream.send(MessageType::DATA_CHUNK_ACK, encoder.view()));
    }

  }

  // The staged bytes are complete. Nothing is promoted, and nothing is
  // acknowledged to the source, until they hash to the digest the grant
  // authorizes.
  const auto digest = staging.finish();
  if (!digest.ok()) {
    return digest.status();
  }
  if (digest.value() != grant.object.content_digest) {
    const Status discarded = store_->discard_staging(grant.movement_id);
    (void)discarded;
    return Status(ReasonCode::CONTENT_DIGEST_MISMATCH,
                  "the received bytes do not hash to the authorized content digest");
  }
  SMF_RETURN_IF_ERROR(staging.promote());

  DataResult result;
  result.movement_id = grant.movement_id;
  result.attempt = attempt;
  result.code = ReasonCode::OK;
  result.stored_digest = digest.value();
  result.stored_bytes = grant.object.total_bytes;
  result.stored_chunks = grant.object.chunk_count;
  result.detail = "stored and verified locally";
  {
    CanonicalEncoder encoder;
    result.encode(encoder);
    const Status result_sent = stream.send(MessageType::DATA_RESULT, encoder.view());
    (void)result_sent;
  }

  {
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.transfers_received += 1;
    counters_.bytes_received += grant.object.total_bytes;
    counters_.chunks_written += received;
    counters_.duplicate_chunks += duplicates;
  }

  // Bytes exist and hash correctly here, but that is not authority: the
  // coordinator still verifies independently and then asks for the commit
  // barrier. The reported state is BYTES_ARRIVED, never COMMITTED.
  return report_attempt_result(grant.movement_id, grant.movement_generation, attempt,
                               MovementState::BYTES_ARRIVED, ReasonCode::OK,
                               "bytes arrived and verified locally", digest.value(),
                               grant.object.total_bytes, grant.object.chunk_count, Digest());
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

Status EndpointAgent::publish_file(StateKind kind, std::string name, StateGeneration generation,
                                   const std::filesystem::path& source_file,
                                   const std::string& producer, bool repeatable) {
  FileHandle handle;
  SMF_RETURN_IF_ERROR(handle.open(source_file, false));
  const auto size = handle.size();
  if (!size.ok()) return size.status();
  if (size.value() > config_.policy.max_object_bytes) {
    return Status(ReasonCode::POLICY_VIOLATION, "the file exceeds the configured object bound");
  }

  // A fixed segmentation independent of the file size, clamped into the bounds
  // the policy declares, so that chunk arithmetic is uniform for every object.
  const std::uint64_t preferred_chunk = 1ULL << 20;
  const std::uint64_t chunk_bytes =
      std::min<std::uint64_t>(config_.policy.max_chunk_bytes,
                              std::max<std::uint64_t>(config_.policy.min_chunk_bytes,
                                                      preferred_chunk));
  Sha256 hasher;
  Bytes buffer(static_cast<std::size_t>(std::min<std::uint64_t>(1U << 20, std::max<std::uint64_t>(size.value(), 1))));
  for (;;) {
    const auto read = handle.read(ByteSpan(buffer.data(), buffer.size()));
    if (!read.ok()) return read.status();
    if (read.value() == 0) break;
    hasher.update(ByteView(buffer.data(), read.value()));
    if (read.value() < buffer.size()) break;
  }
  const Digest content = hasher.finalize();
  handle.close();

  const auto descriptor = StateObjectDescriptor::create(
      kind, std::move(name), generation, content, size.value(), chunk_bytes,
      system_clock().unix_millis(), producer);
  if (!descriptor.ok()) return descriptor.status();

  StateObjectDescriptor value = descriptor.value();
  value.repeatable = repeatable;

  const std::filesystem::path directory = store_->object_directory(value.object_id, generation);
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not create the object directory");

  const std::filesystem::path temporary = directory / "data.import";
  {
    std::filesystem::copy_file(source_file, temporary,
                               std::filesystem::copy_options::overwrite_existing, error);
    if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not copy the object into the store");
    SMF_RETURN_IF_ERROR(sync_existing_file(temporary));
    const std::filesystem::path target = store_->object_data_path(value.object_id, generation);
    std::filesystem::remove(target, error);
    std::filesystem::rename(temporary, target, error);
    if (error) return Status(ReasonCode::STORE_IO_ERROR, "could not place the object bytes");
  }

  IdIssuer issuer;
  const auto origin = EndpointId::parse(kLocalOrigin);
  if (!origin.ok()) return origin.status();

  CommitMarker marker;
  marker.movement_id = issuer.new_movement_id();
  marker.movement_generation = MovementGeneration(1);
  marker.object = value;
  marker.source = origin.value();
  marker.destination = config_.endpoint_id;
  marker.destination_incarnation = DestinationIncarnation::make(
      config_.endpoint_id, incarnation_.boot(), incarnation_.epoch()).value();
  marker.content_digest = content;
  marker.stored_bytes = size.value();
  marker.stored_chunks = value.chunk_count;
  marker.committed_unix_millis = system_clock().unix_millis();
  marker.seal();
  SMF_RETURN_IF_ERROR(store_->write_commit_marker(marker));

  {
    std::lock_guard<std::mutex> lock(counters_mutex_);
    counters_.objects_published += 1;
  }
  log_message(LogLevel::INFO, "endpoint", "published " + describe(value));
  return Status::success();
}

Status EndpointAgent::announce(const StateObjectDescriptor& descriptor) {
  AnnounceObject message;
  message.descriptor = descriptor;
  CanonicalEncoder encoder;
  message.encode(encoder);
  return send_control(MessageType::ANNOUNCE_OBJECT, encoder);
}

// ---------------------------------------------------------------------------
// Coordinator-directed operations
// ---------------------------------------------------------------------------

Status EndpointAgent::report_attempt_result(const MovementId& movement_id,
                                            MovementGeneration generation,
                                            const TransferAttemptId& attempt, MovementState state,
                                            ReasonCode code, const std::string& detail,
                                            const Digest& verified_digest, std::uint64_t bytes,
                                            std::uint32_t chunks, const Digest& marker) {
  AttemptResult result;
  result.movement_id = movement_id;
  result.movement_generation = generation;
  result.attempt = attempt;
  result.state = state;
  result.code = code;
  result.detail = detail;
  result.verified_digest = verified_digest;
  result.bytes = bytes;
  result.chunks = chunks;
  result.marker_digest = marker;
  CanonicalEncoder encoder;
  result.encode(encoder);
  return send_control(MessageType::ATTEMPT_RESULT, encoder);
}

Status EndpointAgent::on_commit_request(const CommitRequest& message) {
  const std::shared_ptr<std::atomic<bool>> cancelled = [&]() {
    std::lock_guard<std::mutex> lock(cancels_mutex_);
    const auto found = cancellations_.find(message.movement_id);
    return found == cancellations_.end() ? std::shared_ptr<std::atomic<bool>>() : found->second;
  }();

  CommitResult result;
  result.movement_id = message.movement_id;
  result.movement_generation = message.movement_generation;

  const auto reject = [&](ReasonCode code, const std::string& detail) -> Status {
    result.code = code;
    result.detail = detail;
    CanonicalEncoder encoder;
    result.encode(encoder);
    const Status sent = send_control(MessageType::COMMIT_RESULT, encoder);
    (void)sent;
    return Status(code, detail);
  };

  if (cancelled != nullptr && cancelled->load(std::memory_order_acquire)) {
    return reject(ReasonCode::MOVEMENT_CANCELLED,
                  "the movement was cancelled before the commit barrier");
  }

  fault_point(fault_points::kDestinationBeforeMarker);

  const StateObjectDescriptor& object = message.object;
  if (!store_->object_present(object.object_id, object.generation)) {
    return reject(ReasonCode::OBJECT_NOT_FOUND, "no bytes are placed for that object version");
  }

  // The destination re-verifies its own bytes before it commits anything. An
  // acknowledgement must never precede the durability point it claims.
  std::uint64_t stored_bytes = 0;
  const auto digest = store_->digest_object(object.object_id, object.generation, &stored_bytes);
  if (!digest.ok()) return reject(digest.status().code(), digest.status().message());
  if (digest.value() != object.content_digest) {
    return reject(ReasonCode::CONTENT_DIGEST_MISMATCH,
                  "the stored bytes no longer hash to the authorized content digest");
  }
  if (stored_bytes != object.total_bytes) {
    return reject(ReasonCode::BYTE_COUNT_MISMATCH, "the stored byte count changed before commit");
  }

  CommitMarker marker;
  marker.movement_id = message.movement_id;
  marker.movement_generation = message.movement_generation;
  marker.object = object;
  marker.source = message.source;
  marker.destination = config_.endpoint_id;
  marker.destination_incarnation =
      DestinationIncarnation::make(config_.endpoint_id, incarnation_.boot(), incarnation_.epoch())
          .value();
  marker.content_digest = object.content_digest;
  marker.stored_bytes = stored_bytes;
  marker.stored_chunks = object.chunk_count;
  marker.committed_unix_millis = system_clock().unix_millis();
  marker.seal();

  const Status written = store_->write_commit_marker(marker);
  if (!written.ok()) return reject(written.code(), written.message());

  fault_point(fault_points::kDestinationAfterMarker);

  result.code = ReasonCode::OK;
  result.marker_digest = marker.marker_digest;
  result.detail = "commit marker written";
  CanonicalEncoder encoder;
  result.encode(encoder);
  return send_control(MessageType::COMMIT_RESULT, encoder);
}

Status EndpointAgent::on_verify_request(const VerifyRequest& message) {
  VerifyResponse response;
  response.movement_id = message.movement_id;
  response.object_id = message.object_id;
  response.object_generation = message.object_generation;

  const auto reply = [&](ReasonCode code, const std::string& detail) -> Status {
    response.code = code;
    (void)detail;
    CanonicalEncoder encoder;
    response.encode(encoder);
    return send_control(MessageType::VERIFY_RESPONSE, encoder);
  };

  if (!store_->object_present(message.object_id, message.object_generation)) {
    return reply(ReasonCode::OBJECT_VERSION_NOT_FOUND, "no bytes are placed for that version");
  }

  std::uint64_t stored_bytes = 0;
  if (message.full_digest_requested) {
    const auto digest = store_->digest_object(message.object_id, message.object_generation,
                                              &stored_bytes);
    if (!digest.ok()) return reply(digest.status().code(), digest.status().message());
    response.stored_digest = digest.value();
    response.stored_bytes = stored_bytes;
    response.stored_chunks = 0;
    return reply(ReasonCode::OK, {});
  }

  // The coordinator asked for one chunk's exact bytes so that it can hash them
  // itself rather than trusting a number reported by this process.
  const std::uint64_t chunk_bytes = message.chunk_bytes;
  std::uint64_t offset = 0;
  if (!checked_mul(static_cast<std::uint64_t>(message.chunk_index), chunk_bytes, offset)) {
    return reply(ReasonCode::SIZE_OVERFLOW, "chunk offset computation overflowed");
  }
  const auto size = store_->object_size(message.object_id, message.object_generation);
  if (!size.ok()) return reply(size.status().code(), size.status().message());
  if (offset >= size.value()) {
    return reply(ReasonCode::CHUNK_INDEX_OUT_OF_RANGE, "that chunk lies beyond the stored object");
  }
  const std::uint64_t length = std::min<std::uint64_t>(chunk_bytes, size.value() - offset);
  const auto bytes = store_->read_range(message.object_id, message.object_generation, offset, length,
                                        chunk_bytes);
  if (!bytes.ok()) return reply(bytes.status().code(), bytes.status().message());

  // The digest the destination claims for this chunk. It is reported so that
  // the coordinator can compare it against the digest it computes itself from
  // the returned bytes; the claim alone is never enough.
  response.chunk_index = message.chunk_index;
  response.chunk_payload = bytes.value();
  response.chunk_digest = compute_chunk_digest(message.object_id, message.object_generation,
                                               message.chunk_index, offset, length,
                                               smf::as_bytes(bytes.value()));
  response.stored_bytes = size.value();
  response.stored_chunks = 0;
  return reply(ReasonCode::OK, {});
}

Status EndpointAgent::on_authority_query(const AuthorityQuery& message) {
  AuthorityReport report;
  report.movement_id = message.movement_id;

  const auto authority = store_->authority(message.object_id, message.object_generation);
  // Mapped deliberately: the storage layer's view becomes the wire report.
  if (!authority.ok()) {
    report.code = authority.status().code();
    report.detail = authority.status().message();
  } else {
    report.code = authority.value().code;
    report.detail = authority.value().detail;
    report.bytes_present = authority.value().bytes_present;
    report.marker_present = authority.value().marker_present;
    report.authoritative = authority.value().authoritative;
    report.marker_digest = authority.value().marker_digest;
    report.stored_bytes = authority.value().stored_bytes;
  }
  if (!report.bytes_present) {
    report.bytes_present = store_->object_present(message.object_id, message.object_generation);
  }
  // "verified" here means the commit marker binding checked out. It is never set
  // merely because bytes exist.
  report.verified = report.marker_present && report.authoritative;

  CanonicalEncoder encoder;
  report.encode(encoder);
  return send_control(MessageType::AUTHORITY_REPORT, encoder);
}

Status EndpointAgent::on_cleanup_request(const CleanupRequest& message) {
  CleanupResult result;
  result.movement_id = message.movement_id;

  CleanupTarget target;
  target.movement_id = message.movement_id;
  target.quarantine = message.quarantine;

  std::uint64_t bytes_removed = 0;
  std::uint32_t entries_removed = 0;
  const Status cleaned = store_->cleanup(target, &bytes_removed, &entries_removed);
  result.code = cleaned.ok() ? ReasonCode::OK : cleaned.code();
  result.detail = cleaned.ok() ? "staging removed" : cleaned.message();
  result.bytes_removed = bytes_removed;
  result.entries_removed = entries_removed;

  {
    std::lock_guard<std::mutex> lock(grants_mutex_);
    for (auto it = grants_.begin(); it != grants_.end();) {
      it = it->second.grant.movement_id == message.movement_id ? grants_.erase(it) : std::next(it);
    }
  }
  clear_cancellation(message.movement_id);

  CanonicalEncoder encoder;
  result.encode(encoder);
  return send_control(MessageType::CLEANUP_RESULT, encoder);
}

Status EndpointAgent::on_cancel(const CancelRequest& message) {
  {
    std::lock_guard<std::mutex> lock(cancels_mutex_);
    const auto found = cancellations_.find(message.movement_id);
    if (found != cancellations_.end()) {
      found->second->store(true, std::memory_order_release);
    } else {
      auto flag = std::make_shared<std::atomic<bool>>(true);
      cancellations_.emplace(message.movement_id, flag);
    }
  }

  CancelAck ack;
  ack.movement_id = message.movement_id;
  ack.movement_generation = message.movement_generation;
  ack.code = ReasonCode::OK;
  ack.detail = "cancellation recorded";
  CanonicalEncoder encoder;
  ack.encode(encoder);
  return send_control(MessageType::CANCEL_ACK, encoder);
}

}  // namespace smf
