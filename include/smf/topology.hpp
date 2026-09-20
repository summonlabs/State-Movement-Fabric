// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Topology is a coordinator-owned, in-memory view of who is currently
// reachable. It is deliberately never persisted as liveness: only the
// generation counter survives a restart, and every registration is dropped, so
// that a restarted coordinator cannot resurrect a peer that has since died.

#ifndef SMF_TOPOLOGY_HPP
#define SMF_TOPOLOGY_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "smf/ids.hpp"
#include "smf/limits.hpp"
#include "smf/status.hpp"
#include "smf/time.hpp"
#include "smf/transport.hpp"

namespace smf {

struct EndpointRegistration {
  EndpointId endpoint;
  EndpointIncarnation incarnation;
  SocketAddress service_address;
  SocketAddress data_address;
  std::string contract;
  Digest capability_digest;
  Millis registered_unix_millis = 0;
  // Dynamic property. Always false for anything loaded from durable storage.
  bool live = false;

  [[nodiscard]] Status validate() const;
};

struct LinkDescriptor {
  EndpointId from;
  EndpointId to;
  // Synthetic measurements are labelled as such so that no report can present
  // modelled numbers as observed ones.
  bool observed = false;
  std::uint32_t rtt_micros = 0;
  std::uint64_t bytes_per_second = 0;
};

// Not thread-safe by design: the coordinator owns it and decides the locking.
class TopologyView {
 public:
  TopologyView() = default;
  TopologyView(EndpointIncarnation coordinator, TopologyGeneration generation)
      : coordinator_(std::move(coordinator)), generation_(generation) {}

  [[nodiscard]] const EndpointIncarnation& coordinator() const noexcept { return coordinator_; }
  void set_coordinator(EndpointIncarnation value) noexcept { coordinator_ = std::move(value); }

  [[nodiscard]] TopologyGeneration generation() const noexcept { return generation_; }

  // Advances the topology generation, invalidating every decision that was made
  // against the previous view.
  [[nodiscard]] Result<TopologyGeneration> advance();

  [[nodiscard]] Status put(EndpointRegistration registration, std::uint32_t max_endpoints);
  [[nodiscard]] Status remove(const EndpointId& endpoint);
  [[nodiscard]] Status mark_dead(const EndpointId& endpoint);

  [[nodiscard]] Result<EndpointRegistration> find(const EndpointId& endpoint) const;
  [[nodiscard]] bool contains(const EndpointId& endpoint) const;

  [[nodiscard]] Status put_link(LinkDescriptor link, std::uint32_t max_links);
  [[nodiscard]] Result<LinkDescriptor> find_link(const EndpointId& from, const EndpointId& to) const;

  [[nodiscard]] const std::vector<EndpointRegistration>& endpoints() const noexcept {
    return endpoints_;
  }
  [[nodiscard]] const std::vector<LinkDescriptor>& links() const noexcept { return links_; }

  [[nodiscard]] std::size_t live_count() const noexcept;

  // Discards every registration and link while keeping the identity and
  // advancing the generation. Used when the coordinator restarts.
  void reset_dynamic_state();

 private:
  EndpointIncarnation coordinator_;
  TopologyGeneration generation_{1};
  std::vector<EndpointRegistration> endpoints_;
  std::vector<LinkDescriptor> links_;
  std::map<EndpointId, std::size_t> index_;
};

}  // namespace smf

#endif  // SMF_TOPOLOGY_HPP
