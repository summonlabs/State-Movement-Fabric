// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf/topology.hpp"

#include <algorithm>

namespace smf {

Status EndpointRegistration::validate() const {
  if (endpoint.empty()) {
    return Status(ReasonCode::INVALID_ID, "endpoint registration requires an endpoint id");
  }
  if (!incarnation.is_set()) {
    return Status(ReasonCode::STALE_INCARNATION,
                  "endpoint registration requires a complete incarnation");
  }
  if (incarnation.endpoint() != endpoint) {
    return Status(ReasonCode::STALE_INCARNATION,
                  "endpoint registration incarnation names a different endpoint");
  }
  if (service_address.port == 0) {
    return Status(ReasonCode::INVALID_ADDRESS, "endpoint registration requires a service port");
  }
  if (data_address.port == 0) {
    return Status(ReasonCode::INVALID_ADDRESS, "endpoint registration requires a data port");
  }
  if (contract.empty() || contract.size() > kMaxTextBytes) {
    return Status(ReasonCode::ENDPOINT_CONTRACT_MISMATCH,
                  "endpoint registration requires a bounded contract string");
  }
  if (capability_digest.is_zero()) {
    return Status(ReasonCode::INVALID_DIGEST,
                  "endpoint registration requires a capability digest");
  }
  return Status::success();
}

Result<TopologyGeneration> TopologyView::advance() {
  const auto next = generation_.next();
  if (!next.ok()) return next.status();
  generation_ = next.value();
  return generation_;
}

Status TopologyView::put(EndpointRegistration registration, std::uint32_t max_endpoints) {
  const Status valid = registration.validate();
  if (!valid.ok()) return valid;

  const auto existing = index_.find(registration.endpoint);
  if (existing != index_.end()) {
    EndpointRegistration& slot = endpoints_[existing->second];
    // A registration with an older incarnation must never displace a newer one.
    if (slot.incarnation.epoch() > registration.incarnation.epoch()) {
      return Status(ReasonCode::STALE_EPOCH,
                    "registration carries an epoch older than the one already recorded");
    }
    slot = std::move(registration);
    return Status::success();
  }

  if (endpoints_.size() >= max_endpoints) {
    return Status(ReasonCode::RESOURCE_EXHAUSTED, "topology endpoint bound reached");
  }
  index_.emplace(registration.endpoint, endpoints_.size());
  endpoints_.push_back(std::move(registration));
  return Status::success();
}

Status TopologyView::remove(const EndpointId& endpoint) {
  const auto existing = index_.find(endpoint);
  if (existing == index_.end()) {
    return Status(ReasonCode::ENDPOINT_NOT_FOUND, "endpoint is not registered");
  }
  const std::size_t position = existing->second;
  endpoints_.erase(endpoints_.begin() + static_cast<std::ptrdiff_t>(position));
  index_.erase(existing);
  for (auto& entry : index_) {
    if (entry.second > position) --entry.second;
  }
  links_.erase(std::remove_if(links_.begin(), links_.end(),
                              [&endpoint](const LinkDescriptor& link) {
                                return link.from == endpoint || link.to == endpoint;
                              }),
               links_.end());
  return Status::success();
}

Status TopologyView::mark_dead(const EndpointId& endpoint) {
  const auto existing = index_.find(endpoint);
  if (existing == index_.end()) {
    return Status(ReasonCode::ENDPOINT_NOT_FOUND, "endpoint is not registered");
  }
  endpoints_[existing->second].live = false;
  const auto advanced = advance();
  if (!advanced.ok()) return advanced.status();
  return Status::success();
}

Result<EndpointRegistration> TopologyView::find(const EndpointId& endpoint) const {
  const auto existing = index_.find(endpoint);
  if (existing == index_.end()) {
    return Status(ReasonCode::ENDPOINT_NOT_FOUND, "endpoint is not registered");
  }
  return endpoints_[existing->second];
}

bool TopologyView::contains(const EndpointId& endpoint) const {
  return index_.find(endpoint) != index_.end();
}

Status TopologyView::put_link(LinkDescriptor link, std::uint32_t max_links) {
  if (link.from == link.to) {
    return Status(ReasonCode::INVALID_ARGUMENT, "a link must connect two distinct endpoints");
  }
  const auto found = std::find_if(links_.begin(), links_.end(), [&link](const LinkDescriptor& item) {
    return item.from == link.from && item.to == link.to;
  });
  if (found != links_.end()) {
    *found = std::move(link);
    return Status::success();
  }
  if (links_.size() >= max_links) {
    return Status(ReasonCode::RESOURCE_EXHAUSTED, "topology link bound reached");
  }
  links_.push_back(std::move(link));
  return Status::success();
}

Result<LinkDescriptor> TopologyView::find_link(const EndpointId& from, const EndpointId& to) const {
  const auto found = std::find_if(links_.begin(), links_.end(), [&from, &to](const LinkDescriptor& item) {
    return item.from == from && item.to == to;
  });
  if (found == links_.end()) {
    return Status(ReasonCode::NOT_FOUND, "no link descriptor is recorded for that pair");
  }
  return *found;
}

std::size_t TopologyView::live_count() const noexcept {
  std::size_t count = 0;
  for (const EndpointRegistration& registration : endpoints_) {
    if (registration.live) ++count;
  }
  return count;
}

void TopologyView::reset_dynamic_state() {
  endpoints_.clear();
  links_.clear();
  index_.clear();
  const auto advanced = advance();
  (void)advanced;
}

}  // namespace smf
