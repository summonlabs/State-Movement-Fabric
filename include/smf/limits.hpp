// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Structural bounds. These are the hard ceilings that decoders enforce before
// any externally supplied count or length can reach a loop or an allocation.
// Operational limits that an operator may tune live in MovementPolicy.

#ifndef SMF_LIMITS_HPP
#define SMF_LIMITS_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace smf {

inline constexpr std::size_t kMaxObjectNameBytes = 4096;
inline constexpr std::size_t kMaxEndpointIdBytes = 63;
inline constexpr std::size_t kMaxTextBytes = 4096;
inline constexpr std::size_t kMaxDetailBytes = 1024;
inline constexpr std::size_t kMaxEvidenceAttributes = 64;
inline constexpr std::size_t kMaxCapabilities = 64;

inline constexpr std::uint32_t kMaxEndpoints = 4096;
inline constexpr std::uint32_t kMaxLinks = 16384;
inline constexpr std::uint32_t kMaxProvenanceEvents = 256;
inline constexpr std::uint32_t kMaxChunksPerObject = 1U << 24;  // 16 777 216 chunks
inline constexpr std::uint32_t kMaxAttemptsHardLimit = 64;

inline constexpr std::uint64_t kMinChunkBytes = 1024;
inline constexpr std::uint64_t kMaxChunkBytes = 64ULL << 20;   // 64 MiB
inline constexpr std::uint64_t kMaxObjectBytes = 1ULL << 40;   // 1 TiB
inline constexpr std::uint64_t kMaxFramePayloadBytes = 1ULL << 20;  // 1 MiB

// Version of the peer contract. A peer that reports a different contract is
// rejected rather than negotiated down.
inline constexpr std::string_view kPeerContract = "smf.peer.v1";

}  // namespace smf

#endif  // SMF_LIMITS_HPP
