// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Build- and wire-level version identity for State Movement Fabric.

#ifndef SMF_VERSION_HPP
#define SMF_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace smf {

// Version of the framed wire protocol and of the durable store formats.
// Bumping any of them is a compatibility break that decoders must detect
// deterministically rather than tolerate.
inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::uint16_t kMovementStoreFormatVersion = 1;
inline constexpr std::uint16_t kCommitMarkerFormatVersion = 1;
inline constexpr std::uint16_t kObjectStoreFormatVersion = 1;

#ifndef SMF_VERSION_STRING
#define SMF_VERSION_STRING "1.0.1"
#endif
#ifndef SMF_VERSION_MAJOR
#define SMF_VERSION_MAJOR 1
#endif
#ifndef SMF_VERSION_MINOR
#define SMF_VERSION_MINOR 0
#endif
#ifndef SMF_VERSION_PATCH
#define SMF_VERSION_PATCH 1
#endif

inline constexpr std::string_view kVersionString = SMF_VERSION_STRING;
inline constexpr int kVersionMajor = SMF_VERSION_MAJOR;
inline constexpr int kVersionMinor = SMF_VERSION_MINOR;
inline constexpr int kVersionPatch = SMF_VERSION_PATCH;

}  // namespace smf

#endif  // SMF_VERSION_HPP
