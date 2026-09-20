// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "smf/ids.hpp"
#include "smf_test.hpp"

using smf::BootId;
using smf::Bytes;
using smf::DeterministicEntropySource;
using smf::EndpointId;
using smf::IdIssuer;
using smf::IncarnationEpoch;
using smf::MovementId;
using smf::ReasonCode;
using smf::StateGeneration;
using smf::StateKind;
using smf::StateObjectId;

SMF_TEST(ids, endpoint_id_accepts_documented_forms) {
  for (const char* candidate : {"a", "source-1", "dest.node_2", "A1", "x.y.z",
                                "012345678901234567890123456789012345678901234567890123456789012"}) {
    const auto parsed = EndpointId::parse(candidate);
    if (!parsed.ok()) {
      smftest::fail(__FILE__, __LINE__, std::string("expected to accept endpoint id ") + candidate +
                                          " but got " + parsed.status().to_string());
    }
    SMF_CHECK_EQ(parsed.value().value(), std::string(candidate));
  }
}

SMF_TEST(ids, endpoint_id_rejects_malformed_forms) {
  const std::vector<std::string> rejected = {
      "", "-leading-dash", ".leading-dot", "has space", "has/slash", "has:colon", "has\nnewline",
      "unicode-\xC3\xA9", std::string(64, 'a')};
  for (const std::string& candidate : rejected) {
    SMF_CHECK_CODE(EndpointId::parse(candidate), ReasonCode::INVALID_ID);
    SMF_CHECK(!EndpointId::is_valid(candidate));
  }
}

SMF_TEST(ids, generation_zero_is_never_valid) {
  SMF_CHECK(!StateGeneration().is_set());
  SMF_CHECK_CODE(StateGeneration::from_value(0), ReasonCode::INVALID_GENERATION);

  const auto one = SMF_REQUIRE_OK(StateGeneration::from_value(1));
  SMF_CHECK(one.is_set());
  const auto two = SMF_REQUIRE_OK(one.next());
  SMF_CHECK_EQ(two.value(), std::uint64_t{2});
  SMF_CHECK(two > one);

  const StateGeneration maximal(UINT64_MAX);
  SMF_CHECK_CODE(maximal.next(), ReasonCode::SIZE_OVERFLOW);
}

SMF_TEST(ids, fixed_id_hex_roundtrip) {
  DeterministicEntropySource entropy(1234);
  IdIssuer issuer(entropy);
  const MovementId id = issuer.new_movement_id();
  SMF_CHECK(!id.is_zero());

  const std::string text = id.hex();
  SMF_CHECK_EQ(text.size(), std::size_t{32});
  const auto parsed = SMF_REQUIRE_OK(MovementId::from_hex(text));
  SMF_CHECK_EQ(parsed, id);

  SMF_CHECK_CODE(MovementId::from_hex(text.substr(2)), ReasonCode::INVALID_ID);
  SMF_CHECK_CODE(MovementId::from_hex("zzzz"), ReasonCode::INVALID_ID);
  SMF_CHECK_CODE(MovementId::from_hex(""), ReasonCode::INVALID_ID);
}

SMF_TEST(ids, identifiers_are_distinct_across_draws) {
  DeterministicEntropySource entropy(99);
  IdIssuer issuer(entropy);
  std::set<std::string> seen;
  constexpr int kDraws = 20000;
  for (int i = 0; i < kDraws; ++i) {
    seen.insert(issuer.new_movement_id().hex());
    seen.insert(issuer.new_attempt_id().hex());
    seen.insert(issuer.new_boot_id().hex());
  }
  SMF_CHECK_EQ(seen.size(), static_cast<std::size_t>(kDraws) * 3U);
}

SMF_TEST(ids, deterministic_entropy_is_reproducible) {
  DeterministicEntropySource first(7);
  DeterministicEntropySource second(7);
  IdIssuer first_issuer(first);
  IdIssuer second_issuer(second);
  for (int i = 0; i < 32; ++i) {
    SMF_CHECK_EQ(first_issuer.new_movement_id(), second_issuer.new_movement_id());
  }
}

SMF_TEST(ids, state_object_identity_is_stable_and_discriminating) {
  const auto model_a = SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::MODEL, "llama/layer0"));
  const auto model_a_again =
      SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::MODEL, "llama/layer0"));
  const auto kv_a = SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::KV, "llama/layer0"));
  const auto model_b = SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::MODEL, "llama/layer1"));
  const auto unknown_kind =
      SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::UNKNOWN, "llama/layer0"));

  SMF_CHECK_EQ(model_a, model_a_again);
  SMF_CHECK_NE(model_a, kv_a);
  SMF_CHECK_NE(model_a, model_b);
  SMF_CHECK_NE(model_a, unknown_kind);
  SMF_CHECK(!model_a.is_zero());

  SMF_CHECK_CODE(smf::derive_state_object_id(StateKind::MODEL, ""), ReasonCode::INVALID_ARGUMENT);
  const std::string invalid_utf8 = "\xC3\x28";
  SMF_CHECK_CODE(smf::derive_state_object_id(StateKind::MODEL, invalid_utf8),
                 ReasonCode::INVALID_UTF8);
}

SMF_TEST(ids, chunk_digest_binds_position_and_payload) {
  const auto object_id = SMF_REQUIRE_OK(smf::derive_state_object_id(StateKind::KV, "cache/0"));
  const StateGeneration generation = SMF_REQUIRE_OK(StateGeneration::from_value(3));
  const Bytes payload{'a', 'b', 'c', 'd'};

  const auto base = smf::compute_chunk_digest(object_id, generation, 0, 0, 4, smf::as_bytes(payload));

  SMF_CHECK_EQ(base,
               smf::compute_chunk_digest(object_id, generation, 0, 0, 4, smf::as_bytes(payload)));
  SMF_CHECK_NE(base, smf::compute_chunk_digest(object_id, generation, 1, 4, 4, smf::as_bytes(payload)));
  SMF_CHECK_NE(base, smf::compute_chunk_digest(object_id, generation, 0, 4, 4, smf::as_bytes(payload)));
  SMF_CHECK_NE(base, smf::compute_chunk_digest(object_id, generation, 0, 0, 3, smf::as_bytes(payload)));
  SMF_CHECK_NE(base, smf::compute_chunk_digest(object_id, StateGeneration(4), 0, 0, 4,
                                               smf::as_bytes(payload)));

  const Bytes other_payload{'a', 'b', 'c', 'e'};
  SMF_CHECK_NE(base, smf::compute_chunk_digest(object_id, generation, 0, 0, 4,
                                               smf::as_bytes(other_payload)));
}

SMF_TEST(ids, incarnation_requires_complete_binding) {
  DeterministicEntropySource entropy(3);
  IdIssuer issuer(entropy);
  const EndpointId endpoint = SMF_REQUIRE_OK(EndpointId::parse("source-1"));
  const BootId boot = issuer.new_boot_id();

  const auto valid = smf::SourceIncarnation::make(endpoint, boot, IncarnationEpoch(1));
  SMF_CHECK_OK(valid);
  SMF_CHECK(valid.value().is_set());

  SMF_CHECK_CODE(smf::SourceIncarnation::make(endpoint, boot, IncarnationEpoch(0)),
                 ReasonCode::INVALID_GENERATION);
  SMF_CHECK_CODE(smf::SourceIncarnation::make(EndpointId(), boot, IncarnationEpoch(1)),
                 ReasonCode::INVALID_ID);
  SMF_CHECK_CODE(smf::SourceIncarnation::make(endpoint, BootId(), IncarnationEpoch(1)),
                 ReasonCode::INVALID_ID);

  const auto restarted = smf::SourceIncarnation::make(endpoint, issuer.new_boot_id(), IncarnationEpoch(2));
  SMF_CHECK_OK(restarted);
  SMF_CHECK(restarted.value() != valid.value());
}

SMF_TEST(ids, state_kind_names_roundtrip) {
  const StateKind kinds[] = {StateKind::UNKNOWN,      StateKind::MODEL,     StateKind::ADAPTER,
                             StateKind::TENSOR,       StateKind::KV,        StateKind::PREFIX,
                             StateKind::CHECKPOINT,   StateKind::ARTIFACT,  StateKind::GENERIC_BLOB};
  for (const StateKind kind : kinds) {
    StateKind parsed = StateKind::UNKNOWN;
    SMF_CHECK(smf::state_kind_from_string(smf::to_string(kind), parsed));
    SMF_CHECK_EQ(parsed, kind);
  }
  StateKind unused = StateKind::MODEL;
  SMF_CHECK(!smf::state_kind_from_string("model", unused));
  SMF_CHECK(!smf::state_kind_from_string("", unused));
  SMF_CHECK(!smf::is_known_state_kind(StateKind::UNKNOWN));
}

SMF_TEST(ids, utf8_validation_is_strict) {
  struct Case {
    std::string bytes;
    bool valid;
  };
  const std::vector<Case> cases = {
      {"", true},
      {"plain ascii", true},
      {"\xC3\xA9", true},
      {"\xE2\x82\xAC", true},
      {"\xF0\x9F\x9A\x80", true},
      {"\x80", false},
      {"\xC3", false},
      {"\xC0\xAF", false},
      {"\xE0\x80\xAF", false},
      {"\xED\xA0\x80", false},
      {"\xF4\x90\x80\x80", false},
      {"\xF8\x88\x80\x80\x80", false},
      {"valid\xC3", false},
  };
  for (const Case& item : cases) {
    SMF_CHECK_EQ(smf::is_valid_utf8(smf::as_bytes(item.bytes)), item.valid);
  }
}
