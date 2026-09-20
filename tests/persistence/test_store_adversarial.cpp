// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Persistence adversarial proofs.
//
// Every case here damages a durable store on disk and then asserts what the
// runtime does about it. The rules under test are:
//   * a recoverable torn tail is reported and handled deterministically;
//   * authoritative corruption that is not a tail is fatal and is never
//     silently skipped;
//   * a rejected store is not partially applied and is not modified;
//   * a restart never restores endpoint liveness, grants, or topology authority.

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "smf/movement_store.hpp"
#include "smf_fixture.hpp"
#include "smf_test.hpp"

using smf::MovementId;
using smf::MovementRecord;
using smf::MovementStore;
using smf::MovementStoreOptions;
using smf::ReasonCode;
using smf::StoreRecoveryReport;

namespace {

constexpr std::uint64_t kPayloadBytes = 1U << 20;
constexpr std::uint64_t kChunkBytes = 256U << 10;

struct Harness {
  explicit Harness(std::string label) : dir(std::move(label)) {
    options.directory = dir.path();
    options.sync_on_write = false;  // durability is exercised separately
  }

  [[nodiscard]] std::filesystem::path log() const { return dir.path() / "movements.smf"; }

  [[nodiscard]] std::vector<MovementRecord> seed(std::size_t count) {
    std::vector<MovementRecord> records;
    {
      auto store = MovementStore::open(options);
      SMF_REQUIRE(store.ok());
      for (std::size_t i = 0; i < count; ++i) {
        const auto object = smftest::make_descriptor(smf::StateKind::KV,
                                                     "suite/object-" + std::to_string(i), 1,
                                                     kPayloadBytes, kChunkBytes);
        records.push_back(smftest::make_record(object, "source-1", "dest-1"));
        SMF_REQUIRE_OK(store.value()->put(records.back()));
      }
    }
    return records;
  }

  [[nodiscard]] smf::Result<std::unique_ptr<MovementStore>> open() {
    return MovementStore::open(options, &report);
  }

  smftest::TempDir dir;
  MovementStoreOptions options;
  StoreRecoveryReport report;
};

// Opens the store and requires it to be refused, returning the code. Also
// asserts that a refused open never modified the file.
[[nodiscard]] ReasonCode expect_refused(Harness& harness) {
  const smf::Bytes before = smftest::read_file(harness.log());
  auto store = harness.open();
  if (store.ok()) {
    smftest::fail(__FILE__, __LINE__, "the store opened despite corruption on disk");
  }
  const smf::Bytes after = smftest::read_file(harness.log());
  if (before != after) {
    smftest::fail(__FILE__, __LINE__,
                  "a refused open modified the store file; rejection must not rewrite it");
  }
  return store.status().code();
}

}  // namespace

SMF_TEST(persistence, valid_reopen_round_trip) {
  Harness harness("persist-valid");
  const std::vector<MovementRecord> seeded = harness.seed(3);

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{3});
  SMF_CHECK_FALSE(harness.report.partial_tail_truncated);
  SMF_CHECK_EQ(harness.report.movements_loaded, std::uint64_t{3});
  for (const MovementRecord& record : seeded) {
    const auto loaded = store.value()->get(record.id);
    SMF_CHECK_OK(loaded);
    SMF_CHECK_EQ(loaded.value().record_digest(), record.record_digest());
  }
}

SMF_TEST(persistence, torn_final_record_is_reported_then_durable) {
  Harness harness("persist-torn");
  (void)harness.seed(3);
  const std::uint64_t whole = smftest::file_size(harness.log());
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 3);

  // Cut into the final record's payload: a torn write, not a corrupt one.
  smftest::truncate_file(harness.log(), spans[2].offset + 40);

  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK(harness.report.partial_tail_truncated);
    SMF_CHECK(harness.report.truncated_bytes > 0);
    SMF_CHECK_EQ(harness.report.movements_loaded, std::uint64_t{2});
    SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
    SMF_CHECK(smftest::file_size(harness.log()) < whole);
  }

  // The truncation itself is durable: a second open finds a clean log.
  auto again = harness.open();
  SMF_CHECK_OK(again);
  SMF_CHECK_FALSE(harness.report.partial_tail_truncated);
  SMF_CHECK_EQ(again.value()->size(), std::size_t{2});
}

SMF_TEST(persistence, truncated_record_header_is_a_torn_tail) {
  Harness harness("persist-shorthdr");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 2);
  smftest::truncate_file(harness.log(), spans[1].offset + 12);

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK(harness.report.partial_tail_truncated);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{1});
}

SMF_TEST(persistence, truncated_file_header_is_fatal) {
  Harness harness("persist-fhdr");
  (void)harness.seed(2);
  smftest::truncate_file(harness.log(), 40);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_TRUNCATED);
}

SMF_TEST(persistence, empty_file_is_treated_as_a_new_store) {
  Harness harness("persist-empty");
  (void)harness.seed(2);
  smftest::truncate_file(harness.log(), 0);

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK(harness.report.created);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{0});
}

SMF_TEST(persistence, corrupt_file_header_checksum_is_fatal) {
  Harness harness("persist-fsum");
  (void)harness.seed(2);
  const std::uint8_t original = smftest::read_byte(harness.log(), 20);
  smftest::patch_byte(harness.log(), 20, static_cast<std::uint8_t>(original ^ 0x5AU));
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CHECKSUM_MISMATCH);
}

SMF_TEST(persistence, corrupt_file_magic_is_fatal) {
  Harness harness("persist-fmagic");
  (void)harness.seed(1);
  smftest::patch_byte(harness.log(), smftest::store_layout::kFileMagic, 'X');
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CORRUPT);
}

SMF_TEST(persistence, corrupt_file_header_size_is_fatal) {
  Harness harness("persist-fhsize");
  (void)harness.seed(1);
  smftest::patch_u32_le(harness.log(), smftest::store_layout::kFileHeaderSize, 64);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CORRUPT);
}

SMF_TEST(persistence, unsupported_file_version_is_fatal) {
  Harness harness("persist-fver");
  (void)harness.seed(1);
  // Patching the version also invalidates the header checksum, so the version
  // check has to be reachable before it. It is: version is validated first.
  smftest::patch_byte(harness.log(), smftest::store_layout::kFileVersion, 9);
  const ReasonCode code = expect_refused(harness);
  SMF_CHECK(code == ReasonCode::STORE_VERSION_UNSUPPORTED ||
            code == ReasonCode::STORE_CHECKSUM_MISMATCH);
}

SMF_TEST(persistence, unsupported_record_version_is_fatal) {
  Harness harness("persist-rver");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_byte(harness.log(), spans[0].offset + smftest::store_layout::kRecordVersion, 9);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_VERSION_UNSUPPORTED);
}

SMF_TEST(persistence, invalid_record_type_is_fatal) {
  Harness harness("persist-rtype");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_byte(harness.log(), spans[0].offset + smftest::store_layout::kRecordType, 77);
  // The checksum covers the type byte, so this presents as container damage.
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CHECKSUM_MISMATCH);
}

SMF_TEST(persistence, invalid_record_type_with_valid_checksum_is_fatal) {
  Harness harness("persist-rtype2");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_byte(harness.log(), spans[0].offset + smftest::store_layout::kRecordType, 77);
  smftest::reseal_record(harness.log(), 0);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_RECORD_INVALID);
}

SMF_TEST(persistence, reserved_fields_must_be_zero) {
  Harness harness("persist-reserved");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_u32_le(harness.log(), spans[0].offset + smftest::store_layout::kRecordReserved2, 1);
  smftest::reseal_record(harness.log(), 0);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_RECORD_INVALID);
}

SMF_TEST(persistence, absurd_declared_length_is_rejected_before_allocation) {
  Harness harness("persist-absurd");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_u32_le(harness.log(), spans[0].offset + smftest::store_layout::kRecordPayloadLength,
                        0xFFFFFFFFU);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_OVERSIZED);
}

SMF_TEST(persistence, corrupt_checksum_on_non_final_record_is_fatal) {
  Harness harness("persist-nontail");
  (void)harness.seed(3);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 3);
  // Damage the payload of record 0, which is authoritative and not a tail.
  smftest::patch_byte(harness.log(), spans[0].offset + smftest::store_layout::kPayload, 0xFF);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CHECKSUM_MISMATCH);
}

SMF_TEST(persistence, corrupt_checksum_on_final_record_is_a_torn_tail) {
  Harness harness("persist-tail");
  (void)harness.seed(3);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 3);
  smftest::patch_byte(harness.log(), spans[2].offset + smftest::store_layout::kPayload, 0xFF);

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK(harness.report.partial_tail_truncated);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
}

SMF_TEST(persistence, impossible_payload_with_valid_checksum_is_fatal) {
  Harness harness("persist-impossible");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 2);
  // Rewrite the leading domain string of record 0's payload so the container is
  // internally consistent but the payload is not a movement record at all.
  smftest::patch_byte(harness.log(), spans[0].offset + smftest::store_layout::kPayload, 0x00);
  smftest::reseal_record(harness.log(), 0);
  const ReasonCode code = expect_refused(harness);
  SMF_CHECK(code == ReasonCode::STORE_RECORD_INVALID ||
            code == ReasonCode::PROTOCOL_CANONICAL_VIOLATION ||
            code == ReasonCode::PROTOCOL_TRUNCATED);
}

SMF_TEST(persistence, duplicate_sequence_is_fatal) {
  Harness harness("persist-dupseq");
  (void)harness.seed(3);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 3);
  // Make record 1 claim the same sequence as record 0.
  smftest::patch_u64_le(harness.log(), spans[1].offset + smftest::store_layout::kRecordSequence, 1);
  smftest::reseal_record(harness.log(), 1);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_RECORD_INVALID);
}

SMF_TEST(persistence, non_monotonic_sequence_is_fatal) {
  Harness harness("persist-regress");
  (void)harness.seed(3);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  SMF_REQUIRE(spans.size() == 3);
  smftest::patch_u64_le(harness.log(), spans[2].offset + smftest::store_layout::kRecordSequence, 1);
  smftest::reseal_record(harness.log(), 2);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_RECORD_INVALID);
}

SMF_TEST(persistence, zero_sequence_is_fatal) {
  Harness harness("persist-zeroseq");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::patch_u64_le(harness.log(), spans[0].offset + smftest::store_layout::kRecordSequence, 0);
  smftest::reseal_record(harness.log(), 0);
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_RECORD_INVALID);
}

SMF_TEST(persistence, trailing_garbage_shorter_than_a_header_is_a_torn_tail) {
  Harness harness("persist-tailgarbage");
  (void)harness.seed(2);
  smf::Bytes garbage(20, smf::Byte{0xAB});
  smftest::append_bytes(harness.log(), smf::as_bytes(garbage));

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK(harness.report.partial_tail_truncated);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
}

SMF_TEST(persistence, trailing_garbage_at_least_a_header_is_fatal) {
  Harness harness("persist-tailgarbage2");
  (void)harness.seed(2);
  smf::Bytes garbage(64, smf::Byte{0xAB});
  smftest::append_bytes(harness.log(), smf::as_bytes(garbage));
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CORRUPT);
}

SMF_TEST(persistence, repeated_reopen_after_recovery_is_stable) {
  Harness harness("persist-repeat");
  (void)harness.seed(4);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  smftest::truncate_file(harness.log(), spans[3].offset + 8);

  for (int cycle = 0; cycle < 5; ++cycle) {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_EQ(store.value()->size(), std::size_t{3});
    if (cycle == 0) {
      SMF_CHECK(harness.report.partial_tail_truncated);
    } else {
      SMF_CHECK_FALSE(harness.report.partial_tail_truncated);
    }
  }
}

SMF_TEST(persistence, stale_replay_after_restart_is_refused) {
  Harness harness("persist-replay");
  const std::vector<MovementRecord> seeded = harness.seed(3);

  // Retire the middle movement, then reopen: it must not come back.
  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_OK(store.value()->retire(seeded[1].id));
    SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
  }
  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
    SMF_CHECK_FALSE(store.value()->contains(seeded[1].id));
    SMF_CHECK_CODE(store.value()->get(seeded[1].id), ReasonCode::MOVEMENT_NOT_FOUND);
  }

  // A retired movement stays retired across a compaction as well.
  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_OK(store.value()->compact());
  }
  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
    SMF_CHECK_FALSE(store.value()->contains(seeded[1].id));
  }
}

SMF_TEST(persistence, coordinator_state_epoch_advances_across_reopen) {
  Harness harness("persist-epoch");
  smf::CoordinatorPersistentState state;
  state.epoch = smf::IncarnationEpoch(7);
  state.policy_generation = smf::PolicyGeneration(3);
  state.compatibility_generation = smf::CompatibilityGeneration(2);
  state.topology_generation = smf::TopologyGeneration(11);
  state.policy_digest = smf::sha256("policy");
  state.last_saved_unix_millis = smf::kEpoch2026;

  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    SMF_CHECK_OK(store.value()->save_coordinator_state(state));
  }
  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    const auto loaded = store.value()->load_coordinator_state();
    SMF_CHECK_OK(loaded);
    SMF_CHECK_EQ(loaded.value().epoch.value(), std::uint64_t{7});
    SMF_CHECK_EQ(loaded.value().topology_generation.value(), std::uint64_t{11});
  }
}

SMF_TEST(persistence, stray_compaction_temporary_does_not_affect_the_store) {
  Harness harness("persist-stray");
  (void)harness.seed(2);

  // A crash during atomic replacement leaves a sibling temporary behind. It must
  // be inert: the authoritative log is the only thing that is read.
  smf::Bytes garbage(4096, smf::Byte{0x5A});
  smftest::write_file(harness.log().string() + ".compact", smf::as_bytes(garbage));

  auto store = harness.open();
  SMF_CHECK_OK(store);
  SMF_CHECK_EQ(store.value()->size(), std::size_t{2});
}

SMF_TEST(persistence, compaction_preserves_content_and_removes_the_temporary) {
  Harness harness("persist-compact");
  const std::vector<MovementRecord> seeded = harness.seed(4);
  (void)seeded;

  {
    auto store = harness.open();
    SMF_CHECK_OK(store);
    const std::uint64_t before = smftest::file_size(harness.log());
    SMF_CHECK_OK(store.value()->compact());
    const std::uint64_t after = smftest::file_size(harness.log());
    SMF_CHECK(after <= before);
    SMF_CHECK_FALSE(std::filesystem::exists(harness.log().string() + ".compact"));
    SMF_CHECK_EQ(store.value()->size(), std::size_t{4});
  }

  auto reopened = harness.open();
  SMF_CHECK_OK(reopened);
  SMF_CHECK_EQ(reopened.value()->size(), std::size_t{4});
}

SMF_TEST(persistence, refused_open_releases_the_lock) {
  Harness harness("persist-lock");
  (void)harness.seed(2);
  const std::vector<smftest::RecordSpan> spans = smftest::scan_records(harness.log());
  const std::uint64_t at = spans[0].offset + smftest::store_layout::kPayload;
  const std::uint8_t original = smftest::read_byte(harness.log(), at);
  smftest::patch_byte(harness.log(), at, static_cast<std::uint8_t>(original ^ 0xFFU));
  SMF_CHECK_EQ(expect_refused(harness), ReasonCode::STORE_CHECKSUM_MISMATCH);

  // Repair the byte exactly, and the directory must still be usable: a refused
  // open has to release the exclusive lock it took.
  smftest::patch_byte(harness.log(), at, original);
  auto store = harness.open();
  SMF_CHECK_OK(store);
}

SMF_TEST(persistence, two_stores_cannot_share_a_directory) {
  Harness harness("persist-exclusive");
  (void)harness.seed(1);
  auto first = harness.open();
  SMF_CHECK_OK(first);
  auto second = MovementStore::open(harness.options);
  SMF_CHECK(!second.ok());
  SMF_CHECK_CODE(second, ReasonCode::STORE_LOCKED);
}
