// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The canonical codec is the only decoder the fabric trusts. These proofs
// exercise it the way an adversary would: truncated fields, absurd declared
// lengths, non-canonical booleans, invalid UTF-8, and trailing bytes.

#include <string>
#include <string_view>

#include "smf/codec.hpp"
#include "smf_test.hpp"

using smf::ByteView;
using smf::Bytes;
using smf::CanonicalDecoder;
using smf::CanonicalEncoder;
using smf::DecodeLimits;
using smf::ReasonCode;

namespace {

[[nodiscard]] Bytes encode_sample() {
  CanonicalEncoder encoder("SMF-TEST-CODEC-v1");
  encoder.u8(0x7FU);
  encoder.boolean(true);
  encoder.boolean(false);
  encoder.u16(0xBEEFU);
  encoder.u32(0xDEADBEEFU);
  encoder.u64(0x0123456789ABCDEFULL);
  encoder.i64(-42);
  encoder.blob(ByteView(reinterpret_cast<const smf::Byte*>("\x00\x01\x02"), 3));
  encoder.text("movement");
  encoder.digest(smf::sha256(std::string_view("payload")));
  return encoder.bytes();
}

}  // namespace

SMF_TEST(codec, roundtrip_all_fields) {
  const Bytes buffer = encode_sample();
  CanonicalDecoder decoder(smf::as_bytes(buffer));

  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.text(64)), std::string_view("SMF-TEST-CODEC-v1"));
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.u8()), std::uint8_t{0x7FU});
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.boolean()), true);
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.boolean()), false);
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.u16()), std::uint16_t{0xBEEFU});
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.u32()), std::uint32_t{0xDEADBEEFU});
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.u64()), std::uint64_t{0x0123456789ABCDEFULL});
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.i64()), std::int64_t{-42});

  const ByteView blob = SMF_REQUIRE_OK(decoder.blob(16));
  SMF_CHECK_EQ(blob.size(), std::size_t{3});
  SMF_CHECK_EQ(blob[2], smf::Byte{0x02});

  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.text(64)), std::string_view("movement"));
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.digest()), smf::sha256(std::string_view("payload")));
  SMF_CHECK_OK(decoder.require_end());
}

SMF_TEST(codec, encoding_is_deterministic) {
  SMF_CHECK_EQ(encode_sample(), encode_sample());
}

SMF_TEST(codec, rejects_non_canonical_boolean) {
  CanonicalEncoder encoder;
  encoder.u8(0x02);
  CanonicalDecoder decoder(encoder.view());
  SMF_CHECK_CODE(decoder.boolean(), ReasonCode::PROTOCOL_CANONICAL_VIOLATION);
}

SMF_TEST(codec, rejects_truncated_fields) {
  const Bytes buffer = encode_sample();

  for (std::size_t cut = 1; cut < buffer.size(); ++cut) {
    CanonicalDecoder decoder(ByteView(buffer.data(), cut));
    bool failed = false;
    for (int i = 0; i < 16 && !failed; ++i) {
      const auto raw = decoder.u64();
      if (!raw.ok()) {
        failed = true;
        break;
      }
    }
    if (!failed) {
      failed = !decoder.require_end().ok();
    }
    if (!failed) {
      smftest::fail(__FILE__, __LINE__,
                    "a truncated buffer of length " + std::to_string(cut) + " decoded successfully");
    }
  }
}

SMF_TEST(codec, rejects_absurd_declared_lengths) {
  CanonicalEncoder encoder;
  encoder.u64(0xFFFFFFFFFFFFFFFFULL);
  CanonicalDecoder decoder(encoder.view());
  SMF_CHECK_CODE(decoder.blob(64), ReasonCode::PROTOCOL_BOUNDS_EXCEEDED);

  // A declared length that is within the caller's bound but longer than the
  // remaining input is a truncation, not a bound violation.
  CanonicalEncoder declared_too_long;
  declared_too_long.u64(2000);
  declared_too_long.text("short");
  CanonicalDecoder second(declared_too_long.view());
  SMF_CHECK_CODE(second.blob(4096), ReasonCode::PROTOCOL_TRUNCATED);
}

SMF_TEST(codec, rejects_invalid_utf8_text) {
  const smf::Byte invalid[] = {0xC0U, 0xAFU, 0x00U};
  CanonicalEncoder encoder;
  encoder.blob(ByteView(invalid, 3));
  CanonicalDecoder decoder(encoder.view());
  SMF_CHECK_CODE(decoder.text(64), ReasonCode::INVALID_UTF8);

  const smf::Byte surrogate[] = {0xEDU, 0xA0U, 0x80U};
  CanonicalEncoder second;
  second.blob(ByteView(surrogate, 3));
  CanonicalDecoder second_decoder(second.view());
  SMF_CHECK_CODE(second_decoder.text(64), ReasonCode::INVALID_UTF8);
}

SMF_TEST(codec, detects_trailing_garbage) {
  CanonicalEncoder encoder;
  encoder.u32(1);
  Bytes buffer = encoder.bytes();
  buffer.push_back(0x00U);
  CanonicalDecoder decoder(smf::as_bytes(buffer));
  SMF_CHECK_EQ(SMF_REQUIRE_OK(decoder.u32()), std::uint32_t{1});
  SMF_CHECK_CODE(decoder.require_end(), ReasonCode::PROTOCOL_TRAILING_GARBAGE);
}

SMF_TEST(codec, enforces_input_limit) {
  DecodeLimits limits;
  limits.max_input_bytes = 8;
  const Bytes buffer(64, smf::Byte{0});
  CanonicalDecoder decoder(smf::as_bytes(buffer), limits);
  SMF_CHECK_CODE(decoder.u8(), ReasonCode::PROTOCOL_BOUNDS_EXCEEDED);
}

SMF_TEST(codec, enforces_collection_count_bound) {
  CanonicalEncoder encoder;
  encoder.u32(1'000'000U);
  CanonicalDecoder decoder(encoder.view());
  SMF_CHECK_CODE(decoder.count(1024), ReasonCode::PROTOCOL_BOUNDS_EXCEEDED);

  CanonicalEncoder ok_encoder;
  ok_encoder.u32(16);
  CanonicalDecoder ok_decoder(ok_encoder.view());
  SMF_CHECK_EQ(SMF_REQUIRE_OK(ok_decoder.count(1024)), std::size_t{16});
}

SMF_TEST(codec, integers_are_little_endian_fixed_width) {
  CanonicalEncoder encoder;
  encoder.u32(0x01020304U);
  const Bytes& buffer = encoder.bytes();
  SMF_REQUIRE(buffer.size() == 4);
  SMF_CHECK_EQ(buffer[0], smf::Byte{0x04});
  SMF_CHECK_EQ(buffer[1], smf::Byte{0x03});
  SMF_CHECK_EQ(buffer[2], smf::Byte{0x02});
  SMF_CHECK_EQ(buffer[3], smf::Byte{0x01});
}

SMF_TEST(codec, decoder_survives_random_mutations_without_crashing) {
  const Bytes canonical = encode_sample();
  SMF_PROPERTY(600) {
    Bytes mutated = canonical;
    const std::size_t mutations = 1 + ctx.rng.below(4);
    for (std::size_t i = 0; i < mutations; ++i) {
      const std::size_t index = ctx.rng.below(mutated.size());
      mutated[index] = static_cast<smf::Byte>(ctx.rng.next_u32() & 0xFFU);
    }
    CanonicalDecoder decoder(smf::as_bytes(mutated));
    for (int field = 0; field < 24; ++field) {
      const auto raw = decoder.u64();
      if (!raw.ok()) break;
    }
    (void)decoder.require_end();
  }
}

SMF_TEST(codec, decoder_survives_random_truncation) {
  const Bytes canonical = encode_sample();
  SMF_PROPERTY(400) {
    const std::size_t length = ctx.rng.below(canonical.size() + 1);
    CanonicalDecoder decoder(ByteView(canonical.data(), length));
    for (int field = 0; field < 24; ++field) {
      const auto raw = decoder.blob(4096);
      if (!raw.ok()) break;
    }
    (void)decoder.require_end();
  }
}
