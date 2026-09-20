// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// SHA-256 and HMAC-SHA-256 are the only cryptographic primitives in the
// fabric, and every authority binding depends on them. The vectors below were
// generated independently (Python hashlib) rather than copied from a
// document, so a defect in the implementation cannot hide behind a defect in
// the expectation.

#include <string>
#include <string_view>
#include <vector>

#include "smf/codec.hpp"
#include "smf/digest.hpp"
#include "smf_test.hpp"

using smf::Bytes;
using smf::ByteView;
using smf::Digest;
using smf::HmacSha256;
using smf::ReasonCode;
using smf::Sha256;

namespace {

struct HashVector {
  std::string_view label;
  std::string_view input;
  std::string_view expected;
};

struct HmacVector {
  std::string_view label;
  Bytes key;
  Bytes data;
  std::string_view expected;
};

[[nodiscard]] Bytes repeated(ByteView pattern, std::size_t count) {
  Bytes out;
  out.reserve(pattern.size() * count);
  for (std::size_t i = 0; i < count; ++i) {
    smf::append(out, pattern);
  }
  return out;
}

[[nodiscard]] Bytes range_bytes(std::uint8_t first, std::uint8_t last) {
  Bytes out;
  for (std::uint32_t value = first; value <= last; ++value) {
    out.push_back(static_cast<smf::Byte>(value));
  }
  return out;
}

}  // namespace

SMF_TEST(digest, sha256_known_vectors) {
  const std::vector<HashVector> vectors = {
      {"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"nist448", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"nist896",
       "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
       "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
  };
  for (const HashVector& vector : vectors) {
    SMF_CHECK_EQ(smf::sha256(vector.input).hex(), std::string(vector.expected));
  }
}

SMF_TEST(digest, sha256_million_a) {
  const Bytes block(64U, static_cast<smf::Byte>('a'));
  Sha256 hasher;
  for (int i = 0; i < 15625; ++i) {
    hasher.update(smf::as_bytes(block));
  }
  SMF_CHECK_EQ(hasher.finalize().hex(),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

SMF_TEST(digest, sha256_incremental_matches_oneshot) {
  SMF_PROPERTY(200) {
    const std::size_t length = ctx.rng.below(600);
    const Bytes payload = ctx.rng.bytes(length);

    const Digest one_shot = smf::sha256(smf::as_bytes(payload));

    Sha256 hasher;
    std::size_t offset = 0;
    while (offset < payload.size()) {
      const std::size_t step = 1 + ctx.rng.below(97);
      const std::size_t take = std::min(step, payload.size() - offset);
      hasher.update(ByteView(payload.data() + offset, take));
      offset += take;
    }
    SMF_CHECK_EQ(hasher.finalize(), one_shot);
  }
}

SMF_TEST(digest, sha256_hasher_is_reusable_after_finalize) {
  Sha256 hasher;
  hasher.update(std::string_view("abc"));
  const Digest first = hasher.finalize();
  hasher.update(std::string_view("abc"));
  const Digest second = hasher.finalize();
  SMF_CHECK_EQ(first, second);
}

SMF_TEST(digest, hmac_known_vectors) {
  const std::vector<HmacVector> vectors = {
      {"rfc4231_1", repeated(ByteView(reinterpret_cast<const smf::Byte*>("\x0b"), 1), 20),
       Bytes{'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'},
       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
      {"rfc4231_2", Bytes{'J', 'e', 'f', 'e'},
       Bytes{'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
             'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?'},
       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
      {"rfc4231_3", repeated(ByteView(reinterpret_cast<const smf::Byte*>("\xaa"), 1), 20),
       repeated(ByteView(reinterpret_cast<const smf::Byte*>("\xdd"), 1), 50),
       "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
      {"rfc4231_4", range_bytes(0x01, 0x19),
       repeated(ByteView(reinterpret_cast<const smf::Byte*>("\xcd"), 1), 50),
       "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
  };

  for (const HmacVector& vector : vectors) {
    const Digest digest = smf::hmac_sha256(smf::as_bytes(vector.key), smf::as_bytes(vector.data));
    SMF_CHECK_EQ(digest.hex(), std::string(vector.expected));
  }
}

SMF_TEST(digest, hmac_keys_longer_than_block) {
  const Bytes key = repeated(ByteView(reinterpret_cast<const smf::Byte*>("\xaa"), 1), 131);
  const std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
  SMF_CHECK_EQ(smf::hmac_sha256(smf::as_bytes(key), smf::as_bytes(std::string_view(data))).hex(),
               std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

  const std::string long_data =
      "This is a test using a larger than block-size key and a larger than block-size data. The "
      "key needs to be hashed before being used by the HMAC algorithm.";
  SMF_CHECK_EQ(smf::hmac_sha256(smf::as_bytes(key), smf::as_bytes(std::string_view(long_data))).hex(),
               std::string("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
}

SMF_TEST(digest, hmac_incremental_matches_oneshot) {
  SMF_PROPERTY(150) {
    const Bytes key = ctx.rng.bytes(1 + ctx.rng.below(200));
    const Bytes payload = ctx.rng.bytes(ctx.rng.below(400));

    HmacSha256 mac(smf::as_bytes(key));
    std::size_t offset = 0;
    while (offset < payload.size()) {
      const std::size_t take = std::min<std::size_t>(1 + ctx.rng.below(31), payload.size() - offset);
      mac.update(ByteView(payload.data() + offset, take));
      offset += take;
    }
    SMF_CHECK_EQ(mac.finalize(), smf::hmac_sha256(smf::as_bytes(key), smf::as_bytes(payload)));
  }
}

SMF_TEST(digest, digest_hex_roundtrip_and_rejection) {
  const Digest digest = smf::sha256(std::string_view("state movement fabric"));
  const std::string text = digest.hex();
  SMF_CHECK_EQ(text.size(), std::size_t{64});

  const auto parsed = SMF_REQUIRE_OK(Digest::from_hex(text));
  SMF_CHECK_EQ(parsed, digest);

  SMF_CHECK_CODE(Digest::from_hex(text.substr(1)), ReasonCode::INVALID_DIGEST);
  SMF_CHECK_CODE(Digest::from_hex(text + "00"), ReasonCode::INVALID_DIGEST);
  SMF_CHECK_CODE(Digest::from_hex("zz" + text.substr(2)), ReasonCode::INVALID_DIGEST);
  SMF_CHECK_CODE(Digest::from_hex(text + "\n"), ReasonCode::INVALID_DIGEST);
  SMF_CHECK_CODE(Digest::from_bytes(ByteView(reinterpret_cast<const smf::Byte*>("short"), 5)),
                 ReasonCode::INVALID_DIGEST);
}

SMF_TEST(digest, zero_digest_detection) {
  const Digest zero;
  SMF_CHECK(zero.is_zero());
  SMF_CHECK(!smf::sha256(std::string_view("")).is_zero());
}

SMF_TEST(digest, truncated_tag_verification) {
  const Digest tag = smf::sha256(std::string_view("tag"));
  SMF_CHECK(smf::verify_truncated_tag(tag, ByteView(tag.data(), 16), 16));
  SMF_CHECK(!smf::verify_truncated_tag(tag, ByteView(tag.data(), 15), 16));
  SMF_CHECK(!smf::verify_truncated_tag(tag, ByteView(tag.data(), 16), 0));
  SMF_CHECK(!smf::verify_truncated_tag(tag, ByteView(tag.data(), 33), 33));

  Bytes tampered(tag.view().begin(), tag.view().end());
  tampered[7] = static_cast<smf::Byte>(tampered[7] ^ 0x01U);
  SMF_CHECK(!smf::verify_truncated_tag(tag, ByteView(tampered.data(), 16), 16));
}

SMF_TEST(digest, canonical_digest_is_domain_separated_and_unambiguous) {
  smf::CanonicalEncoder first("SMF-TEST-A-v1");
  first.text("ab");
  first.text("c");

  smf::CanonicalEncoder second("SMF-TEST-A-v1");
  second.text("a");
  second.text("bc");

  SMF_CHECK_NE(smf::canonical_digest(first), smf::canonical_digest(second));

  smf::CanonicalEncoder other_domain("SMF-TEST-B-v1");
  other_domain.text("ab");
  other_domain.text("c");
  SMF_CHECK_NE(smf::canonical_digest(first), smf::canonical_digest(other_domain));

  smf::CanonicalEncoder same_fields("SMF-TEST-A-v1");
  same_fields.text("ab");
  same_fields.text("c");
  SMF_CHECK_EQ(smf::canonical_digest(first), smf::canonical_digest(same_fields));
}

SMF_TEST(digest, canonical_mac_depends_on_key) {
  smf::CanonicalEncoder encoder("SMF-TEST-MAC-v1");
  encoder.u64(7);
  const Digest a = smf::canonical_mac("key-a", encoder);
  const Digest b = smf::canonical_mac("key-b", encoder);
  SMF_CHECK_NE(a, b);
}
