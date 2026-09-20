// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal in-tree proof harness. It exists instead of a third-party framework
// so that the repository keeps a zero-dependency build, so that no test can be
// given a watchdog timeout, and so that seeded property failures always report
// their reproduction seed.

#ifndef SMF_TEST_HPP
#define SMF_TEST_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "smf/bytes.hpp"
#include "smf/digest.hpp"
#include "smf/ids.hpp"
#include "smf/status.hpp"

namespace smftest {

struct TestCase {
  const char* suite;
  const char* name;
  void (*fn)();
};

[[nodiscard]] std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* suite, const char* name, void (*fn)());
};

[[noreturn]] void fail(const char* file, int line, const std::string& message);

int run_all(int argc, char** argv);

// ---------------------------------------------------------------------------
// Value rendering for assertion messages
// ---------------------------------------------------------------------------

// Explicit overloads are declared before the generic template so that every
// fabric value type can appear in an assertion message.
[[nodiscard]] inline std::string display(const smf::Digest& value) { return value.hex(); }

[[nodiscard]] inline std::string display(const smf::EndpointId& value) { return value.value(); }

[[nodiscard]] inline std::string display(const smf::Status& value) { return value.to_string(); }

template <class Tag, std::size_t N>
[[nodiscard]] std::string display(const smf::FixedId<Tag, N>& value) {
  return value.hex();
}

template <class Tag>
[[nodiscard]] std::string display(const smf::Generation<Tag>& value) {
  return std::to_string(value.value());
}

template <class T>
[[nodiscard]] std::string display(const T& value) {
  std::ostringstream os;
  if constexpr (std::is_same_v<T, std::string_view>) {
    os << std::string(value);
  } else if constexpr (std::is_same_v<T, smf::ByteView>) {
    os << smf::to_hex(value);
  } else if constexpr (std::is_same_v<T, smf::Bytes>) {
    os << smf::to_hex(smf::as_bytes(value));
  } else if constexpr (std::is_enum_v<T>) {
    os << static_cast<long long>(value);
  } else if constexpr (std::is_same_v<T, bool>) {
    os << (value ? "true" : "false");
  } else if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
    os << value;
  } else {
    os << "<unprintable>";
  }
  return os.str();
}

template <class A, class B>
void expect_eq(const char* file, int line, const char* text_a, const char* text_b, const A& a,
               const B& b) {
  if (!(a == b)) {
    fail(file, line, std::string("expected ") + text_a + " == " + text_b + ", got " + display(a) +
                        " vs " + display(b));
  }
}

template <class A, class B>
void expect_ne(const char* file, int line, const char* text_a, const char* text_b, const A& a,
               const B& b) {
  if (a == b) {
    fail(file, line,
         std::string("expected ") + text_a + " != " + text_b + ", both are " + display(a));
  }
}

template <class A, class B>
void expect_lt(const char* file, int line, const char* text_a, const char* text_b, const A& a,
               const B& b) {
  if (!(a < b)) {
    fail(file, line, std::string("expected ") + text_a + " < " + text_b + ", got " + display(a) +
                        " vs " + display(b));
  }
}

template <class T>
void expect_true(const char* file, int line, const char* text, const T& value) {
  if (!static_cast<bool>(value)) {
    fail(file, line, std::string("expected true: ") + text);
  }
}

template <class T>
void expect_false(const char* file, int line, const char* text, const T& value) {
  if (static_cast<bool>(value)) {
    fail(file, line, std::string("expected false: ") + text);
  }
}

// Works for both smf::Status and smf::Result<T>.
template <class T>
void expect_ok(const char* file, int line, const char* text, const T& value) {
  if (value.ok()) return;
  if constexpr (std::is_same_v<T, smf::Status>) {
    fail(file, line, std::string("expected success from ") + text + ", got " + value.to_string());
  } else {
    fail(file, line,
         std::string("expected success from ") + text + ", got " + value.status().to_string());
  }
}

template <class T>
[[nodiscard]] auto require_ok(const char* file, int line, const char* text, T&& value) {
  if (!value.ok()) {
    if constexpr (std::is_same_v<std::remove_cvref_t<T>, smf::Status>) {
      fail(file, line, std::string("required success from ") + text + ", got " + value.to_string());
    } else {
      fail(file, line,
           std::string("required success from ") + text + ", got " + value.status().to_string());
    }
  }
  if constexpr (std::is_same_v<std::remove_cvref_t<T>, smf::Status>) {
    return;
  } else {
    return std::forward<T>(value).value();
  }
}

template <class T>
void expect_code(const char* file, int line, const char* text, const T& value, smf::ReasonCode code) {
  const smf::Status status = [&]() {
    if constexpr (std::is_same_v<T, smf::Status>) {
      return value;
    } else {
      return value.status();
    }
  }();
  if (status.code() != code) {
    fail(file, line, std::string("expected ") + text + " to fail with " + smf::to_string(code) +
                        ", got " + status.to_string());
  }
}

// ---------------------------------------------------------------------------
// Seeded random source and property loops
// ---------------------------------------------------------------------------

class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept : state_(seed) {}

  [[nodiscard]] std::uint64_t next_u64() noexcept;
  [[nodiscard]] std::uint32_t next_u32() noexcept;
  [[nodiscard]] std::size_t below(std::size_t bound) noexcept;
  [[nodiscard]] bool chance(unsigned percent) noexcept;
  [[nodiscard]] smf::Bytes bytes(std::size_t count);
  [[nodiscard]] std::string ascii(std::size_t count);

  template <class T>
  [[nodiscard]] const T& pick(const std::vector<T>& values) noexcept {
    return values[below(values.size())];
  }

 private:
  std::uint64_t state_;
};

class PropertyContext {
 public:
  PropertyContext(std::uint64_t seed_value, std::uint64_t iteration_value, Rng& source) noexcept
      : seed(seed_value), iteration(iteration_value), rng(source) {}

  std::uint64_t seed;
  std::uint64_t iteration;
  Rng& rng;

  [[nodiscard]] bool once() const noexcept { return alive_; }
  void stop() noexcept { alive_ = false; }

 private:
  bool alive_ = true;
};

class PropertyLoop {
 public:
  PropertyLoop(const char* file, int line, std::uint64_t iterations);
  ~PropertyLoop();
  PropertyLoop(const PropertyLoop&) = delete;
  PropertyLoop& operator=(const PropertyLoop&) = delete;

  [[nodiscard]] bool next();
  [[nodiscard]] PropertyContext& context() noexcept { return *context_; }

 private:
  const char* file_;
  int line_;
  std::uint64_t iterations_;
  std::uint64_t iteration_ = 0;
  std::uint64_t seed_;
  Rng rng_;
  std::optional<PropertyContext> context_;
  const PropertyLoop* previous_ = nullptr;
  const PropertyContext* previous_context_ = nullptr;
};

[[nodiscard]] std::uint64_t base_seed() noexcept;
void set_base_seed(std::uint64_t seed) noexcept;

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

class TempDir {
 public:
  explicit TempDir(std::string_view label);
  ~TempDir();
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  TempDir(TempDir&&) = delete;
  TempDir& operator=(TempDir&&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
  [[nodiscard]] std::filesystem::path file(std::string_view relative) const;
  [[nodiscard]] std::filesystem::path directory(std::string_view relative) const;
  void reset();

 private:
  std::filesystem::path path_;
};

}  // namespace smftest

#define SMF_TEST(suite, name)                                                              \
  static void smf_test_body_##suite##_##name();                                            \
  static const ::smftest::Registrar smf_test_registrar_##suite##_##name(#suite, #name,      \
                                                                      &smf_test_body_##suite##_##name); \
  static void smf_test_body_##suite##_##name()

#define SMF_CHECK(condition) \
  ::smftest::expect_true(__FILE__, __LINE__, #condition, static_cast<bool>(condition))

#define SMF_REQUIRE(condition)                                                       \
  do {                                                                                \
    if (!static_cast<bool>(condition)) {                                              \
      ::smftest::fail(__FILE__, __LINE__, std::string("required: ") + #condition);    \
    }                                                                                 \
  } while (false)

#define SMF_CHECK_EQ(a, b) ::smftest::expect_eq(__FILE__, __LINE__, #a, #b, (a), (b))
#define SMF_CHECK_NE(a, b) ::smftest::expect_ne(__FILE__, __LINE__, #a, #b, (a), (b))
#define SMF_CHECK_LT(a, b) ::smftest::expect_lt(__FILE__, __LINE__, #a, #b, (a), (b))
#define SMF_CHECK_FALSE(condition) \
  ::smftest::expect_false(__FILE__, __LINE__, #condition, static_cast<bool>(condition))
#define SMF_CHECK_OK(expression) ::smftest::expect_ok(__FILE__, __LINE__, #expression, (expression))
#define SMF_CHECK_CODE(expression, code) \
  ::smftest::expect_code(__FILE__, __LINE__, #expression, (expression), (code))
#define SMF_REQUIRE_OK(expression) ::smftest::require_ok(__FILE__, __LINE__, #expression, (expression))

// Usage:  SMF_PROPERTY(200) { ... use ctx.rng ... }
#define SMF_PROPERTY(iterations)                                                        \
  for (::smftest::PropertyLoop smf_prop_loop(__FILE__, __LINE__, (iterations));          \
       smf_prop_loop.next();)                                                            \
    for (::smftest::PropertyContext& ctx = smf_prop_loop.context(); ctx.once(); ctx.stop())

#endif  // SMF_TEST_HPP
