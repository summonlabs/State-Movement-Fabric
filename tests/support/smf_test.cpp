// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "smf_test.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>

#include "smf/ids.hpp"

namespace smftest {
namespace {

constexpr std::uint64_t kDefaultSeed = 0x5EEDFAB1C0FFEEULL;

std::uint64_t g_base_seed = kDefaultSeed;

thread_local const PropertyLoop* g_current_property = nullptr;
thread_local const PropertyContext* g_current_context = nullptr;

struct TestFailure {
  std::string message;
};

[[nodiscard]] bool parse_u64(const std::string& text, std::uint64_t& out) {
  if (text.empty()) return false;
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10ULL) return false;
    value = (value * 10ULL) + digit;
  }
  out = value;
  return true;
}

[[nodiscard]] std::string unique_suffix() {
  smf::IdIssuer issuer;
  return issuer.new_boot_id().hex();
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> instance;
  return instance;
}

Registrar::Registrar(const char* suite, const char* name, void (*fn)()) {
  registry().push_back(TestCase{suite, name, fn});
}

void fail(const char* file, int line, const std::string& message) {
  std::ostringstream os;
  if (g_current_context != nullptr) {
    os << "[property seed=" << g_current_context->seed << " iteration=" << g_current_context->iteration
       << "] ";
  }
  os << message << "  (" << file << ":" << line << ")";
  throw TestFailure{os.str()};
}

std::uint64_t Rng::next_u64() noexcept {
  state_ += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

std::uint32_t Rng::next_u32() noexcept { return static_cast<std::uint32_t>(next_u64() >> 32U); }

std::size_t Rng::below(std::size_t bound) noexcept {
  if (bound <= 1) return 0;
  const std::uint64_t range = static_cast<std::uint64_t>(bound);
  const std::uint64_t threshold = (0ULL - range) % range;
  for (;;) {
    const std::uint64_t value = next_u64();
    if (value >= threshold) return static_cast<std::size_t>(value % range);
  }
}

bool Rng::chance(unsigned percent) noexcept { return below(100) < percent; }

smf::Bytes Rng::bytes(std::size_t count) {
  smf::Bytes out(count);
  for (std::size_t i = 0; i < count; ++i) out[i] = static_cast<smf::Byte>(next_u64() & 0xFFULL);
  return out;
}

std::string Rng::ascii(std::size_t count) {
  std::string out;
  out.reserve(count);
  constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(kAlphabet[below(sizeof(kAlphabet) - 1)]);
  }
  return out;
}

PropertyLoop::PropertyLoop(const char* file, int line, std::uint64_t iterations)
    : file_(file),
      line_(line),
      iterations_(iterations),
      seed_(base_seed()),
      rng_(seed_) {
  context_.emplace(seed_, 0, rng_);
  previous_ = g_current_property;
  previous_context_ = g_current_context;
  g_current_property = this;
  g_current_context = &*context_;
}

PropertyLoop::~PropertyLoop() {
  g_current_property = previous_;
  g_current_context = previous_context_;
}

bool PropertyLoop::next() {
  if (iteration_ >= iterations_) return false;
  ++iteration_;
  // Reseed per iteration from the base seed so that iteration N is reproducible
  // independently of how many iterations ran before it.
  rng_ = Rng((seed_ * 0x9E3779B97F4A7C15ULL) + iteration_);
  context_.emplace(seed_, iteration_, rng_);
  g_current_context = &*context_;
  return true;
}

std::uint64_t base_seed() noexcept { return g_base_seed; }

void set_base_seed(std::uint64_t seed) noexcept { g_base_seed = seed; }

TempDir::TempDir(std::string_view label) {
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  path_ = base / ("smf-test-" + std::string(label) + "-" + unique_suffix());
  std::error_code error;
  std::filesystem::remove_all(path_, error);
  std::filesystem::create_directories(path_, error);
}

TempDir::~TempDir() {
  std::error_code error;
  std::filesystem::remove_all(path_, error);
}

std::filesystem::path TempDir::file(std::string_view relative) const {
  return path_ / std::filesystem::path(std::string(relative));
}

std::filesystem::path TempDir::directory(std::string_view relative) const {
  const std::filesystem::path target = path_ / std::filesystem::path(std::string(relative));
  std::error_code error;
  std::filesystem::create_directories(target, error);
  return target;
}

void TempDir::reset() {
  std::error_code error;
  std::filesystem::remove_all(path_, error);
  std::filesystem::create_directories(path_, error);
}

int run_all(int argc, char** argv) {
  std::string filter;
  bool list_only = false;

  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else if (argument.rfind("--seed=", 0) == 0) {
      std::uint64_t seed = 0;
      if (!parse_u64(argument.substr(7), seed)) {
        std::cerr << "invalid --seed value: " << argument.substr(7) << "\n";
        return 2;
      }
      set_base_seed(seed);
    } else if (argument == "--list") {
      list_only = true;
    } else {
      std::cerr << "unrecognized argument: " << argument << "\n";
      return 2;
    }
  }

  if (const char* env_seed = std::getenv("SMF_TEST_SEED"); env_seed != nullptr && *env_seed != '\0') {
    std::uint64_t seed = 0;
    if (parse_u64(env_seed, seed)) set_base_seed(seed);
  }

  std::vector<TestCase>& cases = registry();
  std::sort(cases.begin(), cases.end(), [](const TestCase& a, const TestCase& b) {
    if (std::strcmp(a.suite, b.suite) != 0) return std::strcmp(a.suite, b.suite) < 0;
    return std::strcmp(a.name, b.name) < 0;
  });

  if (list_only) {
    for (const TestCase& test : cases) {
      std::cout << test.suite << "." << test.name << "\n";
    }
    return 0;
  }

  std::vector<std::string> failures;
  std::size_t executed = 0;

  std::cout << "[==========] seed=" << base_seed() << " suites=" << cases.size() << "\n";
  for (const TestCase& test : cases) {
    const std::string full_name = std::string(test.suite) + "." + test.name;
    if (!filter.empty() && full_name.find(filter) == std::string::npos) continue;
    ++executed;
    std::cout << "[ RUN      ] " << full_name << std::endl;
    try {
      test.fn();
      std::cout << "[       OK ] " << full_name << std::endl;
    } catch (const TestFailure& failure) {
      std::cout << "[  FAILED  ] " << full_name << ": " << failure.message << std::endl;
      failures.push_back(full_name + ": " + failure.message);
    } catch (const std::exception& error) {
      std::cout << "[  FAILED  ] " << full_name << ": unexpected exception: " << error.what()
                << std::endl;
      failures.push_back(full_name + ": unexpected exception: " + error.what());
    } catch (...) {
      std::cout << "[  FAILED  ] " << full_name << ": unexpected non-standard exception"
                << std::endl;
      failures.push_back(full_name + ": unexpected non-standard exception");
    }
  }

  std::cout << "[==========] executed=" << executed << " failed=" << failures.size() << "\n";
  for (const std::string& failure : failures) {
    std::cout << "[  FAILED  ] " << failure << "\n";
  }
  return failures.empty() ? 0 : 1;
}

}  // namespace smftest
