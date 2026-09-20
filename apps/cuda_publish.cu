// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "cuda_publish.hpp"

#include <cuda_runtime.h>

#include <cstdio>
#include <vector>

#include "smf/digest.hpp"

namespace smf::app {
namespace {

// A deterministic fill computed on the device. The host never writes these
// bytes, so a successful transfer proves the device allocation was real and its
// contents actually travelled.
__global__ void fill_pattern(unsigned char* data, unsigned long long bytes,
                             unsigned long long seed) {
  const unsigned long long threads =
      static_cast<unsigned long long>(gridDim.x) * static_cast<unsigned long long>(blockDim.x);
  const unsigned long long words = (bytes + 7ULL) / 8ULL;
  for (unsigned long long word =
           (static_cast<unsigned long long>(blockIdx.x) * blockDim.x) + threadIdx.x;
       word < words; word += threads) {
    unsigned long long z = seed ^ (word * 0x9E3779B97F4A7C15ULL);
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31U);
    const unsigned long long offset = word * 8ULL;
    for (unsigned long long byte = 0; byte < 8ULL && (offset + byte) < bytes; ++byte) {
      data[offset + byte] = static_cast<unsigned char>((z >> (8U * byte)) & 0xFFULL);
    }
  }
}

[[nodiscard]] Status cuda_failure(const char* what, cudaError_t error) {
  return Status(ReasonCode::INTERNAL_ERROR,
                std::string(what) + " failed: " + cudaGetErrorString(error));
}

}  // namespace

bool cuda_available() noexcept {
  int devices = 0;
  if (cudaGetDeviceCount(&devices) != cudaSuccess) {
    cudaGetLastError();
    return false;
  }
  return devices > 0;
}

std::string cuda_runtime_version() noexcept {
  int version = 0;
  if (cudaRuntimeGetVersion(&version) != cudaSuccess) {
    cudaGetLastError();
    return "unknown";
  }
  return std::to_string(version / 1000) + "." + std::to_string((version % 1000) / 10);
}

Result<CudaPublishReport> publish_from_cuda_device(EndpointAgent& agent, StateKind kind,
                                                   const std::string& name,
                                                   StateGeneration generation, std::uint64_t bytes,
                                                   std::uint64_t seed, bool repeatable) {
  if (bytes == 0) {
    return Status(ReasonCode::INVALID_SIZE, "a device payload must not be empty");
  }
  if (!cuda_available()) {
    return Status(ReasonCode::UNSUPPORTED, "no usable CUDA device is present on this host");
  }

  CudaPublishReport report;
  report.available = true;
  report.runtime_version = cuda_runtime_version();
  report.device_bytes = bytes;

  int device = 0;
  cudaDeviceProp properties{};
  if (cudaGetDeviceProperties(&properties, device) != cudaSuccess) {
    cudaGetLastError();
    return Status(ReasonCode::UNSUPPORTED, "the CUDA device properties could not be read");
  }
  report.device_name = properties.name;

  std::size_t free_before = 0;
  std::size_t total = 0;
  if (cudaMemGetInfo(&free_before, &total) != cudaSuccess) {
    cudaGetLastError();
    return Status(ReasonCode::INTERNAL_ERROR, "cudaMemGetInfo failed before the allocation");
  }
  report.device_free_before = free_before;
  report.device_total = total;

  void* device_buffer = nullptr;
  const cudaError_t allocated = cudaMalloc(&device_buffer, static_cast<std::size_t>(bytes));
  if (allocated != cudaSuccess) {
    cudaGetLastError();
    return cuda_failure("cudaMalloc", allocated);
  }

  const auto release = [&]() {
    if (device_buffer != nullptr) {
      const cudaError_t freed = cudaFree(device_buffer);
      device_buffer = nullptr;
      if (freed != cudaSuccess) cudaGetLastError();
    }
  };

  const unsigned int block = 256;
  const unsigned long long words = (bytes + 7ULL) / 8ULL;
  unsigned int grid = static_cast<unsigned int>((words + block - 1) / block);
  if (grid > 65535U) grid = 65535U;
  fill_pattern<<<grid, block>>>(static_cast<unsigned char*>(device_buffer), bytes, seed);
  const cudaError_t launched = cudaGetLastError();
  if (launched != cudaSuccess) {
    release();
    return cuda_failure("the fill kernel", launched);
  }
  const cudaError_t synchronised = cudaDeviceSynchronize();
  if (synchronised != cudaSuccess) {
    release();
    return cuda_failure("cudaDeviceSynchronize", synchronised);
  }

  std::vector<unsigned char> host(static_cast<std::size_t>(bytes));
  const cudaError_t copied =
      cudaMemcpy(host.data(), device_buffer, static_cast<std::size_t>(bytes),
                 cudaMemcpyDeviceToHost);
  if (copied != cudaSuccess) {
    release();
    return cuda_failure("cudaMemcpy", copied);
  }

  release();

  std::size_t free_after = 0;
  std::size_t total_after = 0;
  if (cudaMemGetInfo(&free_after, &total_after) != cudaSuccess) {
    cudaGetLastError();
    return Status(ReasonCode::INTERNAL_ERROR, "cudaMemGetInfo failed after the free");
  }
  report.device_free_after = free_after;

  // The bytes now live in ordinary host memory and enter the fabric through the
  // same publication path any other state object uses.
  StateObjectDescriptor descriptor;
  const Status published =
      agent.publish_bytes(kind, name, generation,
                          ByteView(reinterpret_cast<const Byte*>(host.data()), host.size()),
                          "smf-cuda", repeatable, &descriptor);
  if (!published.ok()) return published;

  report.content_digest = descriptor.content_digest;
  report.object = describe(descriptor);
  return report;
}

}  // namespace smf::app
