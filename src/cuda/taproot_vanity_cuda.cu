#include "taproot_vanity.hpp"

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::uint32_t kThreadsPerBlock = 256;
constexpr std::uint32_t kCandidatesPerThread = 4;
constexpr std::uint32_t kBlocks = 240;
constexpr std::uint32_t kBatch = kThreadsPerBlock * kCandidatesPerThread * kBlocks;
constexpr std::uint32_t kMaxSeed = 256;

__constant__ std::uint8_t c_seed[kMaxSeed];
__constant__ std::uint8_t c_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR32((x), 2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define BSIG1(x) (ROTR32((x), 6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define SSIG0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))

__device__ __forceinline__ bool scalar_valid(const std::uint8_t* v) {
    bool nonzero = false;
    for (int i = 0; i < 32; ++i) nonzero |= v[i] != 0;
    if (!nonzero) return false;
    for (int i = 0; i < 32; ++i) {
        if (v[i] < c_order[i]) return true;
        if (v[i] > c_order[i]) return false;
    }
    return false;
}

__device__ __forceinline__ void sha256_single(const std::uint8_t* msg, std::uint32_t len,
                                              std::uint8_t out[32]) {
    constexpr std::uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    std::uint32_t h[8] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
                          0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    std::uint8_t block[128] = {};
    for (std::uint32_t i = 0; i < len; ++i) block[i] = msg[i];
    block[len] = 0x80U;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8ULL;
    const std::uint32_t total = (len + 9U <= 64U) ? 64U : 128U;
    for (int i = 0; i < 8; ++i) block[total - 1 - i] = static_cast<std::uint8_t>(bit_len >> (8 * i));
    for (std::uint32_t off = 0; off < total; off += 64) {
        std::uint32_t w[64];
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[off + i * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[off + i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[off + i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(block[off + i * 4 + 3]);
        }
        #pragma unroll
        for (int i = 16; i < 64; ++i) w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
        std::uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        #pragma unroll
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t t1 = hh + BSIG1(e) + CH(e, f, g) + k[i] + w[i];
            const std::uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    #pragma unroll
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(h[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(h[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(h[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(h[i]);
    }
}

__global__ __launch_bounds__(kThreadsPerBlock, 2)
void derive_private_keys_kernel(std::uint32_t seed_len, std::uint64_t start_counter,
                                std::uint8_t* out_keys, std::uint8_t* out_valid) {
    const std::uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const std::uint32_t base = tid * kCandidatesPerThread;
    constexpr char domain[] = "TaprootVanity/seed-v1";
    #pragma unroll
    for (std::uint32_t lane = 0; lane < kCandidatesPerThread; ++lane) {
        const std::uint64_t counter = start_counter + base + lane;
        std::uint8_t msg[sizeof(domain) - 1 + kMaxSeed + 8 + 4];
        std::uint32_t pos = 0;
        #pragma unroll
        for (std::uint32_t i = 0; i < sizeof(domain) - 1; ++i) msg[pos++] = static_cast<std::uint8_t>(domain[i]);
        for (std::uint32_t i = 0; i < seed_len; ++i) msg[pos++] = c_seed[i];
        #pragma unroll
        for (int shift = 56; shift >= 0; shift -= 8) msg[pos++] = static_cast<std::uint8_t>(counter >> shift);
        msg[pos++] = 0; msg[pos++] = 0; msg[pos++] = 0; msg[pos++] = 0;
        std::uint8_t digest[32];
        sha256_single(msg, pos, digest);
        const std::uint32_t out = (base + lane) * 32;
        #pragma unroll
        for (int i = 0; i < 32; ++i) out_keys[out + i] = digest[i];
        out_valid[base + lane] = scalar_valid(digest) ? 1 : 0;
    }
}

void check_cuda(cudaError_t err, const char* what) {
    if (err != cudaSuccess) throw std::runtime_error(std::string(what) + ": " + cudaGetErrorString(err));
}

}  // namespace

extern "C" int taproot_vanity_cuda_search(const std::uint8_t* seed,
                                           std::uint32_t seed_len,
                                           const char* prefix,
                                           std::uint64_t start_counter,
                                           std::uint64_t attempts) {
    if (seed_len > kMaxSeed) {
        std::cerr << "seed is limited to " << kMaxSeed << " bytes for constant-memory broadcast\n";
        return 1;
    }
    try {
        check_cuda(cudaMemcpyToSymbol(c_seed, seed, seed_len), "copy seed");
        std::uint8_t* d_keys = nullptr;
        std::uint8_t* d_valid = nullptr;
        check_cuda(cudaMalloc(reinterpret_cast<void**>(&d_keys), kBatch * 32), "alloc keys");
        check_cuda(cudaMalloc(reinterpret_cast<void**>(&d_valid), kBatch), "alloc valid");
        std::vector<std::uint8_t> keys(kBatch * 32);
        std::vector<std::uint8_t> valid(kBatch);
        for (std::uint64_t done = 0; done < attempts; done += kBatch) {
            const std::uint64_t batch = std::min<std::uint64_t>(kBatch, attempts - done);
            derive_private_keys_kernel<<<kBlocks, kThreadsPerBlock>>>(seed_len, start_counter + done, d_keys, d_valid);
            check_cuda(cudaGetLastError(), "launch derive_private_keys_kernel");
            check_cuda(cudaMemcpy(keys.data(), d_keys, batch * 32, cudaMemcpyDeviceToHost), "copy keys");
            check_cuda(cudaMemcpy(valid.data(), d_valid, batch, cudaMemcpyDeviceToHost), "copy valid");
            for (std::uint64_t i = 0; i < batch; ++i) {
                if (valid[i] == 0) continue;
                std::array<std::uint8_t, 32> key{};
                std::memcpy(key.data(), keys.data() + i * 32, 32);
                auto data = taproot_vanity::derive_taproot_key(key);
                if (data.address.rfind(prefix, 0) == 0) {
                    std::cout << "counter=" << (start_counter + done + i) << '\n'
                              << "privkey=" << taproot_vanity::hex(data.private_key) << '\n'
                              << "address=" << data.address << '\n';
                    cudaFree(d_keys);
                    cudaFree(d_valid);
                    return 0;
                }
            }
        }
        cudaFree(d_keys);
        cudaFree(d_valid);
        std::cerr << "no match in " << attempts << " attempts\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "cuda search error: " << e.what() << '\n';
        return 1;
    }
}
