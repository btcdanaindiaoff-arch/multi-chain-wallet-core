// src/crypto/Hash.cpp
// Full implementation of cryptographic hash functions.
//
// SHA-256, SHA-512, RIPEMD-160 use OpenSSL EVP.
// Keccak-256 uses a standalone sponge construction (NOT SHA3-256).

#include "wallet/crypto/Hash.h"

#include <openssl/evp.h>
#include <cstring>
#include <stdexcept>

// ============================================================================
// Minimal Keccak-256 implementation (sponge construction)
// This is the *original* Keccak used by Ethereum, NOT NIST SHA3-256.
// Difference: Keccak uses padding 0x01, SHA3 uses 0x06.
// ============================================================================
namespace {

using KeccakState = uint64_t[25];

static constexpr uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static constexpr int kRotationOffsets[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static constexpr int kPiLane[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccakF1600(KeccakState state) {
    for (int round = 0; round < 24; ++round) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                state[y + x] ^= D[x];
        }

        // Rho and Pi
        uint64_t temp[25];
        for (int i = 0; i < 25; ++i)
            temp[kPiLane[i]] = rotl64(state[i], kRotationOffsets[i]);

        // Chi
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; ++x)
                state[y + x] = temp[y + x] ^ (~temp[y + (x + 1) % 5] & temp[y + (x + 2) % 5]);

        // Iota
        state[0] ^= kRoundConstants[round];
    }
}

static std::array<uint8_t, 32> keccak256Impl(const uint8_t* data, size_t len) {
    // Keccak-256: rate = 1088 bits = 136 bytes, capacity = 512 bits
    constexpr size_t rate = 136;
    KeccakState state;
    std::memset(state, 0, sizeof(state));

    // Absorb phase
    size_t offset = 0;
    while (offset + rate <= len) {
        for (size_t i = 0; i < rate / 8; ++i) {
            uint64_t lane = 0;
            std::memcpy(&lane, data + offset + i * 8, 8);
            state[i] ^= lane;
        }
        keccakF1600(state);
        offset += rate;
    }

    // Pad last block -- Keccak padding (0x01), NOT SHA3 (0x06)
    uint8_t lastBlock[rate];
    std::memset(lastBlock, 0, rate);
    size_t remaining = len - offset;
    std::memcpy(lastBlock, data + offset, remaining);
    lastBlock[remaining] = 0x01;        // Keccak domain separator
    lastBlock[rate - 1] |= 0x80;        // Final bit of multi-rate padding

    for (size_t i = 0; i < rate / 8; ++i) {
        uint64_t lane = 0;
        std::memcpy(&lane, lastBlock + i * 8, 8);
        state[i] ^= lane;
    }
    keccakF1600(state);

    // Squeeze phase -- extract 32 bytes (256 bits)
    std::array<uint8_t, 32> hash;
    std::memcpy(hash.data(), state, 32);
    return hash;
}

} // anonymous namespace

// ============================================================================
// OpenSSL EVP-based hash helpers
// ============================================================================
namespace wallet {
namespace crypto {

std::array<uint8_t, 32> Hash::sha256(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> digest;
    unsigned int len = 0;
    if (!EVP_Digest(data.data(), data.size(), digest.data(), &len,
                    EVP_sha256(), nullptr)) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    return digest;
}

std::array<uint8_t, 64> Hash::sha512(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 64> digest;
    unsigned int len = 0;
    if (!EVP_Digest(data.data(), data.size(), digest.data(), &len,
                    EVP_sha512(), nullptr)) {
        throw std::runtime_error("SHA-512 digest failed");
    }
    return digest;
}

std::array<uint8_t, 32> Hash::keccak256(const std::vector<uint8_t>& data) {
    return keccak256Impl(data.data(), data.size());
}

std::array<uint8_t, 20> Hash::ripemd160(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 20> digest;
    unsigned int len = 0;
    if (!EVP_Digest(data.data(), data.size(), digest.data(), &len,
                    EVP_ripemd160(), nullptr)) {
        throw std::runtime_error("RIPEMD-160 digest failed");
    }
    return digest;
}

std::array<uint8_t, 32> Hash::doubleSha256(const std::vector<uint8_t>& data) {
    auto first = sha256(data);
    std::vector<uint8_t> tmp(first.begin(), first.end());
    return sha256(tmp);
}

std::array<uint8_t, 20> Hash::hash160(const std::vector<uint8_t>& data) {
    auto sha = sha256(data);
    std::vector<uint8_t> tmp(sha.begin(), sha.end());
    return ripemd160(tmp);
}

} // namespace crypto
} // namespace wallet
