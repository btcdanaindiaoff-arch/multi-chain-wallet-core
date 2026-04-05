#pragma once
#ifndef WALLET_CRYPTO_HASH_H
#define WALLET_CRYPTO_HASH_H

#include <array>
#include <cstdint>
#include <vector>

namespace wallet {
namespace crypto {

/// @brief Common cryptographic hash functions used across chains.
class Hash {
public:
    /// SHA-256 digest (32 bytes).
    static std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);

    /// SHA-512 digest (64 bytes).
    static std::array<uint8_t, 64> sha512(const std::vector<uint8_t>& data);

    /// Keccak-256 digest (32 bytes) -- used by Ethereum.
    static std::array<uint8_t, 32> keccak256(const std::vector<uint8_t>& data);

    /// RIPEMD-160 digest (20 bytes) -- used in Bitcoin address derivation.
    static std::array<uint8_t, 20> ripemd160(const std::vector<uint8_t>& data);

    /// Double SHA-256: sha256(sha256(data)) -- Bitcoin convention.
    static std::array<uint8_t, 32> doubleSha256(const std::vector<uint8_t>& data);

    /// HASH160: ripemd160(sha256(data)) -- Bitcoin pubkey hashing.
    static std::array<uint8_t, 20> hash160(const std::vector<uint8_t>& data);
};

} // namespace crypto
} // namespace wallet

#endif // WALLET_CRYPTO_HASH_H
