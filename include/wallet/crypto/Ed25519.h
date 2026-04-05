#pragma once
#ifndef WALLET_CRYPTO_ED25519_H
#define WALLET_CRYPTO_ED25519_H

#include <array>
#include <cstdint>
#include <vector>

namespace wallet {
namespace crypto {

/// @brief Ed25519 signature operations.
///
/// Used by Solana and other chains that rely on EdDSA over Curve25519.
class Ed25519 {
public:
    /// Sign an arbitrary-length message with an Ed25519 seed.
    /// @param message   Message bytes to sign.
    /// @param seed      32-byte Ed25519 private seed.
    /// @return 64-byte Ed25519 signature.
    static std::array<uint8_t, 64> sign(
        const std::vector<uint8_t>& message,
        const std::array<uint8_t, 32>& seed);

    /// Verify an Ed25519 signature.
    /// @param message   Original message bytes.
    /// @param signature 64-byte signature.
    /// @param publicKey 32-byte Ed25519 public key.
    /// @return true if signature is valid.
    static bool verify(
        const std::vector<uint8_t>& message,
        const std::array<uint8_t, 64>& signature,
        const std::array<uint8_t, 32>& publicKey);

    /// Derive the 32-byte public key from an Ed25519 seed.
    /// @param seed  32-byte private seed.
    /// @return 32-byte public key.
    static std::array<uint8_t, 32> publicKeyFromSeed(
        const std::array<uint8_t, 32>& seed);
};

} // namespace crypto
} // namespace wallet

#endif // WALLET_CRYPTO_ED25519_H
