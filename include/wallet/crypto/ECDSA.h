#pragma once
#ifndef WALLET_CRYPTO_ECDSA_H
#define WALLET_CRYPTO_ECDSA_H

#include <array>
#include <cstdint>
#include <vector>

namespace wallet {
namespace crypto {

/// @brief ECDSA operations on the secp256k1 curve using OpenSSL.
class ECDSA {
public:
    /// Sign a 32-byte message hash with a private key.
    /// @param hash       32-byte SHA-256 or Keccak-256 digest.
    /// @param privateKey 32-byte secp256k1 private key.
    /// @return DER-encoded signature bytes.
    static std::vector<uint8_t> sign(
        const std::array<uint8_t, 32>& hash,
        const std::array<uint8_t, 32>& privateKey);

    /// Verify a DER-encoded signature against a hash and public key.
    /// @param hash      32-byte digest.
    /// @param signature DER-encoded signature.
    /// @param publicKey Compressed (33) or uncompressed (65) secp256k1 key.
    /// @return true if the signature is valid.
    static bool verify(
        const std::array<uint8_t, 32>& hash,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& publicKey);

    /// Derive the compressed public key from a private key.
    /// @param privateKey 32-byte secp256k1 scalar.
    /// @return 33-byte compressed public key.
    static std::vector<uint8_t> publicKeyFromPrivate(
        const std::array<uint8_t, 32>& privateKey);
};

} // namespace crypto
} // namespace wallet

#endif // WALLET_CRYPTO_ECDSA_H
