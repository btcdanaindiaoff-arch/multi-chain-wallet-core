#pragma once
#ifndef WALLET_CORE_KEYPAIR_H
#define WALLET_CORE_KEYPAIR_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

/// @brief 32-byte private key (secp256k1 scalar or Ed25519 seed).
struct PrivateKey {
    std::array<uint8_t, 32> data;
};

/// @brief Compressed or uncompressed public key.
///
/// Length varies by curve:
///   - secp256k1 compressed: 33 bytes
///   - secp256k1 uncompressed: 65 bytes
///   - Ed25519: 32 bytes
struct PublicKey {
    std::vector<uint8_t> data;
};

/// @brief A matched private / public key pair with chain-aware address
///        derivation.
struct KeyPair {
    PrivateKey privateKey;
    PublicKey  publicKey;

    /// Derive a human-readable address for the given SLIP-44 coin type.
    /// Delegates to the appropriate chain implementation via ChainRegistry.
    /// @param coinType  SLIP-44 coin type identifier.
    /// @return Chain-specific address string.
    std::string getAddress(uint32_t coinType) const;
};

} // namespace wallet

#endif // WALLET_CORE_KEYPAIR_H
