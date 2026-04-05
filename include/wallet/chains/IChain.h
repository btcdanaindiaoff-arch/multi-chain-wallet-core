#pragma once
#ifndef WALLET_CHAINS_ICHAIN_H
#define WALLET_CHAINS_ICHAIN_H

#include <cstdint>
#include <string>
#include <vector>

#include "wallet/core/KeyPair.h"

namespace wallet {

/// @brief Abstract interface for blockchain-specific operations.
///
/// Each supported blockchain implements this interface to provide
/// address derivation and transaction signing using its native
/// algorithms and encoding formats.
class IChain {
public:
    virtual ~IChain() = default;

    /// Derive a chain-specific address from a public key.
    /// @param pubkey  The public key to encode.
    /// @return Human-readable address string (e.g. 0x... for Ethereum).
    virtual std::string deriveAddress(const PublicKey& pubkey) const = 0;

    /// Sign a raw transaction payload.
    /// @param txData  Serialised, unsigned transaction bytes.
    /// @param key     Private key used for signing.
    /// @return Signed transaction bytes ready for broadcast.
    virtual std::vector<uint8_t> signTransaction(
        const std::vector<uint8_t>& txData,
        const PrivateKey& key) const = 0;

    /// Return the SLIP-44 coin type for this chain.
    virtual uint32_t coinType() const = 0;

    /// Return a human-readable chain identifier (e.g. "Ethereum", "Bitcoin").
    virtual std::string chainName() const = 0;
};

} // namespace wallet

#endif // WALLET_CHAINS_ICHAIN_H
