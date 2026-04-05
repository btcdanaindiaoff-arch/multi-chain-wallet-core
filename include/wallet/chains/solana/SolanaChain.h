#pragma once
#ifndef WALLET_CHAINS_SOLANA_SOLANACHAIN_H
#define WALLET_CHAINS_SOLANA_SOLANACHAIN_H

#include "wallet/chains/IChain.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

/// @brief Solana chain implementation.
///
/// Uses Ed25519 for key generation, signing, and Base58-encoded addresses.
class SolanaChain : public IChain {
public:
    /// Derive a Solana address (Base58-encoded Ed25519 public key).
    /// @param pubkey  Ed25519 public key (32 bytes).
    /// @return Base58-encoded address string.
    std::string deriveAddress(const PublicKey& pubkey) const override;

    /// Sign a Solana transaction.
    /// @param txData  Serialised unsigned transaction bytes.
    /// @param key     Ed25519 private key (seed).
    /// @return Signed transaction bytes.
    std::vector<uint8_t> signTransaction(
        const std::vector<uint8_t>& txData,
        const PrivateKey& key) const override;

    /// SLIP-44 coin type for Solana: 501.
    uint32_t coinType() const override;

    /// @return "Solana"
    std::string chainName() const override;
};

} // namespace wallet

#endif // WALLET_CHAINS_SOLANA_SOLANACHAIN_H
