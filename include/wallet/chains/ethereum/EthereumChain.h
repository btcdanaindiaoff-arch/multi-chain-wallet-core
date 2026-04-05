#pragma once
#ifndef WALLET_CHAINS_ETHEREUM_ETHEREUMCHAIN_H
#define WALLET_CHAINS_ETHEREUM_ETHEREUMCHAIN_H

#include "wallet/chains/IChain.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

/// @brief Ethereum / EVM chain implementation.
///
/// Supports address derivation via Keccak-256 and transaction signing
/// for both legacy and EIP-1559 transaction formats.
class EthereumChain : public IChain {
public:
    /// Derive an EIP-55 checksummed Ethereum address from a public key.
    /// @param pubkey  Uncompressed secp256k1 public key (65 bytes).
    /// @return Address string prefixed with "0x".
    std::string deriveAddress(const PublicKey& pubkey) const override;

    /// Sign an RLP-encoded Ethereum transaction.
    /// @param txData  RLP-encoded unsigned transaction bytes.
    /// @param key     secp256k1 private key.
    /// @return RLP-encoded signed transaction bytes.
    std::vector<uint8_t> signTransaction(
        const std::vector<uint8_t>& txData,
        const PrivateKey& key) const override;

    /// SLIP-44 coin type for Ethereum: 60.
    uint32_t coinType() const override;

    /// @return "Ethereum"
    std::string chainName() const override;
};

} // namespace wallet

#endif // WALLET_CHAINS_ETHEREUM_ETHEREUMCHAIN_H
