#pragma once
#ifndef WALLET_CHAINS_BITCOIN_BITCOINCHAIN_H
#define WALLET_CHAINS_BITCOIN_BITCOINCHAIN_H

#include "wallet/chains/IChain.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

/// @brief Bitcoin chain implementation.
///
/// Supports P2PKH, P2SH-P2WPKH, and native SegWit (bech32) address
/// derivation.  Transaction signing covers legacy and SegWit inputs.
class BitcoinChain : public IChain {
public:
    /// Derive a Bitcoin address from a compressed public key.
    /// Default format: native SegWit (bech32, bc1...).
    /// @param pubkey  Compressed secp256k1 public key (33 bytes).
    /// @return Bech32 address string.
    std::string deriveAddress(const PublicKey& pubkey) const override;

    /// Sign a serialised Bitcoin transaction.
    /// @param txData  Unsigned transaction bytes.
    /// @param key     secp256k1 private key.
    /// @return Signed transaction bytes.
    std::vector<uint8_t> signTransaction(
        const std::vector<uint8_t>& txData,
        const PrivateKey& key) const override;

    /// SLIP-44 coin type for Bitcoin: 0.
    uint32_t coinType() const override;

    /// @return "Bitcoin"
    std::string chainName() const override;
};

} // namespace wallet

#endif // WALLET_CHAINS_BITCOIN_BITCOINCHAIN_H
