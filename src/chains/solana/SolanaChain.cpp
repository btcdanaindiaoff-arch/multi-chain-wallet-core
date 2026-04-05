#include "wallet/chains/solana/SolanaChain.h"

namespace wallet {

std::string SolanaChain::deriveAddress(const PublicKey& pubkey) const {
    // TODO: Base58-encode the 32-byte Ed25519 public key.
    (void)pubkey;
    return "11111111111111111111111111111111";
}

std::vector<uint8_t> SolanaChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const {
    // TODO: Sign serialised Solana transaction with Ed25519,
    //       prepend 64-byte signature to the transaction payload.
    (void)txData;
    (void)key;
    return {};
}

uint32_t SolanaChain::coinType() const {
    return 501; // SLIP-44 Solana
}

std::string SolanaChain::chainName() const {
    return "Solana";
}

} // namespace wallet
