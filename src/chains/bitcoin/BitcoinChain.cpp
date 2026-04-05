#include "wallet/chains/bitcoin/BitcoinChain.h"

namespace wallet {

std::string BitcoinChain::deriveAddress(const PublicKey& pubkey) const {
    // TODO: Compute HASH160 of compressed public key,
    //       encode as Bech32 witness v0 address (bc1...).
    (void)pubkey;
    return "bc1q000000000000000000000000000000000000000";
}

std::vector<uint8_t> BitcoinChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const {
    // TODO: Parse unsigned transaction, compute sighash for each input,
    //       sign with ECDSA secp256k1, assemble witness data.
    (void)txData;
    (void)key;
    return {};
}

uint32_t BitcoinChain::coinType() const {
    return 0; // SLIP-44 Bitcoin
}

std::string BitcoinChain::chainName() const {
    return "Bitcoin";
}

} // namespace wallet
