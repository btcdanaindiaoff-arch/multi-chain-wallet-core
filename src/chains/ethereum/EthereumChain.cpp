#include "wallet/chains/ethereum/EthereumChain.h"

namespace wallet {

std::string EthereumChain::deriveAddress(const PublicKey& pubkey) const {
    // TODO: Take the last 64 bytes of the uncompressed public key (skip 0x04),
    //       compute Keccak-256, take the last 20 bytes, hex-encode with "0x"
    //       prefix, and apply EIP-55 checksum.
    (void)pubkey;
    return "0x0000000000000000000000000000000000000000";
}

std::vector<uint8_t> EthereumChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const {
    // TODO: Decode RLP transaction, compute Keccak-256 hash,
    //       sign with ECDSA secp256k1, encode (v, r, s) into signed tx.
    (void)txData;
    (void)key;
    return {};
}

uint32_t EthereumChain::coinType() const {
    return 60; // SLIP-44 Ethereum
}

std::string EthereumChain::chainName() const {
    return "Ethereum";
}

} // namespace wallet
