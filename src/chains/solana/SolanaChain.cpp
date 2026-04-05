// ==========================================================================
// SolanaChain.cpp -- Solana address derivation & transaction signing
// ==========================================================================
#include "wallet/chains/solana/SolanaChain.h"
#include "wallet/crypto/Ed25519.h"
#include "wallet/utils/Base58.h"

#include <stdexcept>
#include <cstring>

namespace wallet {

using crypto::Ed25519;
using utils::Base58;

// ---------------------------------------------------------------------------
// deriveAddress()  --  Base58-encoded Ed25519 public key
// ---------------------------------------------------------------------------
std::string SolanaChain::deriveAddress(const PublicKey& pubkey) const {
    // Solana addresses are simply the Base58-encoded 32-byte Ed25519
    // public key.
    if (pubkey.data.size() != 32)
        throw std::runtime_error(
            "SolanaChain::deriveAddress: expected 32-byte Ed25519 public key");

    return Base58::encode(pubkey.data);
}

// ---------------------------------------------------------------------------
// signTransaction()  --  Ed25519 sign and prepend signature
//
// Solana transaction wire format (simplified):
// [1 byte  signature count]
// [N * 64  signatures]
// [remaining: message bytes]
//
// The input txData is the **message bytes** only (the serialised
// transaction message without the signature array).  We sign the
// message, then output the full wire-format transaction:
//   [01] [64-byte signature] [message bytes]
//
// For multi-signer scenarios, the caller should assemble the
// signatures separately.
// ---------------------------------------------------------------------------
std::vector<uint8_t> SolanaChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const
{
    if (txData.empty())
        throw std::runtime_error("SolanaChain::signTransaction: empty txData");

    // Ed25519 sign the message bytes
    auto signature = Ed25519::sign(txData, key.data);

    // Assemble: [sigCount=1] [64-byte sig] [message]
    std::vector<uint8_t> signedTx;
    signedTx.reserve(1 + 64 + txData.size());

    signedTx.push_back(0x01); // 1 signature
    signedTx.insert(signedTx.end(), signature.begin(), signature.end());
    signedTx.insert(signedTx.end(), txData.begin(), txData.end());

    return signedTx;
}

uint32_t SolanaChain::coinType() const { return 501; }
std::string SolanaChain::chainName() const { return "Solana"; }

} // namespace wallet
