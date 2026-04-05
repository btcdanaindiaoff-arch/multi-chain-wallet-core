#include <gtest/gtest.h>
#include "wallet/chains/solana/SolanaChain.h"
#include "wallet/core/KeyPair.h"

using namespace wallet;

// TODO: Replace with real Solana test vectors.

TEST(SolanaTest, CoinType) {
    SolanaChain sol;
    EXPECT_EQ(sol.coinType(), 501u);
}

TEST(SolanaTest, ChainName) {
    SolanaChain sol;
    EXPECT_EQ(sol.chainName(), "Solana");
}

TEST(SolanaTest, DeriveAddressLength) {
    SolanaChain sol;
    PublicKey pk;
    pk.data.resize(32, 0); // Placeholder Ed25519 key
    std::string addr = sol.deriveAddress(pk);
    // Base58-encoded 32 bytes should be 32-44 characters.
    EXPECT_GE(addr.size(), 32u);
    EXPECT_LE(addr.size(), 44u);
}

TEST(SolanaTest, SignTransactionReturnsBytes) {
    SolanaChain sol;
    PrivateKey key{};
    std::vector<uint8_t> txData = {0x01, 0x00}; // Placeholder
    auto signed_tx = sol.signTransaction(txData, key);
    // TODO: Once implemented, signed_tx should be non-empty.
    (void)signed_tx;
}
