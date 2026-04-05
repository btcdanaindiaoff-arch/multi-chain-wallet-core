#include <gtest/gtest.h>
#include "wallet/chains/ethereum/EthereumChain.h"
#include "wallet/core/KeyPair.h"

using namespace wallet;

// TODO: Replace with real Ethereum test vectors.

TEST(EthereumTest, CoinType) {
    EthereumChain eth;
    EXPECT_EQ(eth.coinType(), 60u);
}

TEST(EthereumTest, ChainName) {
    EthereumChain eth;
    EXPECT_EQ(eth.chainName(), "Ethereum");
}

TEST(EthereumTest, DeriveAddressFormat) {
    EthereumChain eth;
    PublicKey pk;
    pk.data.resize(65, 0); // Placeholder uncompressed key
    std::string addr = eth.deriveAddress(pk);
    // Address should start with "0x" and be 42 characters.
    EXPECT_EQ(addr.substr(0, 2), "0x");
    EXPECT_EQ(addr.size(), 42u);
}

TEST(EthereumTest, SignTransactionReturnsBytes) {
    EthereumChain eth;
    PrivateKey key{};
    std::vector<uint8_t> txData = {0xf8, 0x00}; // Placeholder RLP
    auto signed_tx = eth.signTransaction(txData, key);
    // TODO: Once implemented, signed_tx should be non-empty.
    (void)signed_tx;
}
