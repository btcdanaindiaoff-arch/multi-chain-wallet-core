#include <gtest/gtest.h>
#include "wallet/chains/bitcoin/BitcoinChain.h"
#include "wallet/core/KeyPair.h"

using namespace wallet;

// TODO: Replace with real Bitcoin test vectors.

TEST(BitcoinTest, CoinType) {
    BitcoinChain btc;
    EXPECT_EQ(btc.coinType(), 0u);
}

TEST(BitcoinTest, ChainName) {
    BitcoinChain btc;
    EXPECT_EQ(btc.chainName(), "Bitcoin");
}

TEST(BitcoinTest, DeriveAddressFormat) {
    BitcoinChain btc;
    PublicKey pk;
    pk.data.resize(33, 0); // Placeholder compressed key
    std::string addr = btc.deriveAddress(pk);
    // Native SegWit address should start with "bc1".
    EXPECT_EQ(addr.substr(0, 3), "bc1");
}

TEST(BitcoinTest, SignTransactionReturnsBytes) {
    BitcoinChain btc;
    PrivateKey key{};
    std::vector<uint8_t> txData = {0x01, 0x00, 0x00, 0x00}; // Placeholder
    auto signed_tx = btc.signTransaction(txData, key);
    // TODO: Once implemented, signed_tx should be non-empty.
    (void)signed_tx;
}
