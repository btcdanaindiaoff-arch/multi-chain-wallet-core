// =============================================================================
// test_bitcoin.cpp - Comprehensive Bitcoin chain tests
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/chains/bitcoin/BitcoinChain.h>
#include <wallet/core/KeyPair.h>
#include <wallet/utils/Hex.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

using namespace wallet;

class BitcoinChainTest : public ::testing::Test {
protected:
    BitcoinChain chain_;
};

// =============================================================================
// Chain metadata tests
// =============================================================================

TEST_F(BitcoinChainTest, CoinTypeIs0) {
    EXPECT_EQ(chain_.coinType(), 0u);
}

TEST_F(BitcoinChainTest, ChainNameIsBitcoin) {
    EXPECT_EQ(chain_.chainName(), "Bitcoin");
}

// =============================================================================
// Address derivation tests (Bech32 / SegWit)
// =============================================================================

TEST_F(BitcoinChainTest, DeriveAddressFromCompressedKey) {
    // Create a 33-byte compressed public key
    // 0x02 or 0x03 prefix followed by 32 bytes
    PublicKey pubkey;
    pubkey.data.resize(33);
    pubkey.data[0] = 0x02; // even y-coordinate
    for (int i = 1; i < 33; ++i) {
        pubkey.data[i] = static_cast<uint8_t>((i * 11 + 7) % 256);
    }

    std::string address = chain_.deriveAddress(pubkey);

    // Native SegWit (Bech32) address should start with "bc1q"
    EXPECT_GE(address.size(), 42u); // Bech32 addresses are 42-62 chars
    EXPECT_EQ(address.substr(0, 4), "bc1q");
}

TEST_F(BitcoinChainTest, AddressIsAllLowercase) {
    PublicKey pubkey;
    pubkey.data.resize(33);
    pubkey.data[0] = 0x03;
    for (int i = 1; i < 33; ++i) {
        pubkey.data[i] = static_cast<uint8_t>(i * 3);
    }

    std::string address = chain_.deriveAddress(pubkey);
    for (char c : address) {
        if (std::isalpha(c)) {
            EXPECT_EQ(c, std::tolower(c))
                << "Bech32 address must be lowercase, found: " << c;
        }
    }
}

TEST_F(BitcoinChainTest, DifferentKeysProduceDifferentAddresses) {
    PublicKey pubkey1, pubkey2;
    pubkey1.data.resize(33);
    pubkey2.data.resize(33);
    pubkey1.data[0] = 0x02;
    pubkey2.data[0] = 0x02;
    for (int i = 1; i < 33; ++i) {
        pubkey1.data[i] = static_cast<uint8_t>(i);
        pubkey2.data[i] = static_cast<uint8_t>(i + 50);
    }

    EXPECT_NE(chain_.deriveAddress(pubkey1), chain_.deriveAddress(pubkey2));
}

// =============================================================================
// Transaction signing tests (SegWit)
// =============================================================================

TEST_F(BitcoinChainTest, SignTransactionReturnsNonEmpty) {
    // Mock unsigned SegWit transaction
    // Version(4) + marker(0x00) + flag(0x01) + input_count + inputs + output_count + outputs + locktime
    std::vector<uint8_t> txData = {
        // Version 2
        0x02, 0x00, 0x00, 0x00,
        // Input count: 1
        0x01,
        // Previous txid (32 bytes, dummy)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        // Previous vout (4 bytes)
        0x00, 0x00, 0x00, 0x00,
        // ScriptSig length: 0 (SegWit - empty)
        0x00,
        // Sequence
        0xFF, 0xFF, 0xFF, 0xFF,
        // Output count: 1
        0x01,
        // Value: 50000 sats (8 bytes LE)
        0x50, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ScriptPubKey length + P2WPKH script
        0x16, 0x00, 0x14,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD,
        // Locktime
        0x00, 0x00, 0x00, 0x00
    };

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    EXPECT_FALSE(signedTx.empty());
}

TEST_F(BitcoinChainTest, SignTransactionProducesSegWitFormat) {
    // Minimal unsigned tx for signing
    std::vector<uint8_t> txData = {
        0x02, 0x00, 0x00, 0x00, // version
        0x01,                   // input count
        // 32-byte prevhash
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, // prevout index
        0x00,                   // scriptSig (empty for SegWit)
        0xFF, 0xFF, 0xFF, 0xFF, // sequence
        0x01,                   // output count
        0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // value
        0x16, 0x00, 0x14,       // P2WPKH script header
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14,
        0x00, 0x00, 0x00, 0x00  // locktime
    };

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    ASSERT_GE(signedTx.size(), 10u);

    // SegWit format: version(4) + marker(0x00) + flag(0x01) + ...
    // Check for SegWit marker and flag after version bytes
    EXPECT_EQ(signedTx[4], 0x00) << "Missing SegWit marker byte";
    EXPECT_EQ(signedTx[5], 0x01) << "Missing SegWit flag byte";
}
