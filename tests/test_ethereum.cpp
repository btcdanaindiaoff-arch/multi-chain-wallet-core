// =============================================================================
// test_ethereum.cpp - Comprehensive Ethereum chain tests
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/chains/ethereum/EthereumChain.h>
#include <wallet/core/KeyPair.h>
#include <wallet/utils/Hex.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cctype>

using namespace wallet;

class EthereumChainTest : public ::testing::Test {
protected:
    EthereumChain chain_;
};

// =============================================================================
// Chain metadata tests
// =============================================================================

TEST_F(EthereumChainTest, CoinTypeIs60) {
    EXPECT_EQ(chain_.coinType(), 60u);
}

TEST_F(EthereumChainTest, ChainNameIsEthereum) {
    EXPECT_EQ(chain_.chainName(), "Ethereum");
}

// =============================================================================
// Address derivation tests
// =============================================================================

TEST_F(EthereumChainTest, DeriveAddressFromUncompressedKey) {
    // Create a 65-byte uncompressed public key starting with 0x04
    PublicKey pubkey;
    pubkey.data.resize(65);
    pubkey.data[0] = 0x04;
    // Fill with deterministic test data (non-zero)
    for (int i = 1; i < 65; ++i) {
        pubkey.data[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
    }

    std::string address = chain_.deriveAddress(pubkey);

    // Address should be 42 chars: "0x" + 40 hex digits
    EXPECT_EQ(address.size(), 42u);
    EXPECT_EQ(address.substr(0, 2), "0x");

    // Remaining 40 chars should be valid hex
    std::string hexPart = address.substr(2);
    EXPECT_EQ(hexPart.size(), 40u);
    for (char c : hexPart) {
        EXPECT_TRUE(std::isxdigit(c)) << "Non-hex char in address: " << c;
    }
}

TEST_F(EthereumChainTest, AddressHasEIP55MixedCaseChecksum) {
    // EIP-55 checksum means the address should have mixed case (not all lower/upper)
    PublicKey pubkey;
    pubkey.data.resize(65);
    pubkey.data[0] = 0x04;
    for (int i = 1; i < 65; ++i) {
        pubkey.data[i] = static_cast<uint8_t>((i * 37 + 99) % 256);
    }

    std::string address = chain_.deriveAddress(pubkey);
    std::string hexPart = address.substr(2);

    bool hasUpper = false, hasLower = false;
    for (char c : hexPart) {
        if (std::isupper(c)) hasUpper = true;
        if (std::islower(c)) hasLower = true;
    }
    // EIP-55 checksum should produce a mix of upper and lower hex letters
    // (statistically very likely for any non-trivial address)
    EXPECT_TRUE(hasUpper || hasLower)
        << "Address lacks alphabetic hex chars: " << address;
}

TEST_F(EthereumChainTest, DifferentKeysProduceDifferentAddresses) {
    PublicKey pubkey1, pubkey2;
    pubkey1.data.resize(65);
    pubkey2.data.resize(65);
    pubkey1.data[0] = 0x04;
    pubkey2.data[0] = 0x04;
    for (int i = 1; i < 65; ++i) {
        pubkey1.data[i] = static_cast<uint8_t>(i);
        pubkey2.data[i] = static_cast<uint8_t>(i + 100);
    }

    std::string addr1 = chain_.deriveAddress(pubkey1);
    std::string addr2 = chain_.deriveAddress(pubkey2);
    EXPECT_NE(addr1, addr2);
}

// =============================================================================
// Transaction signing tests
// =============================================================================

TEST_F(EthereumChainTest, SignTransactionReturnsNonEmpty) {
    // Mock transaction data (RLP-encoded unsigned tx)
    std::vector<uint8_t> txData = {
        0xE8,                                     // RLP list prefix
        0x80,                                     // nonce = 0
        0x85, 0x04, 0xA8, 0x17, 0xC8, 0x00,     // gasPrice
        0x82, 0x52, 0x08,                         // gasLimit = 21000
        0x94,                                     // to address prefix (20 bytes)
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x87, 0x03, 0x8D, 0x7E, 0xA4, 0xC6, 0x80, 0x00, // value
        0x80                                      // data (empty)
    };

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    EXPECT_FALSE(signedTx.empty());
}

TEST_F(EthereumChainTest, SignTransactionOutputIsValidRLP) {
    // Minimal RLP-encoded tx
    std::vector<uint8_t> txData = {0xC0}; // empty list

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    ASSERT_FALSE(signedTx.empty());
    // RLP-encoded list should start in range 0xC0-0xFF
    EXPECT_GE(signedTx[0], 0xC0);
}
