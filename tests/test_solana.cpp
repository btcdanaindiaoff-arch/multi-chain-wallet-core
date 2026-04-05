// =============================================================================
// test_solana.cpp - Comprehensive Solana chain tests
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/chains/solana/SolanaChain.h>
#include <wallet/core/KeyPair.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

using namespace wallet;

class SolanaChainTest : public ::testing::Test {
protected:
    SolanaChain chain_;
};

// =============================================================================
// Chain metadata tests
// =============================================================================

TEST_F(SolanaChainTest, CoinTypeIs501) {
    EXPECT_EQ(chain_.coinType(), 501u);
}

TEST_F(SolanaChainTest, ChainNameIsSolana) {
    EXPECT_EQ(chain_.chainName(), "Solana");
}

// =============================================================================
// Address derivation tests (Base58 of Ed25519 public key)
// =============================================================================

TEST_F(SolanaChainTest, DeriveAddressFrom32ByteKey) {
    // Ed25519 public key is exactly 32 bytes
    PublicKey pubkey;
    pubkey.data.resize(32);
    for (int i = 0; i < 32; ++i) {
        pubkey.data[i] = static_cast<uint8_t>((i * 13 + 5) % 256);
    }

    std::string address = chain_.deriveAddress(pubkey);

    // Solana addresses are Base58-encoded 32-byte keys
    // Resulting in 32-44 character strings
    EXPECT_GE(address.size(), 32u);
    EXPECT_LE(address.size(), 44u);
}

TEST_F(SolanaChainTest, AddressContainsOnlyBase58Chars) {
    PublicKey pubkey;
    pubkey.data.resize(32);
    for (int i = 0; i < 32; ++i) {
        pubkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    std::string address = chain_.deriveAddress(pubkey);
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    const std::string base58Chars =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (char c : address) {
        EXPECT_NE(base58Chars.find(c), std::string::npos)
            << "Invalid Base58 character in address: " << c;
    }
}

TEST_F(SolanaChainTest, DifferentKeysProduceDifferentAddresses) {
    PublicKey pubkey1, pubkey2;
    pubkey1.data.resize(32);
    pubkey2.data.resize(32);
    for (int i = 0; i < 32; ++i) {
        pubkey1.data[i] = static_cast<uint8_t>(i);
        pubkey2.data[i] = static_cast<uint8_t>(i + 100);
    }

    EXPECT_NE(chain_.deriveAddress(pubkey1), chain_.deriveAddress(pubkey2));
}

TEST_F(SolanaChainTest, AllZeroKeyProducesValidAddress) {
    PublicKey pubkey;
    pubkey.data.resize(32, 0x00);

    std::string address = chain_.deriveAddress(pubkey);
    // Should still produce a valid Base58 string
    EXPECT_GE(address.size(), 1u);
    EXPECT_LE(address.size(), 44u);
}

// =============================================================================
// Transaction signing tests (Ed25519)
// =============================================================================

TEST_F(SolanaChainTest, SignTransactionReturnsNonEmpty) {
    // Mock Solana transaction message (simplified)
    std::vector<uint8_t> txData = {
        // Header: num_required_signatures, num_readonly_signed, num_readonly_unsigned
        0x01, 0x00, 0x01,
        // Num accounts: 2
        0x02,
        // Account 1 (signer, 32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        // Account 2 (program, 32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Recent blockhash (32 bytes)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        // Instruction count: 0
        0x00
    };

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    EXPECT_FALSE(signedTx.empty());
}

TEST_F(SolanaChainTest, SignTransactionPrependsSignatureCountAndSignature) {
    // Minimal transaction message
    std::vector<uint8_t> txData(100, 0x42);

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    ASSERT_GE(signedTx.size(), 65u);

    // First byte should be signature count (0x01 for single signer)
    EXPECT_EQ(signedTx[0], 0x01) << "Expected signature count of 1";

    // Next 64 bytes should be the Ed25519 signature
    // Total: 1 (count) + 64 (signature) + original message
    EXPECT_EQ(signedTx.size(), 1u + 64u + txData.size())
        << "Signed tx should be: 1 byte count + 64 byte sig + original message";
}

TEST_F(SolanaChainTest, SignTransactionSignatureIsNonZero) {
    std::vector<uint8_t> txData(50, 0xAB);

    PrivateKey privkey;
    for (int i = 0; i < 32; ++i) {
        privkey.data[i] = static_cast<uint8_t>(i + 1);
    }

    auto signedTx = chain_.signTransaction(txData, privkey);
    ASSERT_GE(signedTx.size(), 65u);

    // Check that the 64-byte signature (bytes 1-64) is not all zeros
    bool sigAllZero = std::all_of(signedTx.begin() + 1,
                                  signedTx.begin() + 65,
                                  [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(sigAllZero) << "Ed25519 signature should not be all zeros";
}
