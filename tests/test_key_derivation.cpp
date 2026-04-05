// =============================================================================
// test_key_derivation.cpp - Comprehensive BIP-32/44 HD wallet tests
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/core/HDWallet.h>
#include <wallet/core/Mnemonic.h>
#include <wallet/core/KeyPair.h>

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

using namespace wallet;

class HDWalletTest : public ::testing::Test {
protected:
    void SetUp() override {
        mnemonic_ = Mnemonic::generate(24);
        wallet_ = HDWallet::fromMnemonic(mnemonic_, "");
    }

    Mnemonic mnemonic_ = Mnemonic::generate(24);
    HDWallet wallet_ = HDWallet::fromMnemonic(mnemonic_, "");
};

// =============================================================================
// Wallet creation tests
// =============================================================================

TEST_F(HDWalletTest, FromMnemonicSucceeds) {
    // If we got here, fromMnemonic did not throw
    SUCCEED();
}

TEST_F(HDWalletTest, FromMnemonicWithPassphrase) {
    HDWallet walletWithPass = HDWallet::fromMnemonic(mnemonic_, "test_passphrase");
    // Should succeed without throwing
    SUCCEED();
}

// =============================================================================
// Key derivation tests
// =============================================================================

TEST_F(HDWalletTest, DeriveKeyEthereumReturnsNonZeroPrivateKey) {
    // BIP-44: m/44'/60'/0'/0/0
    KeyPair kp = wallet_.deriveKey(60, 0, 0, 0);
    // Private key should not be all zeros
    bool allZero = std::all_of(kp.privateKey.data.begin(),
                               kp.privateKey.data.end(),
                               [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(allZero);
}

TEST_F(HDWalletTest, DeriveKeyBitcoinReturnsNonZeroPrivateKey) {
    // BIP-44: m/44'/0'/0'/0/0
    KeyPair kp = wallet_.deriveKey(0, 0, 0, 0);
    bool allZero = std::all_of(kp.privateKey.data.begin(),
                               kp.privateKey.data.end(),
                               [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(allZero);
}

TEST_F(HDWalletTest, DeriveKeySolanaReturnsNonZeroPrivateKey) {
    // BIP-44: m/44'/501'/0'/0/0
    KeyPair kp = wallet_.deriveKey(501, 0, 0, 0);
    bool allZero = std::all_of(kp.privateKey.data.begin(),
                               kp.privateKey.data.end(),
                               [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(allZero);
}

TEST_F(HDWalletTest, DifferentCoinTypesProduceDifferentKeys) {
    KeyPair ethKey = wallet_.deriveKey(60, 0, 0, 0);
    KeyPair btcKey = wallet_.deriveKey(0, 0, 0, 0);
    KeyPair solKey = wallet_.deriveKey(501, 0, 0, 0);

    EXPECT_NE(ethKey.privateKey.data, btcKey.privateKey.data);
    EXPECT_NE(ethKey.privateKey.data, solKey.privateKey.data);
    EXPECT_NE(btcKey.privateKey.data, solKey.privateKey.data);
}

TEST_F(HDWalletTest, DifferentAccountsProduceDifferentKeys) {
    KeyPair account0 = wallet_.deriveKey(60, 0, 0, 0);
    KeyPair account1 = wallet_.deriveKey(60, 1, 0, 0);
    EXPECT_NE(account0.privateKey.data, account1.privateKey.data);
}

TEST_F(HDWalletTest, DifferentIndicesProduceDifferentKeys) {
    KeyPair index0 = wallet_.deriveKey(60, 0, 0, 0);
    KeyPair index1 = wallet_.deriveKey(60, 0, 0, 1);
    EXPECT_NE(index0.privateKey.data, index1.privateKey.data);
}

// =============================================================================
// Master fingerprint tests
// =============================================================================

TEST_F(HDWalletTest, MasterFingerprintIs8HexChars) {
    std::string fp = wallet_.getMasterFingerprint();
    EXPECT_EQ(fp.size(), 8u);
    // All characters should be valid hex digits
    for (char c : fp) {
        EXPECT_TRUE(std::isxdigit(c)) << "Non-hex char in fingerprint: " << c;
    }
}

TEST_F(HDWalletTest, SameMnemonicProducesSameFingerprint) {
    HDWallet wallet2 = HDWallet::fromMnemonic(mnemonic_, "");
    EXPECT_EQ(wallet_.getMasterFingerprint(), wallet2.getMasterFingerprint());
}

TEST_F(HDWalletTest, DifferentPassphraseProducesDifferentFingerprint) {
    HDWallet walletWithPass = HDWallet::fromMnemonic(mnemonic_, "different");
    EXPECT_NE(wallet_.getMasterFingerprint(), walletWithPass.getMasterFingerprint());
}

// =============================================================================
// Determinism tests
// =============================================================================

TEST_F(HDWalletTest, SameMnemonicAndPathProduceConsistentKeys) {
    KeyPair kp1 = wallet_.deriveKey(60, 0, 0, 0);
    KeyPair kp2 = wallet_.deriveKey(60, 0, 0, 0);
    EXPECT_EQ(kp1.privateKey.data, kp2.privateKey.data);
    EXPECT_EQ(kp1.publicKey.data, kp2.publicKey.data);
}
