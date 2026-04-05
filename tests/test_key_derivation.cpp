#include <gtest/gtest.h>
#include "wallet/core/HDWallet.h"
#include "wallet/core/Mnemonic.h"
#include "wallet/core/KeyPair.h"

using namespace wallet;

// TODO: Replace placeholder tests with BIP-32/44 test vectors.

TEST(KeyDerivationTest, DeriveEthereumKey) {
    // BIP-44 path: m/44'/60'/0'/0/0
    Mnemonic m = Mnemonic::generate(24);
    HDWallet wallet = HDWallet::fromMnemonic(m);
    KeyPair kp = wallet.deriveKey(60, 0, 0, 0);
    // TODO: Verify derived key matches expected test vector.
    (void)kp;
}

TEST(KeyDerivationTest, DeriveBitcoinKey) {
    // BIP-44 path: m/44'/0'/0'/0/0
    Mnemonic m = Mnemonic::generate(24);
    HDWallet wallet = HDWallet::fromMnemonic(m);
    KeyPair kp = wallet.deriveKey(0, 0, 0, 0);
    (void)kp;
}

TEST(KeyDerivationTest, DeriveSolanaKey) {
    // BIP-44 path: m/44'/501'/0'/0/0
    Mnemonic m = Mnemonic::generate(24);
    HDWallet wallet = HDWallet::fromMnemonic(m);
    KeyPair kp = wallet.deriveKey(501, 0, 0, 0);
    (void)kp;
}

TEST(KeyDerivationTest, MasterFingerprintNotEmpty) {
    Mnemonic m = Mnemonic::generate(24);
    HDWallet wallet = HDWallet::fromMnemonic(m);
    std::string fp = wallet.getMasterFingerprint();
    EXPECT_EQ(fp.size(), 8u); // 4 bytes = 8 hex chars
}
