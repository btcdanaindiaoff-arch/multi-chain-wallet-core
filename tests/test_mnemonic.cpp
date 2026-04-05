#include <gtest/gtest.h>
#include "wallet/core/Mnemonic.h"

using namespace wallet;

// TODO: Replace placeholder tests with real BIP-39 test vectors.

TEST(MnemonicTest, GenerateDefaultWordCount) {
    // TODO: Verify generate() produces a 24-word mnemonic.
    Mnemonic m = Mnemonic::generate(24);
    EXPECT_FALSE(m.toString().empty());
}

TEST(MnemonicTest, GenerateTwelveWords) {
    // TODO: Verify generate(12) produces a 12-word mnemonic.
    Mnemonic m = Mnemonic::generate(12);
    EXPECT_FALSE(m.toString().empty());
}

TEST(MnemonicTest, ValidateKnownMnemonic) {
    // TODO: Test with a known-valid BIP-39 test vector.
    std::string testMnemonic = "abandon abandon abandon abandon abandon "
                               "abandon abandon abandon abandon abandon "
                               "abandon about";
    // Once implemented, this should return true:
    // EXPECT_TRUE(Mnemonic::validate(testMnemonic));
    (void)testMnemonic;
}

TEST(MnemonicTest, ValidateInvalidMnemonic) {
    EXPECT_FALSE(Mnemonic::validate("not a valid mnemonic phrase"));
}

TEST(MnemonicTest, ToSeedProduces64Bytes) {
    Mnemonic m = Mnemonic::generate(24);
    auto seed = m.toSeed("");
    EXPECT_EQ(seed.size(), 64u);
}
