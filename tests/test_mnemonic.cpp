// =============================================================================
// test_mnemonic.cpp - Comprehensive BIP-39 mnemonic tests
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/core/Mnemonic.h>

#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <stdexcept>

using namespace wallet;

// =============================================================================
// Generation tests
// =============================================================================

TEST(MnemonicTest, Generate24ProducesExactly24Words) {
    Mnemonic m = Mnemonic::generate(24);
    std::string words = m.toString();
    EXPECT_FALSE(words.empty());

    // Count words by splitting on spaces
    std::istringstream iss(words);
    std::string word;
    int count = 0;
    while (iss >> word) {
        ++count;
    }
    EXPECT_EQ(count, 24);
}

TEST(MnemonicTest, Generate12ProducesExactly12Words) {
    Mnemonic m = Mnemonic::generate(12);
    std::string words = m.toString();
    EXPECT_FALSE(words.empty());

    std::istringstream iss(words);
    std::string word;
    int count = 0;
    while (iss >> word) {
        ++count;
    }
    EXPECT_EQ(count, 12);
}

TEST(MnemonicTest, InvalidWordCountThrows) {
    // BIP-39 only supports 12, 15, 18, 21, 24 words
    EXPECT_THROW(Mnemonic::generate(13), std::invalid_argument);
    EXPECT_THROW(Mnemonic::generate(0), std::invalid_argument);
    EXPECT_THROW(Mnemonic::generate(7), std::invalid_argument);
}

// =============================================================================
// Seed derivation tests
// =============================================================================

TEST(MnemonicTest, ToSeedProduces64Bytes) {
    Mnemonic m = Mnemonic::generate(24);
    auto seed = m.toSeed("");
    EXPECT_EQ(seed.size(), 64u);
}

TEST(MnemonicTest, ToSeedWithPassphraseProduces64Bytes) {
    Mnemonic m = Mnemonic::generate(12);
    auto seed = m.toSeed("my_passphrase");
    EXPECT_EQ(seed.size(), 64u);
}

TEST(MnemonicTest, DifferentPassphrasesProduceDifferentSeeds) {
    Mnemonic m = Mnemonic::generate(24);
    auto seed1 = m.toSeed("");
    auto seed2 = m.toSeed("password123");
    EXPECT_NE(seed1, seed2);
}

// =============================================================================
// Validation tests
// =============================================================================

TEST(MnemonicTest, ValidateReturnsFalseForInvalidInput) {
    EXPECT_FALSE(Mnemonic::validate("invalid words that are not in bip39 wordlist"));
    EXPECT_FALSE(Mnemonic::validate(""));
    EXPECT_FALSE(Mnemonic::validate("hello world"));
}

TEST(MnemonicTest, ValidateReturnsTrueForGeneratedMnemonic) {
    Mnemonic m = Mnemonic::generate(24);
    EXPECT_TRUE(Mnemonic::validate(m.toString()));
}

// =============================================================================
// Round-trip tests
// =============================================================================

TEST(MnemonicTest, ToStringRoundTrip) {
    Mnemonic m = Mnemonic::generate(12);
    std::string words = m.toString();
    // Validate that the generated words pass validation
    EXPECT_TRUE(Mnemonic::validate(words));
}

TEST(MnemonicTest, GeneratedWordsAreNotEmpty) {
    Mnemonic m = Mnemonic::generate(24);
    std::string words = m.toString();
    std::istringstream iss(words);
    std::string word;
    while (iss >> word) {
        EXPECT_FALSE(word.empty());
        // Each word should contain only lowercase letters
        for (char c : word) {
            EXPECT_TRUE(std::isalpha(c));
        }
    }
}
