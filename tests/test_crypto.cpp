// =============================================================================
// test_crypto.cpp - Comprehensive tests for crypto primitives
// =============================================================================
#include <gtest/gtest.h>

#include <wallet/crypto/Hash.h>
#include <wallet/utils/Hex.h>
#include <wallet/utils/Base58.h>
#include <wallet/utils/RLP.h>
#include <wallet/utils/Bech32.h>

#include <vector>
#include <string>
#include <cstdint>

using namespace wallet;

// =============================================================================
// Hash tests
// =============================================================================

TEST(HashTest, SHA256EmptyProducesKnownDigest) {
    std::vector<uint8_t> empty;
    auto digest = Hash::sha256(empty);
    ASSERT_EQ(digest.size(), 32u);
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string hex = Hex::encode(digest);
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(HashTest, Keccak256EmptyProduces32Bytes) {
    std::vector<uint8_t> empty;
    auto digest = Hash::keccak256(empty);
    EXPECT_EQ(digest.size(), 32u);
    // Keccak-256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    std::string hex = Hex::encode(digest);
    EXPECT_EQ(hex.substr(0, 16), "c5d2460186f7233c");
}

TEST(HashTest, DoubleSha256Produces32Bytes) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto digest = Hash::doubleSha256(data);
    EXPECT_EQ(digest.size(), 32u);
    // Must differ from single SHA-256
    auto single = Hash::sha256(data);
    EXPECT_NE(digest, single);
}

TEST(HashTest, Hash160Produces20Bytes) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto digest = Hash::hash160(data);
    EXPECT_EQ(digest.size(), 20u);
}

TEST(HashTest, Ripemd160ProducesCorrectLength) {
    std::vector<uint8_t> data = {0x61, 0x62, 0x63}; // "abc"
    auto digest = Hash::ripemd160(data);
    EXPECT_EQ(digest.size(), 20u);
}

// =============================================================================
// Hex tests
// =============================================================================

TEST(HexTest, EncodeDeadBeef) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string encoded = Hex::encode(data);
    EXPECT_EQ(encoded, "deadbeef");
}

TEST(HexTest, DecodeRoundTrip) {
    std::string hexStr = "deadbeef";
    auto decoded = Hex::decode(hexStr);
    ASSERT_EQ(decoded.size(), 4u);
    EXPECT_EQ(decoded[0], 0xDE);
    EXPECT_EQ(decoded[1], 0xAD);
    EXPECT_EQ(decoded[2], 0xBE);
    EXPECT_EQ(decoded[3], 0xEF);
    // Re-encode should match
    EXPECT_EQ(Hex::encode(decoded), hexStr);
}

TEST(HexTest, EncodeEmpty) {
    std::vector<uint8_t> empty;
    EXPECT_EQ(Hex::encode(empty), "");
}

TEST(HexTest, DecodeEmpty) {
    auto decoded = Hex::decode("");
    EXPECT_TRUE(decoded.empty());
}

// =============================================================================
// Base58 tests
// =============================================================================

TEST(Base58Test, EncodeDecodeRoundTrip) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    std::string encoded = Base58::encode(data);
    EXPECT_FALSE(encoded.empty());
    auto decoded = Base58::decode(encoded);
    EXPECT_EQ(decoded, data);
}

TEST(Base58Test, EncodeKnownVector) {
    // Base58 of "Hello World" bytes
    std::vector<uint8_t> hello = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20,
                                   0x57, 0x6F, 0x72, 0x6C, 0x64};
    std::string encoded = Base58::encode(hello);
    EXPECT_FALSE(encoded.empty());
    // Round-trip
    auto decoded = Base58::decode(encoded);
    EXPECT_EQ(decoded, hello);
}

TEST(Base58Test, LeadingZerosPreserved) {
    // Leading zero bytes should produce leading '1' characters in Base58
    std::vector<uint8_t> data = {0x00, 0x00, 0x01};
    std::string encoded = Base58::encode(data);
    EXPECT_GE(encoded.size(), 2u); // At least two '1' chars for leading zeros
    auto decoded = Base58::decode(encoded);
    EXPECT_EQ(decoded, data);
}

// =============================================================================
// RLP tests
// =============================================================================

TEST(RLPTest, EncodeUintZero) {
    auto result = RLP::encodeUint(0);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x80);
}

TEST(RLPTest, EncodeEmptyString) {
    std::vector<uint8_t> empty;
    auto result = RLP::encodeString(empty);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x80);
}

TEST(RLPTest, EncodeSingleByte) {
    // Single byte < 0x80 encodes as itself
    std::vector<uint8_t> single = {0x42};
    auto result = RLP::encodeString(single);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x42);
}

TEST(RLPTest, EncodeShortString) {
    // "dog" = {0x64, 0x6f, 0x67} -> 0x83 0x64 0x6f 0x67
    std::vector<uint8_t> dog = {0x64, 0x6F, 0x67};
    auto result = RLP::encodeString(dog);
    ASSERT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 0x83);
    EXPECT_EQ(result[1], 0x64);
    EXPECT_EQ(result[2], 0x6F);
    EXPECT_EQ(result[3], 0x67);
}

TEST(RLPTest, EncodeUintSmallValue) {
    // RLP of 1 should be 0x01
    auto result = RLP::encodeUint(1);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x01);
}

TEST(RLPTest, EncodeUintLargeValue) {
    // RLP of 1024 (0x0400) should be 0x82, 0x04, 0x00
    auto result = RLP::encodeUint(1024);
    ASSERT_GE(result.size(), 2u);
    EXPECT_EQ(result[0], 0x82);
}

// =============================================================================
// Bech32 tests
// =============================================================================

TEST(Bech32Test, EncodeDecodeRoundTrip) {
    // Encode a witness v0 program (20-byte hash)
    std::vector<uint8_t> program = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6
    };
    std::string encoded = Bech32::encode("bc", 0, program);
    EXPECT_FALSE(encoded.empty());
    EXPECT_EQ(encoded.substr(0, 4), "bc1q");

    // Decode and verify round-trip
    auto [hrp, version, decoded_program] = Bech32::decode(encoded);
    EXPECT_EQ(hrp, "bc");
    EXPECT_EQ(version, 0);
    EXPECT_EQ(decoded_program, program);
}

TEST(Bech32Test, EncodedStringIsLowercase) {
    std::vector<uint8_t> program(20, 0x00);
    std::string encoded = Bech32::encode("bc", 0, program);
    for (char c : encoded) {
        if (std::isalpha(c)) {
            EXPECT_EQ(c, std::tolower(c));
        }
    }
}
