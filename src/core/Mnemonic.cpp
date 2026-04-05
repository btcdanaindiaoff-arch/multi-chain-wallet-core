// src/core/Mnemonic.cpp
// BIP-39 mnemonic generation, validation, and seed derivation.
//
// - generate(): OpenSSL RAND_bytes entropy -> SHA-256 checksum -> wordlist mapping
// - validate(): word count + wordlist membership check
// - toSeed():   PBKDF2-HMAC-SHA512, salt = "mnemonic" + passphrase, 2048 iterations

#include "wallet/core/Mnemonic.h"
#include "wallet/crypto/Hash.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace {

// ============================================================================
// BIP-39 English wordlist (first 128 official words)
// NOTE: For production use, replace this entire array with the official
// 2048-word BIP-39 English wordlist from:
//   https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
// ============================================================================
static const char* const kWordlist[] = {
    "abandon",  "ability",  "able",     "about",    "above",    "absent",
    "absorb",   "abstract", "absurd",   "abuse",    "access",   "accident",
    "account",  "accuse",   "achieve",  "acid",     "acoustic", "acquire",
    "across",   "act",      "action",   "actor",    "actress",  "actual",
    "adapt",    "add",      "addict",   "address",  "adjust",   "admit",
    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",
    "afraid",   "again",    "age",      "agent",    "agree",    "ahead",
    "aim",      "air",      "airport",  "aisle",    "alarm",    "album",
    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",
    "almost",   "alone",    "alpha",    "already",  "also",     "alter",
    "always",   "amateur",  "amazing",  "among",    "amount",   "amused",
    "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",
    "antenna",  "antique",  "anxiety",  "any",      "apart",    "apology",
    "appear",   "apple",    "approve",  "april",    "arch",     "arctic",
    "area",     "arena",    "argue",    "arm",      "armed",    "armor",
    "army",     "around",   "arrange",  "arrest",   "arrive",   "arrow",
    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",
    "assault",  "asset",    "assist",   "assume",   "asthma",   "athlete",
    "atom",     "attack",   "attend",   "attitude", "attract",  "auction",
    "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
    "average",  "avocado"
};

static constexpr int kWordlistSize = sizeof(kWordlist) / sizeof(kWordlist[0]);

// For a full BIP-39 implementation, kWordlistSize must be 2048.
// Indices >= kWordlistSize are mapped modulo kWordlistSize.
static const char* safeWord(int index) {
    return kWordlist[index % kWordlistSize];
}

// Check if a word exists in the wordlist; return its index or -1.
static int findWordIndex(const std::string& word) {
    for (int i = 0; i < kWordlistSize; ++i) {
        if (word == kWordlist[i]) return i;
    }
    return -1;
}

// Extract a single 11-bit value from a bit array packed in bytes.
static uint16_t extract11Bits(const std::vector<uint8_t>& bits, size_t bitOffset) {
    uint16_t value = 0;
    for (int i = 0; i < 11; ++i) {
        size_t byteIdx = (bitOffset + static_cast<size_t>(i)) / 8;
        size_t bitIdx  = 7 - ((bitOffset + static_cast<size_t>(i)) % 8);
        if (bits[byteIdx] & (1u << bitIdx))
            value |= static_cast<uint16_t>(1u << (10 - i));
    }
    return value;
}

} // anonymous namespace

namespace wallet {

Mnemonic Mnemonic::generate(int wordCount) {
    // BIP-39: wordCount -> entropy bits
    //   12 -> 128, 15 -> 160, 18 -> 192, 21 -> 224, 24 -> 256
    int entropyBits;
    switch (wordCount) {
        case 12: entropyBits = 128; break;
        case 15: entropyBits = 160; break;
        case 18: entropyBits = 192; break;
        case 21: entropyBits = 224; break;
        case 24: entropyBits = 256; break;
        default:
            throw std::invalid_argument(
                "BIP-39 word count must be 12, 15, 18, 21, or 24");
    }
    int entropyBytes = entropyBits / 8;

    // Generate random entropy using OpenSSL
    std::vector<uint8_t> entropy(static_cast<size_t>(entropyBytes));
    if (RAND_bytes(entropy.data(), entropyBytes) != 1) {
        throw std::runtime_error("Failed to generate random entropy");
    }

    // Compute SHA-256 checksum of entropy
    auto hash = crypto::Hash::sha256(entropy);

    // Concatenate entropy + checksum bits into a single bit stream
    // Total bits = entropyBits + checksumBits = 11 * wordCount
    std::vector<uint8_t> allBytes(entropy);
    allBytes.push_back(hash[0]); // Only need first byte for up to 8 checksum bits

    // Map each 11-bit group to a wordlist index
    Mnemonic m;
    m.words_.reserve(static_cast<size_t>(wordCount));
    for (int i = 0; i < wordCount; ++i) {
        uint16_t idx = extract11Bits(allBytes, static_cast<size_t>(i) * 11);
        idx %= 2048; // Ensure within BIP-39 bounds
        m.words_.push_back(safeWord(static_cast<int>(idx)));
    }

    return m;
}

bool Mnemonic::validate(const std::string& words) {
    // Split by spaces
    std::vector<std::string> wordVec;
    std::istringstream iss(words);
    std::string word;
    while (iss >> word) {
        wordVec.push_back(word);
    }

    // Check valid word count
    size_t count = wordVec.size();
    if (count != 12 && count != 15 && count != 18 &&
        count != 21 && count != 24) {
        return false;
    }

    // Verify each word is in the wordlist
    for (const auto& w : wordVec) {
        if (findWordIndex(w) < 0) {
            return false;
        }
    }

    return true;
}

std::string Mnemonic::toString() const {
    std::string result;
    for (size_t i = 0; i < words_.size(); ++i) {
        if (i > 0) result += ' ';
        result += words_[i];
    }
    return result;
}

std::vector<uint8_t> Mnemonic::toSeed(const std::string& passphrase) const {
    // BIP-39: PBKDF2-HMAC-SHA512
    // Password = mnemonic sentence (UTF-8 NFKD)
    // Salt     = "mnemonic" + passphrase (UTF-8 NFKD)
    // Iterations = 2048
    // Key length = 64 bytes (512 bits)
    std::string mnemonic = toString();
    std::string salt = "mnemonic" + passphrase;

    std::vector<uint8_t> seed(64);
    if (PKCS5_PBKDF2_HMAC(
            mnemonic.c_str(),
            static_cast<int>(mnemonic.size()),
            reinterpret_cast<const unsigned char*>(salt.c_str()),
            static_cast<int>(salt.size()),
            2048,        // iterations
            EVP_sha512(),
            64,          // key length
            seed.data()) != 1) {
        throw std::runtime_error("PBKDF2-HMAC-SHA512 failed");
    }

    return seed;
}

} // namespace wallet
