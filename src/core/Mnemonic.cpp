#include "wallet/core/Mnemonic.h"

#include <stdexcept>

namespace wallet {

Mnemonic Mnemonic::generate(int wordCount) {
    // TODO: Generate cryptographically random entropy (wordCount/3*4 bytes),
    //       compute SHA-256 checksum, map to BIP-39 English wordlist.
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 &&
        wordCount != 21 && wordCount != 24) {
        throw std::invalid_argument("Word count must be 12, 15, 18, 21, or 24");
    }
    Mnemonic m;
    // TODO: Fill m.words_ with generated words.
    return m;
}

bool Mnemonic::validate(const std::string& words) {
    // TODO: Split words by space, verify count, verify each word is in the
    //       BIP-39 wordlist, verify checksum bits.
    (void)words;
    return false;
}

std::string Mnemonic::toString() const {
    // TODO: Join words_ with single spaces.
    std::string result;
    for (size_t i = 0; i < words_.size(); ++i) {
        if (i > 0) result += " ";
        result += words_[i];
    }
    return result;
}

std::vector<uint8_t> Mnemonic::toSeed(const std::string& passphrase) const {
    // TODO: PBKDF2-HMAC-SHA512 with password = mnemonic string,
    //       salt = "mnemonic" + passphrase, iterations = 2048, dkLen = 64.
    (void)passphrase;
    return std::vector<uint8_t>(64, 0);
}

} // namespace wallet
