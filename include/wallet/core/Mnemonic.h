#pragma once
#ifndef WALLET_CORE_MNEMONIC_H
#define WALLET_CORE_MNEMONIC_H

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {

/// @brief BIP-39 mnemonic phrase generator and validator.
///
/// Supports 12, 15, 18, 21, and 24 word mnemonics drawn from the
/// English wordlist defined in BIP-39.
class Mnemonic {
public:
    /// Generate a new random mnemonic.
    /// @param wordCount  Number of words (12, 15, 18, 21, or 24). Default 24.
    /// @return A valid Mnemonic instance.
    static Mnemonic generate(int wordCount = 24);

    /// Validate whether a space-separated mnemonic string is well-formed
    /// and passes the BIP-39 checksum verification.
    /// @param words  Space-separated mnemonic phrase.
    /// @return true if valid, false otherwise.
    static bool validate(const std::string& words);

    /// Serialise the mnemonic as a single space-separated string.
    std::string toString() const;

    /// Derive a 64-byte seed from the mnemonic using PBKDF2-HMAC-SHA512.
    /// @param passphrase  Optional passphrase (empty string if none).
    /// @return 64-byte seed suitable for HD key derivation.
    std::vector<uint8_t> toSeed(const std::string& passphrase = "") const;

private:
    std::vector<std::string> words_;  ///< Individual mnemonic words.
};

} // namespace wallet

#endif // WALLET_CORE_MNEMONIC_H
