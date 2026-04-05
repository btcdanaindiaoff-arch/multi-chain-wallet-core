#pragma once
#ifndef WALLET_CORE_HDWALLET_H
#define WALLET_CORE_HDWALLET_H

#include <cstdint>
#include <string>
#include <vector>

// Forward declarations
namespace wallet {
class Mnemonic;
struct KeyPair;
} // namespace wallet

namespace wallet {

/// @brief Hierarchical Deterministic wallet implementing BIP-32/BIP-44.
///
/// Derives child keys from a master seed produced by a BIP-39 mnemonic.
class HDWallet {
public:
    /// Construct an HDWallet from a validated mnemonic and optional passphrase.
    /// @param mnemonic  A valid BIP-39 mnemonic.
    /// @param passphrase  Optional passphrase for additional entropy.
    /// @return Fully initialised HDWallet instance.
    static HDWallet fromMnemonic(const Mnemonic& mnemonic,
                                 const std::string& passphrase = "");

    /// Derive a key pair following the BIP-44 path:
    ///   m / purpose' / coinType' / account' / change / index
    /// @param coinType  SLIP-44 coin type (e.g. 60 for Ethereum, 0 for Bitcoin).
    /// @param account   Account index (hardened).
    /// @param change    0 = external (receiving), 1 = internal (change).
    /// @param index     Address index.
    /// @return Derived KeyPair containing private and public keys.
    KeyPair deriveKey(uint32_t coinType,
                      uint32_t account,
                      uint32_t change,
                      uint32_t index);

    /// Return the master key fingerprint as a hex string (first 4 bytes of
    /// the HASH160 of the master public key).
    std::string getMasterFingerprint() const;

private:
    HDWallet() = default;

    std::vector<uint8_t> seed_;       ///< 64-byte BIP-39 seed.
    std::vector<uint8_t> masterKey_;  ///< 32-byte master private key.
};

} // namespace wallet

#endif // WALLET_CORE_HDWALLET_H
