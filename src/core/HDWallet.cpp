#include "wallet/core/HDWallet.h"
#include "wallet/core/Mnemonic.h"
#include "wallet/core/KeyPair.h"

namespace wallet {

HDWallet HDWallet::fromMnemonic(const Mnemonic& mnemonic,
                                 const std::string& passphrase) {
    HDWallet wallet;
    // TODO: Derive 64-byte seed from mnemonic using PBKDF2-HMAC-SHA512
    //       with "mnemonic" + passphrase as the salt.
    // TODO: Split seed into master private key (first 32 bytes) and
    //       chain code (last 32 bytes) via HMAC-SHA512("Bitcoin seed", seed).
    wallet.seed_ = mnemonic.toSeed(passphrase);
    return wallet;
}

KeyPair HDWallet::deriveKey(uint32_t coinType,
                             uint32_t account,
                             uint32_t change,
                             uint32_t index) {
    // TODO: Implement BIP-44 derivation path:
    //       m / 44' / coinType' / account' / change / index
    //       using CKDpriv (hardened) and CKDpub (normal) as per BIP-32.
    (void)coinType;
    (void)account;
    (void)change;
    (void)index;
    return KeyPair{};
}

std::string HDWallet::getMasterFingerprint() const {
    // TODO: Compute HASH160 of the master public key, return first 4 bytes
    //       as an 8-character hex string.
    return "00000000";
}

} // namespace wallet
