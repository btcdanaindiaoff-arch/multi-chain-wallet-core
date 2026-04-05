// src/core/HDWallet.cpp
// BIP-32 Hierarchical Deterministic wallet with BIP-44 path derivation.
//
// - fromMnemonic(): seed -> HMAC-SHA512("Bitcoin seed", seed) -> master key + chain code
// - deriveKey(): CKDpriv for hardened and normal child key derivation
// - getMasterFingerprint(): HASH160(masterPubKey)[0..3] as hex

#include "wallet/core/HDWallet.h"
#include "wallet/core/Mnemonic.h"
#include "wallet/core/KeyPair.h"
#include "wallet/crypto/Hash.h"
#include "wallet/utils/Hex.h"

#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <cstring>
#include <stdexcept>

namespace {

// HMAC-SHA512 helper
static std::vector<uint8_t> hmacSha512(const uint8_t* key, size_t keyLen,
                                        const uint8_t* data, size_t dataLen) {
    std::vector<uint8_t> result(64);
    unsigned int len = 64;
    if (!HMAC(EVP_sha512(), key, static_cast<int>(keyLen),
              data, dataLen, result.data(), &len)) {
        throw std::runtime_error("HMAC-SHA512 failed");
    }
    result.resize(len);
    return result;
}

// Derive compressed public key (33 bytes) from 32-byte private key via secp256k1
static std::vector<uint8_t> deriveCompressedPubKey(const uint8_t* privKey32) {
    std::vector<uint8_t> pubKey(33);

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) throw std::runtime_error("Failed to create EC_KEY");

    BIGNUM* privBN = BN_bin2bn(privKey32, 32, nullptr);
    if (!privBN) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to create BIGNUM from private key");
    }

    if (!EC_KEY_set_private_key(ecKey, privBN)) {
        BN_free(privBN);
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to set private key");
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pubPoint = EC_POINT_new(group);
    if (!pubPoint) {
        BN_free(privBN);
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to create EC_POINT");
    }

    if (!EC_POINT_mul(group, pubPoint, privBN, nullptr, nullptr, nullptr)) {
        EC_POINT_free(pubPoint);
        BN_free(privBN);
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to compute public key point");
    }

    EC_KEY_set_public_key(ecKey, pubPoint);
    EC_KEY_set_conv_form(ecKey, POINT_CONVERSION_COMPRESSED);

    size_t len = EC_POINT_point2oct(group, pubPoint,
                                     POINT_CONVERSION_COMPRESSED,
                                     pubKey.data(), 33, nullptr);
    if (len != 33) {
        EC_POINT_free(pubPoint);
        BN_free(privBN);
        EC_KEY_free(ecKey);
        throw std::runtime_error("Failed to serialize compressed public key");
    }

    EC_POINT_free(pubPoint);
    BN_free(privBN);
    EC_KEY_free(ecKey);

    return pubKey;
}

// BIP-32 Child Key Derivation (private -> private)
// Returns 64 bytes: [0..31] = child key, [32..63] = child chain code
static std::vector<uint8_t> ckdPriv(const uint8_t* parentKey,
                                     const uint8_t* parentChainCode,
                                     uint32_t index) {
    std::vector<uint8_t> data;

    bool hardened = (index >= 0x80000000u);
    if (hardened) {
        // Hardened child: data = 0x00 || ser256(parentKey) || ser32(index)
        data.push_back(0x00);
        data.insert(data.end(), parentKey, parentKey + 32);
    } else {
        // Normal child: data = serP(point(parentKey)) || ser32(index)
        auto pubKey = deriveCompressedPubKey(parentKey);
        data.insert(data.end(), pubKey.begin(), pubKey.end());
    }

    // Append index in big-endian (ser32)
    data.push_back(static_cast<uint8_t>((index >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((index >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((index >>  8) & 0xFF));
    data.push_back(static_cast<uint8_t>( index        & 0xFF));

    // I = HMAC-SHA512(Key = parentChainCode, Data = data)
    auto I = hmacSha512(parentChainCode, 32, data.data(), data.size());

    // IL = I[0..31], IR = I[32..63]
    // childKey = (parse256(IL) + parentKey) mod n
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);

    BIGNUM* ilBN = BN_bin2bn(I.data(), 32, nullptr);
    BIGNUM* parentBN = BN_bin2bn(parentKey, 32, nullptr);
    BIGNUM* childBN = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_mod_add(childBN, ilBN, parentBN, order, ctx);

    // Serialize child key to 32 bytes (zero-padded from left)
    std::vector<uint8_t> result(64);
    int keyLen = BN_num_bytes(childBN);
    if (keyLen > 32) {
        BN_CTX_free(ctx); BN_free(childBN); BN_free(parentBN);
        BN_free(ilBN); BN_free(order); EC_GROUP_free(group);
        throw std::runtime_error("Child key derivation overflow");
    }
    std::memset(result.data(), 0, 32);
    BN_bn2bin(childBN, result.data() + (32 - keyLen));

    // Child chain code = IR = I[32..63]
    std::memcpy(result.data() + 32, I.data() + 32, 32);

    BN_CTX_free(ctx);
    BN_free(childBN);
    BN_free(parentBN);
    BN_free(ilBN);
    BN_free(order);
    EC_GROUP_free(group);

    return result;
}

} // anonymous namespace

namespace wallet {

HDWallet HDWallet::fromMnemonic(const Mnemonic& mnemonic,
                                 const std::string& passphrase) {
    HDWallet wallet;

    // Step 1: Derive 64-byte seed from mnemonic via BIP-39 PBKDF2
    wallet.seed_ = mnemonic.toSeed(passphrase);

    // Step 2: Master key generation per BIP-32
    // I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
    const std::string hmacKey = "Bitcoin seed";
    auto I = hmacSha512(
        reinterpret_cast<const uint8_t*>(hmacKey.c_str()),
        hmacKey.size(),
        wallet.seed_.data(),
        wallet.seed_.size());

    // IL = master secret key (32 bytes)
    // IR = master chain code (32 bytes)
    wallet.masterKey_.assign(I.begin(), I.begin() + 32);
    wallet.chainCode_.assign(I.begin() + 32, I.end());

    return wallet;
}

KeyPair HDWallet::deriveKey(uint32_t coinType,
                             uint32_t account,
                             uint32_t change,
                             uint32_t index) {
    // BIP-44 path: m / 44' / coinType' / account' / change / index
    // Hardened indices have bit 31 set (0x80000000)
    const uint32_t purpose = 44u | 0x80000000u;
    const uint32_t coinH   = coinType | 0x80000000u;
    const uint32_t acctH   = account  | 0x80000000u;
    // change and index are NOT hardened in BIP-44

    // Start from master key and chain code
    std::vector<uint8_t> currentKey(masterKey_);
    std::vector<uint8_t> currentChain(chainCode_);

    // Derive each level of the BIP-44 path
    uint32_t path[] = { purpose, coinH, acctH, change, index };
    for (uint32_t idx : path) {
        auto derived = ckdPriv(currentKey.data(), currentChain.data(), idx);
        currentKey.assign(derived.begin(), derived.begin() + 32);
        currentChain.assign(derived.begin() + 32, derived.end());
    }

    // Build KeyPair from derived child key
    KeyPair kp;
    std::memcpy(kp.privateKey.data.data(), currentKey.data(), 32);

    // Derive compressed public key from the child private key
    auto pubKey = deriveCompressedPubKey(currentKey.data());
    kp.publicKey.data = std::move(pubKey);

    return kp;
}

std::string HDWallet::getMasterFingerprint() const {
    // BIP-32 fingerprint = first 4 bytes of HASH160(masterPublicKey)
    // HASH160 = RIPEMD160(SHA256(pubkey))
    auto pubKey = deriveCompressedPubKey(masterKey_.data());
    std::vector<uint8_t> pubVec(pubKey.begin(), pubKey.end());
    auto h160 = crypto::Hash::hash160(pubVec);

    // Return first 4 bytes as lowercase hex string
    std::vector<uint8_t> fingerprint(h160.begin(), h160.begin() + 4);
    return utils::Hex::encode(fingerprint);
}

} // namespace wallet
