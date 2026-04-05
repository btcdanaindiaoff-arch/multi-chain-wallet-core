// ==========================================================================
// Ed25519.cpp -- Ed25519 sign / verify / pubkey derivation (OpenSSL 3.x EVP)
// ==========================================================================
#include "wallet/crypto/Ed25519.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

namespace wallet {
namespace crypto {

namespace {

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

struct EVP_MD_CTX_Deleter {
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

// Create an EVP_PKEY from a 32-byte Ed25519 private seed.
EVP_PKEY_ptr keyFromSeed(const std::array<uint8_t, 32>& seed) {
    EVP_PKEY* raw = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (!raw)
        throw std::runtime_error("Ed25519: EVP_PKEY_new_raw_private_key failed");
    return EVP_PKEY_ptr(raw);
}

// Create an EVP_PKEY from a 32-byte Ed25519 public key.
EVP_PKEY_ptr keyFromPub(const std::array<uint8_t, 32>& pub) {
    EVP_PKEY* raw = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!raw)
        throw std::runtime_error("Ed25519: EVP_PKEY_new_raw_public_key failed");
    return EVP_PKEY_ptr(raw);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// sign()  --  produce a 64-byte Ed25519 signature
// ---------------------------------------------------------------------------
std::array<uint8_t, 64> Ed25519::sign(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& seed)
{
    auto pkey = keyFromSeed(seed);
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx)
        throw std::runtime_error("Ed25519::sign: EVP_MD_CTX_new failed");

    // Ed25519 uses a single-shot DigestSign (md == nullptr)
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
        throw std::runtime_error("Ed25519::sign: DigestSignInit failed");

    // Determine signature length first
    size_t sigLen = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sigLen,
                       message.data(), message.size()) != 1)
        throw std::runtime_error("Ed25519::sign: DigestSign (len query) failed");

    std::array<uint8_t, 64> sig{};
    sigLen = 64;
    if (EVP_DigestSign(ctx.get(), sig.data(), &sigLen,
                       message.data(), message.size()) != 1)
        throw std::runtime_error("Ed25519::sign: DigestSign failed");

    return sig;
}

// ---------------------------------------------------------------------------
// verify()  --  verify an Ed25519 signature
// ---------------------------------------------------------------------------
bool Ed25519::verify(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 64>& signature,
    const std::array<uint8_t, 32>& publicKey)
{
    auto pkey = keyFromPub(publicKey);
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
        return false;

    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                            message.data(), message.size()) == 1;
}

// ---------------------------------------------------------------------------
// publicKeyFromSeed()  --  extract the 32-byte public key from a seed
// ---------------------------------------------------------------------------
std::array<uint8_t, 32> Ed25519::publicKeyFromSeed(
    const std::array<uint8_t, 32>& seed)
{
    auto pkey = keyFromSeed(seed);

    std::array<uint8_t, 32> pub{};
    size_t pubLen = 32;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pubLen) != 1)
        throw std::runtime_error("Ed25519::publicKeyFromSeed: get_raw_public_key failed");

    return pub;
}

} // namespace crypto
} // namespace wallet
