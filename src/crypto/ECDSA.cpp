// ==========================================================================
// ECDSA.cpp -- secp256k1 ECDSA sign / verify / pubkey derivation (OpenSSL)
// ==========================================================================
#include "wallet/crypto/ECDSA.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <cstring>

namespace wallet {
namespace crypto {

// ---------------------------------------------------------------------------
// Helper RAII wrappers
// ---------------------------------------------------------------------------
namespace {

struct BN_CTX_Deleter   { void operator()(BN_CTX*   p) const { BN_CTX_free(p);   } };
struct BIGNUM_Deleter   { void operator()(BIGNUM*   p) const { BN_free(p);       } };
struct EC_KEY_Deleter   { void operator()(EC_KEY*   p) const { EC_KEY_free(p);   } };
struct EC_POINT_Deleter { void operator()(EC_POINT* p) const { EC_POINT_free(p); } };
struct ECDSA_SIG_Deleter{ void operator()(ECDSA_SIG* p) const { ECDSA_SIG_free(p); } };

using BN_CTX_ptr    = std::unique_ptr<BN_CTX,    BN_CTX_Deleter>;
using BIGNUM_ptr    = std::unique_ptr<BIGNUM,    BIGNUM_Deleter>;
using EC_KEY_ptr    = std::unique_ptr<EC_KEY,    EC_KEY_Deleter>;
using EC_POINT_ptr  = std::unique_ptr<EC_POINT,  EC_POINT_Deleter>;
using ECDSA_SIG_ptr = std::unique_ptr<ECDSA_SIG, ECDSA_SIG_Deleter>;

EC_KEY_ptr makeKey() {
    EC_KEY* k = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!k) throw std::runtime_error("EC_KEY_new_by_curve_name(secp256k1) failed");
    return EC_KEY_ptr(k);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// sign()  --  DER-encoded ECDSA signature
// ---------------------------------------------------------------------------
std::vector<uint8_t> ECDSA::sign(
    const std::array<uint8_t, 32>& hash,
    const std::array<uint8_t, 32>& privateKey)
{
    auto key = makeKey();

    // Set private key
    BIGNUM_ptr priv(BN_bin2bn(privateKey.data(), 32, nullptr));
    if (!priv || !EC_KEY_set_private_key(key.get(), priv.get()))
        throw std::runtime_error("ECDSA::sign: failed to set private key");

    // Derive and set public key (required by some OpenSSL builds)
    const EC_GROUP* group = EC_KEY_get0_group(key.get());
    BN_CTX_ptr ctx(BN_CTX_new());
    EC_POINT_ptr pub(EC_POINT_new(group));
    if (!EC_POINT_mul(group, pub.get(), priv.get(), nullptr, nullptr, ctx.get()))
        throw std::runtime_error("ECDSA::sign: EC_POINT_mul failed");
    if (!EC_KEY_set_public_key(key.get(), pub.get()))
        throw std::runtime_error("ECDSA::sign: failed to set public key");

    // Sign
    ECDSA_SIG* rawSig = ECDSA_do_sign(hash.data(), 32, key.get());
    if (!rawSig)
        throw std::runtime_error("ECDSA_do_sign failed");
    ECDSA_SIG_ptr sig(rawSig);

    // Serialize to DER
    unsigned char* der = nullptr;
    int derLen = i2d_ECDSA_SIG(sig.get(), &der);
    if (derLen <= 0)
        throw std::runtime_error("i2d_ECDSA_SIG failed");

    std::vector<uint8_t> result(der, der + derLen);
    OPENSSL_free(der);
    return result;
}

// ---------------------------------------------------------------------------
// verify()  --  verify DER-encoded signature against hash + public key
// ---------------------------------------------------------------------------
bool ECDSA::verify(
    const std::array<uint8_t, 32>& hash,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& publicKey)
{
    auto key = makeKey();

    // Set public key from octets (compressed 33 or uncompressed 65 bytes)
    const EC_GROUP* group = EC_KEY_get0_group(key.get());
    BN_CTX_ptr ctx(BN_CTX_new());
    EC_POINT_ptr pt(EC_POINT_new(group));
    if (!EC_POINT_oct2point(group, pt.get(), publicKey.data(),
                            publicKey.size(), ctx.get()))
        return false;
    if (!EC_KEY_set_public_key(key.get(), pt.get()))
        return false;

    // Deserialize DER signature
    const unsigned char* p = signature.data();
    ECDSA_SIG* rawSig = d2i_ECDSA_SIG(nullptr, &p,
                                        static_cast<long>(signature.size()));
    if (!rawSig) return false;
    ECDSA_SIG_ptr sig(rawSig);

    return ECDSA_do_verify(hash.data(), 32, sig.get(), key.get()) == 1;
}

// ---------------------------------------------------------------------------
// publicKeyFromPrivate()  --  derive compressed 33-byte public key
// ---------------------------------------------------------------------------
std::vector<uint8_t> ECDSA::publicKeyFromPrivate(
    const std::array<uint8_t, 32>& privateKey)
{
    auto key = makeKey();
    const EC_GROUP* group = EC_KEY_get0_group(key.get());

    BIGNUM_ptr priv(BN_bin2bn(privateKey.data(), 32, nullptr));
    BN_CTX_ptr ctx(BN_CTX_new());
    EC_POINT_ptr pub(EC_POINT_new(group));

    if (!EC_POINT_mul(group, pub.get(), priv.get(), nullptr, nullptr, ctx.get()))
        throw std::runtime_error("ECDSA::publicKeyFromPrivate: EC_POINT_mul failed");

    // Compressed form = 33 bytes (02/03 prefix + 32-byte X)
    EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
    size_t len = EC_POINT_point2oct(group, pub.get(),
                                     POINT_CONVERSION_COMPRESSED,
                                     nullptr, 0, ctx.get());
    std::vector<uint8_t> result(len);
    EC_POINT_point2oct(group, pub.get(), POINT_CONVERSION_COMPRESSED,
                       result.data(), len, ctx.get());
    return result;
}

} // namespace crypto
} // namespace wallet
