#include "wallet/crypto/ECDSA.h"

namespace wallet {
namespace crypto {

std::vector<uint8_t> ECDSA::sign(
    const std::array<uint8_t, 32>& hash,
    const std::array<uint8_t, 32>& privateKey) {
    // TODO: Use OpenSSL EC_KEY with NID_secp256k1 to sign the hash.
    //       Return DER-encoded ECDSA signature.
    (void)hash;
    (void)privateKey;
    return {};
}

bool ECDSA::verify(
    const std::array<uint8_t, 32>& hash,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& publicKey) {
    // TODO: Use OpenSSL to verify DER-encoded signature against hash
    //       using the given public key on secp256k1.
    (void)hash;
    (void)signature;
    (void)publicKey;
    return false;
}

std::vector<uint8_t> ECDSA::publicKeyFromPrivate(
    const std::array<uint8_t, 32>& privateKey) {
    // TODO: Use OpenSSL EC_POINT_mul to derive the compressed public key
    //       (33 bytes) from the private scalar.
    (void)privateKey;
    return std::vector<uint8_t>(33, 0);
}

} // namespace crypto
} // namespace wallet
