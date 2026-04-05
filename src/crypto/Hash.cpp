#include "wallet/crypto/Hash.h"

// TODO: Include OpenSSL headers:
// #include <openssl/sha.h>
// #include <openssl/ripemd.h>
// #include <openssl/evp.h>

namespace wallet {
namespace crypto {

std::array<uint8_t, 32> Hash::sha256(const std::vector<uint8_t>& data) {
    // TODO: Implement using OpenSSL SHA256().
    (void)data;
    return {};
}

std::array<uint8_t, 64> Hash::sha512(const std::vector<uint8_t>& data) {
    // TODO: Implement using OpenSSL SHA512().
    (void)data;
    return {};
}

std::array<uint8_t, 32> Hash::keccak256(const std::vector<uint8_t>& data) {
    // TODO: Implement Keccak-256 (NOT standard SHA3-256).
    //       OpenSSL 3.x: EVP_MD_fetch(NULL, "KECCAK-256", NULL)
    //       or use a standalone Keccak implementation.
    (void)data;
    return {};
}

std::array<uint8_t, 20> Hash::ripemd160(const std::vector<uint8_t>& data) {
    // TODO: Implement using OpenSSL RIPEMD160().
    (void)data;
    return {};
}

std::array<uint8_t, 32> Hash::doubleSha256(const std::vector<uint8_t>& data) {
    // TODO: return sha256(sha256(data))
    (void)data;
    return {};
}

std::array<uint8_t, 20> Hash::hash160(const std::vector<uint8_t>& data) {
    // TODO: return ripemd160(sha256(data))
    (void)data;
    return {};
}

} // namespace crypto
} // namespace wallet
