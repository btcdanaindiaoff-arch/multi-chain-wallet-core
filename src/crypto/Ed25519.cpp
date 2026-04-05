#include "wallet/crypto/Ed25519.h"

namespace wallet {
namespace crypto {

std::array<uint8_t, 64> Ed25519::sign(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 32>& seed) {
    // TODO: Implement Ed25519 signing (use libsodium or OpenSSL 3.x EVP_PKEY).
    (void)message;
    (void)seed;
    return {};
}

bool Ed25519::verify(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 64>& signature,
    const std::array<uint8_t, 32>& publicKey) {
    // TODO: Verify Ed25519 signature.
    (void)message;
    (void)signature;
    (void)publicKey;
    return false;
}

std::array<uint8_t, 32> Ed25519::publicKeyFromSeed(
    const std::array<uint8_t, 32>& seed) {
    // TODO: Derive Ed25519 public key from seed.
    (void)seed;
    return {};
}

} // namespace crypto
} // namespace wallet
