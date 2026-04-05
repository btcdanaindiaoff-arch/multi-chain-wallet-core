#include "wallet/utils/Base58.h"

namespace wallet {
namespace utils {

std::string Base58::encode(const std::vector<uint8_t>& data) {
    // TODO: Implement Base58 encoding using the Bitcoin alphabet:
    //       123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    (void)data;
    return "";
}

std::vector<uint8_t> Base58::decode(const std::string& encoded) {
    // TODO: Implement Base58 decoding.
    (void)encoded;
    return {};
}

std::string Base58::encodeCheck(const std::vector<uint8_t>& data) {
    // TODO: Append first 4 bytes of doubleSha256(data) as checksum,
    //       then Base58 encode.
    (void)data;
    return "";
}

std::vector<uint8_t> Base58::decodeCheck(const std::string& encoded) {
    // TODO: Base58 decode, verify last 4 bytes are valid checksum.
    (void)encoded;
    return {};
}

} // namespace utils
} // namespace wallet
