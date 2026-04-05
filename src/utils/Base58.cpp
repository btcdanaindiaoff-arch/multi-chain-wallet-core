// src/utils/Base58.cpp
// Full Base58 and Base58Check encoding/decoding using Bitcoin alphabet.

#include "wallet/utils/Base58.h"
#include "wallet/crypto/Hash.h"

#include <algorithm>
#include <stdexcept>

namespace {

// Bitcoin Base58 alphabet
static constexpr char kAlphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Reverse lookup table: ASCII char -> Base58 digit value (255 = invalid)
static constexpr uint8_t kAlphabetMap[] = {
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255, 255,255,255,255,255,255,255,255,
    255,  0,  1,  2,  3,  4,  5,  6,   7,  8,255,255,255,255,255,255,
    255,  9, 10, 11, 12, 13, 14, 15,  16,255, 17, 18, 19, 20, 21,255,
     22, 23, 24, 25, 26, 27, 28, 29,  30, 31, 32,255,255,255,255,255,
    255, 33, 34, 35, 36, 37, 38, 39,  40, 41, 42, 43,255, 44, 45, 46,
     47, 48, 49, 50, 51, 52, 53, 54,  55, 56, 57,255,255,255,255,255
};

} // anonymous namespace

namespace wallet {
namespace utils {

std::string Base58::encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    // Count leading zero bytes -> they become '1' characters
    size_t leadingZeros = 0;
    for (size_t i = 0; i < data.size() && data[i] == 0; ++i)
        ++leadingZeros;

    // Allocate enough space: log(256)/log(58) ~ 1.366
    size_t maxLen = data.size() * 138 / 100 + 1;
    std::vector<uint8_t> b58(maxLen, 0);

    // Process each input byte through base conversion
    for (size_t i = 0; i < data.size(); ++i) {
        int carry = static_cast<int>(data[i]);
        for (size_t j = maxLen; j-- > 0;) {
            carry += 256 * static_cast<int>(b58[j]);
            b58[j] = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
    }

    // Skip leading zeros in the base58 result
    size_t start = 0;
    while (start < maxLen && b58[start] == 0)
        ++start;

    // Build result string
    std::string result;
    result.reserve(leadingZeros + (maxLen - start));
    result.append(leadingZeros, '1');
    for (size_t i = start; i < maxLen; ++i)
        result.push_back(kAlphabet[b58[i]]);

    return result;
}

std::vector<uint8_t> Base58::decode(const std::string& encoded) {
    if (encoded.empty()) return {};

    // Count leading '1' characters -> they map to 0x00 bytes
    size_t leadingOnes = 0;
    for (size_t i = 0; i < encoded.size() && encoded[i] == '1'; ++i)
        ++leadingOnes;

    // Allocate enough space: log(58)/log(256) ~ 0.733
    size_t maxLen = encoded.size() * 733 / 1000 + 1;
    std::vector<uint8_t> b256(maxLen, 0);

    for (size_t i = 0; i < encoded.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(encoded[i]);
        if (ch >= sizeof(kAlphabetMap) || kAlphabetMap[ch] == 255) {
            throw std::invalid_argument(
                std::string("Invalid Base58 character: ") + encoded[i]);
        }
        int carry = kAlphabetMap[ch];
        for (size_t j = maxLen; j-- > 0;) {
            carry += 58 * static_cast<int>(b256[j]);
            b256[j] = static_cast<uint8_t>(carry % 256);
            carry /= 256;
        }
    }

    // Skip leading zeros in the byte result
    size_t start = 0;
    while (start < maxLen && b256[start] == 0)
        ++start;

    // Build output with leading zero bytes preserved
    std::vector<uint8_t> result;
    result.reserve(leadingOnes + (maxLen - start));
    result.insert(result.end(), leadingOnes, 0x00);
    result.insert(result.end(), b256.begin() + static_cast<long>(start), b256.end());

    return result;
}

std::string Base58::encodeCheck(const std::vector<uint8_t>& data) {
    // Compute 4-byte checksum = first 4 bytes of doubleSha256(data)
    auto hash = wallet::crypto::Hash::doubleSha256(data);

    // Append checksum to data
    std::vector<uint8_t> dataWithChecksum(data);
    dataWithChecksum.insert(dataWithChecksum.end(),
                            hash.begin(), hash.begin() + 4);

    return encode(dataWithChecksum);
}

std::vector<uint8_t> Base58::decodeCheck(const std::string& encoded) {
    std::vector<uint8_t> decoded = decode(encoded);

    if (decoded.size() < 4) {
        throw std::runtime_error("Base58Check: input too short for checksum");
    }

    // Split payload and checksum
    std::vector<uint8_t> payload(decoded.begin(),
                                 decoded.end() - 4);
    std::vector<uint8_t> checksum(decoded.end() - 4,
                                  decoded.end());

    // Verify checksum
    auto hash = wallet::crypto::Hash::doubleSha256(payload);
    for (int i = 0; i < 4; ++i) {
        if (checksum[static_cast<size_t>(i)] != hash[static_cast<size_t>(i)]) {
            throw std::runtime_error("Base58Check: invalid checksum");
        }
    }

    return payload;
}

} // namespace utils
} // namespace wallet
