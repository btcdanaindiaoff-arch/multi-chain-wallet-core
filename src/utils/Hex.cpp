// src/utils/Hex.cpp
// Hex encoding and decoding with proper nibble conversion and validation.

#include "wallet/utils/Hex.h"

#include <stdexcept>
#include <sstream>

namespace wallet {
namespace utils {

std::string Hex::encode(const std::vector<uint8_t>& data) {
    static constexpr char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(hexChars[(byte >> 4) & 0x0F]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> Hex::decode(const std::string& hex) {
    std::string input = hex;

    // Strip optional "0x" or "0X" prefix
    if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input = input.substr(2);
    }

    if (input.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    std::vector<uint8_t> result;
    result.reserve(input.size() / 2);

    for (size_t i = 0; i < input.size(); i += 2) {
        uint8_t high = 0, low = 0;

        // High nibble
        char ch = input[i];
        if (ch >= '0' && ch <= '9')      high = static_cast<uint8_t>(ch - '0');
        else if (ch >= 'a' && ch <= 'f') high = static_cast<uint8_t>(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') high = static_cast<uint8_t>(ch - 'A' + 10);
        else throw std::invalid_argument(std::string("Invalid hex character: ") + ch);

        // Low nibble
        ch = input[i + 1];
        if (ch >= '0' && ch <= '9')      low = static_cast<uint8_t>(ch - '0');
        else if (ch >= 'a' && ch <= 'f') low = static_cast<uint8_t>(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') low = static_cast<uint8_t>(ch - 'A' + 10);
        else throw std::invalid_argument(std::string("Invalid hex character: ") + ch);

        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return result;
}

} // namespace utils
} // namespace wallet
