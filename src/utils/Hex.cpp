#include "wallet/utils/Hex.h"

#include <stdexcept>

namespace wallet {
namespace utils {

std::string Hex::encode(const std::vector<uint8_t>& data) {
    // TODO: Convert each byte to two lowercase hex characters.
    static const char* hexChars = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(hexChars[byte >> 4]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> Hex::decode(const std::string& hex) {
    // TODO: Validate input, strip optional "0x" prefix, decode pairs.
    std::string input = hex;
    if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input = input.substr(2);
    }
    if (input.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    std::vector<uint8_t> result;
    result.reserve(input.size() / 2);
    for (size_t i = 0; i < input.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        // TODO: Proper hex char to nibble conversion with validation.
        (void)hi;
        (void)lo;
        result.push_back(0); // Placeholder
    }
    return result;
}

} // namespace utils
} // namespace wallet
