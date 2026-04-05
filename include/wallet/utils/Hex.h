#pragma once
#ifndef WALLET_UTILS_HEX_H
#define WALLET_UTILS_HEX_H

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace utils {

/// @brief Hex encoding and decoding utilities.
class Hex {
public:
    /// Encode raw bytes as a lowercase hex string.
    /// @param data  Input bytes.
    /// @return Hex-encoded string (no "0x" prefix).
    static std::string encode(const std::vector<uint8_t>& data);

    /// Decode a hex string to bytes. Accepts optional "0x" prefix.
    /// @param hex  Hex-encoded string.
    /// @return Decoded bytes.
    /// @throws std::invalid_argument on invalid hex characters.
    static std::vector<uint8_t> decode(const std::string& hex);
};

} // namespace utils
} // namespace wallet

#endif // WALLET_UTILS_HEX_H
