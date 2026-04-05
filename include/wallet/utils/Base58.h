#pragma once
#ifndef WALLET_UTILS_BASE58_H
#define WALLET_UTILS_BASE58_H

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace utils {

/// @brief Base58 and Base58Check encoding/decoding.
///
/// Used by Bitcoin (P2PKH, WIF) and Solana (addresses).
class Base58 {
public:
    /// Base58 encode raw bytes.
    static std::string encode(const std::vector<uint8_t>& data);

    /// Base58 decode a string back to bytes.
    static std::vector<uint8_t> decode(const std::string& encoded);

    /// Base58Check encode (appends 4-byte double-SHA256 checksum).
    static std::string encodeCheck(const std::vector<uint8_t>& data);

    /// Base58Check decode and verify checksum.
    /// @throws std::runtime_error if checksum is invalid.
    static std::vector<uint8_t> decodeCheck(const std::string& encoded);
};

} // namespace utils
} // namespace wallet

#endif // WALLET_UTILS_BASE58_H
