#pragma once
#ifndef WALLET_UTILS_RLP_H
#define WALLET_UTILS_RLP_H

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace utils {

/// @brief Recursive Length Prefix (RLP) encoding for Ethereum.
///
/// Implements the encoding scheme defined in the Ethereum Yellow Paper
/// for serialising transactions and other data structures.
class RLP {
public:
    /// RLP-encode a single byte string.
    static std::vector<uint8_t> encodeString(const std::vector<uint8_t>& data);

    /// RLP-encode a list of already-encoded items.
    static std::vector<uint8_t> encodeList(
        const std::vector<std::vector<uint8_t>>& items);

    /// Convenience: RLP-encode a uint256 value (big-endian, minimal bytes).
    static std::vector<uint8_t> encodeUint(uint64_t value);
};

} // namespace utils
} // namespace wallet

#endif // WALLET_UTILS_RLP_H
