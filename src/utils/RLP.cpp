// ==========================================================================
// RLP.cpp -- Recursive Length Prefix encoding (Ethereum Yellow Paper)
// ==========================================================================
#include "wallet/utils/RLP.h"

#include <stdexcept>

namespace wallet {
namespace utils {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
namespace {

/// Encode a length as big-endian minimal bytes.
std::vector<uint8_t> encodeLengthBytes(size_t len) {
    std::vector<uint8_t> out;
    if (len == 0) {
        out.push_back(0);
        return out;
    }
    // Collect bytes in little-endian then reverse
    while (len > 0) {
        out.insert(out.begin(), static_cast<uint8_t>(len & 0xFF));
        len >>= 8;
    }
    return out;
}

/// Encode a length prefix for either string or list.
/// @param dataLen  Length of the payload.
/// @param shortBase  Base for short payloads (0x80 for string, 0xC0 for list).
/// @param longBase   Base for long payloads  (0xB7 for string, 0xF7 for list).
std::vector<uint8_t> encodeLength(size_t dataLen, uint8_t shortBase, uint8_t longBase) {
    std::vector<uint8_t> out;
    if (dataLen <= 55) {
        out.push_back(static_cast<uint8_t>(shortBase + dataLen));
    } else {
        auto lenBytes = encodeLengthBytes(dataLen);
        out.push_back(static_cast<uint8_t>(longBase + lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
    return out;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// encodeString()
// ---------------------------------------------------------------------------
std::vector<uint8_t> RLP::encodeString(const std::vector<uint8_t>& data) {
    // Single byte in [0x00, 0x7F]: pass through as-is
    if (data.size() == 1 && data[0] <= 0x7F) {
        return data;
    }

    // Empty string
    if (data.empty()) {
        return {0x80};
    }

    auto prefix = encodeLength(data.size(), 0x80, 0xB7);
    prefix.insert(prefix.end(), data.begin(), data.end());
    return prefix;
}

// ---------------------------------------------------------------------------
// encodeList()
// ---------------------------------------------------------------------------
std::vector<uint8_t> RLP::encodeList(
    const std::vector<std::vector<uint8_t>>& items)
{
    // Concatenate all already-encoded items
    std::vector<uint8_t> payload;
    for (const auto& item : items) {
        payload.insert(payload.end(), item.begin(), item.end());
    }

    auto prefix = encodeLength(payload.size(), 0xC0, 0xF7);
    prefix.insert(prefix.end(), payload.begin(), payload.end());
    return prefix;
}

// ---------------------------------------------------------------------------
// encodeUint()
// ---------------------------------------------------------------------------
std::vector<uint8_t> RLP::encodeUint(uint64_t value) {
    if (value == 0) {
        // RLP encodes zero as empty byte string => 0x80
        return encodeString({});
    }

    // Convert to big-endian minimal bytes
    std::vector<uint8_t> bytes;
    uint64_t tmp = value;
    while (tmp > 0) {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(tmp & 0xFF));
        tmp >>= 8;
    }

    return encodeString(bytes);
}

} // namespace utils
} // namespace wallet
