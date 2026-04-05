#include "wallet/utils/RLP.h"

namespace wallet {
namespace utils {

std::vector<uint8_t> RLP::encodeString(const std::vector<uint8_t>& data) {
    // TODO: Implement RLP string encoding:
    //       - Single byte [0x00, 0x7f]: returned as-is.
    //       - 0-55 bytes: 0x80 + length prefix.
    //       - >55 bytes: 0xb7 + length-of-length prefix.
    (void)data;
    return {};
}

std::vector<uint8_t> RLP::encodeList(
    const std::vector<std::vector<uint8_t>>& items) {
    // TODO: Concatenate encoded items, prefix with list header:
    //       - Total payload <= 55 bytes: 0xc0 + total_length.
    //       - Total payload >  55 bytes: 0xf7 + length-of-length.
    (void)items;
    return {};
}

std::vector<uint8_t> RLP::encodeUint(uint64_t value) {
    // TODO: Encode as big-endian minimal bytes, then RLP-encode as string.
    (void)value;
    return {};
}

} // namespace utils
} // namespace wallet
