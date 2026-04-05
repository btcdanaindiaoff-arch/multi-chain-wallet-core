#include "wallet/utils/Bech32.h"

namespace wallet {
namespace utils {

std::string Bech32::encode(const std::string& hrp,
                           uint8_t version,
                           const std::vector<uint8_t>& program) {
    // TODO: Implement BIP-173 Bech32 encoding.
    //       1. Convert program from 8-bit to 5-bit groups.
    //       2. Prepend witness version.
    //       3. Compute Bech32 checksum.
    //       4. Encode with HRP separator '1'.
    (void)hrp;
    (void)version;
    (void)program;
    return "";
}

std::string Bech32::encodeM(const std::string& hrp,
                            uint8_t version,
                            const std::vector<uint8_t>& program) {
    // TODO: Implement BIP-350 Bech32m encoding (for witness version >= 1).
    (void)hrp;
    (void)version;
    (void)program;
    return "";
}

bool Bech32::decode(const std::string& address,
                    std::string& hrp,
                    uint8_t& version,
                    std::vector<uint8_t>& program) {
    // TODO: Decode Bech32/Bech32m address, validate checksum,
    //       convert 5-bit groups back to 8-bit.
    (void)address;
    (void)hrp;
    (void)version;
    (void)program;
    return false;
}

} // namespace utils
} // namespace wallet
