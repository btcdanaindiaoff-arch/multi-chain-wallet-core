#pragma once
#ifndef WALLET_UTILS_BECH32_H
#define WALLET_UTILS_BECH32_H

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace utils {

/// @brief Bech32 and Bech32m encoding for SegWit addresses.
///
/// Implements BIP-173 (Bech32) and BIP-350 (Bech32m).
class Bech32 {
public:
    /// Bech32 encode a witness program.
    /// @param hrp      Human-readable part (e.g. "bc" for mainnet Bitcoin).
    /// @param version  Witness version (0-16).
    /// @param program  Witness program bytes.
    /// @return Bech32-encoded address string.
    static std::string encode(const std::string& hrp,
                              uint8_t version,
                              const std::vector<uint8_t>& program);

    /// Bech32m encode (for witness version >= 1, per BIP-350).
    static std::string encodeM(const std::string& hrp,
                               uint8_t version,
                               const std::vector<uint8_t>& program);

    /// Decode a Bech32 / Bech32m address.
    /// @param address  Encoded address.
    /// @param[out] hrp      Extracted human-readable part.
    /// @param[out] version  Extracted witness version.
    /// @param[out] program  Extracted witness program.
    /// @return true if decoding succeeds.
    static bool decode(const std::string& address,
                       std::string& hrp,
                       uint8_t& version,
                       std::vector<uint8_t>& program);
};

} // namespace utils
} // namespace wallet

#endif // WALLET_UTILS_BECH32_H
