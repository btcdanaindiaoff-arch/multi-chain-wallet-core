// ==========================================================================
// Bech32.cpp -- BIP-173 (Bech32) and BIP-350 (Bech32m) encoding/decoding
// ==========================================================================
#include "wallet/utils/Bech32.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace wallet {
namespace utils {

// ---------------------------------------------------------------------------
// Constants and polymod helpers
// ---------------------------------------------------------------------------
namespace {

const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

constexpr uint32_t BECH32_CONST  = 1;          // BIP-173
constexpr uint32_t BECH32M_CONST = 0x2bc830a3; // BIP-350

uint32_t polymod(const std::vector<uint8_t>& values) {
    static const uint32_t GEN[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };
    uint32_t chk = 1;
    for (auto v : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1FFFFFF) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

std::vector<uint8_t> hrpExpand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) >> 5);
    ret.push_back(0);
    for (char c : hrp) ret.push_back(static_cast<uint8_t>(c) & 0x1F);
    return ret;
}

bool verifyChecksum(const std::string& hrp,
                    const std::vector<uint8_t>& data,
                    uint32_t expectedConst) {
    auto exp = hrpExpand(hrp);
    exp.insert(exp.end(), data.begin(), data.end());
    return polymod(exp) == expectedConst;
}

std::vector<uint8_t> createChecksum(const std::string& hrp,
                                     const std::vector<uint8_t>& data,
                                     uint32_t constant) {
    auto values = hrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6, 0);
    uint32_t mod = polymod(values) ^ constant;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i)
        ret[i] = static_cast<uint8_t>((mod >> (5 * (5 - i))) & 31);
    return ret;
}

/// Convert between bit groups. `frombits` and `tobits` are bit widths.
bool convertBits(std::vector<uint8_t>& out,
                 const std::vector<uint8_t>& in,
                 int frombits, int tobits, bool pad) {
    int acc = 0;
    int bits = 0;
    int maxv = (1 << tobits) - 1;
    for (auto value : in) {
        if (value < 0 || (value >> frombits)) return false;
        acc = (acc << frombits) | value;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }
    if (pad) {
        if (bits) out.push_back(static_cast<uint8_t>((acc << (tobits - bits)) & maxv));
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

std::string encodeImpl(const std::string& hrp, uint8_t version,
                        const std::vector<uint8_t>& program,
                        uint32_t constant) {
    // Convert 8-bit program to 5-bit groups
    std::vector<uint8_t> data5;
    data5.push_back(version); // witness version as a single 5-bit value
    if (!convertBits(data5, program, 8, 5, true))
        throw std::runtime_error("Bech32::encode: convertBits failed");

    auto checksum = createChecksum(hrp, data5, constant);
    data5.insert(data5.end(), checksum.begin(), checksum.end());

    std::string result = hrp + '1';
    for (auto d : data5)
        result += BECH32_CHARSET[d];
    return result;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// encode()  --  BIP-173 Bech32 (witness v0)
// ---------------------------------------------------------------------------
std::string Bech32::encode(const std::string& hrp,
                            uint8_t version,
                            const std::vector<uint8_t>& program) {
    return encodeImpl(hrp, version, program, BECH32_CONST);
}

// ---------------------------------------------------------------------------
// encodeM()  --  BIP-350 Bech32m (witness v1+)
// ---------------------------------------------------------------------------
std::string Bech32::encodeM(const std::string& hrp,
                              uint8_t version,
                              const std::vector<uint8_t>& program) {
    return encodeImpl(hrp, version, program, BECH32M_CONST);
}

// ---------------------------------------------------------------------------
// decode()  --  decode Bech32 or Bech32m address
// ---------------------------------------------------------------------------
bool Bech32::decode(const std::string& address,
                    std::string& hrp,
                    uint8_t& version,
                    std::vector<uint8_t>& program) {
    // Mixed case check
    bool hasLower = false, hasUpper = false;
    for (char c : address) {
        if (c >= 'a' && c <= 'z') hasLower = true;
        if (c >= 'A' && c <= 'Z') hasUpper = true;
    }
    if (hasLower && hasUpper) return false;

    // Lowercase for processing
    std::string addr = address;
    std::transform(addr.begin(), addr.end(), addr.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Find separator (last '1')
    auto sepPos = addr.rfind('1');
    if (sepPos == std::string::npos || sepPos < 1 ||
        sepPos + 7 > addr.size() || addr.size() > 90)
        return false;

    hrp = addr.substr(0, sepPos);
    std::vector<uint8_t> data5;

    // Decode data part from charset
    for (size_t i = sepPos + 1; i < addr.size(); ++i) {
        const char* pos = std::find(BECH32_CHARSET, BECH32_CHARSET + 32, addr[i]);
        if (pos == BECH32_CHARSET + 32) return false;
        data5.push_back(static_cast<uint8_t>(pos - BECH32_CHARSET));
    }

    if (data5.size() < 6) return false;

    // Determine which constant to verify against
    // Witness version 0 => Bech32, version 1-16 => Bech32m
    version = data5[0];
    uint32_t expectedConst = (version == 0) ? BECH32_CONST : BECH32M_CONST;

    if (!verifyChecksum(hrp, data5, expectedConst))
        return false;

    // Strip witness version and 6-byte checksum, convert 5-bit -> 8-bit
    std::vector<uint8_t> data5payload(data5.begin() + 1, data5.end() - 6);
    program.clear();
    if (!convertBits(program, data5payload, 5, 8, false))
        return false;

    // Validate witness program length (BIP-141)
    if (program.size() < 2 || program.size() > 40)
        return false;
    if (version == 0 && program.size() != 20 && program.size() != 32)
        return false;

    return true;
}

} // namespace utils
} // namespace wallet
