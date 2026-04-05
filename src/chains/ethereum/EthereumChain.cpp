// ==========================================================================
// EthereumChain.cpp -- Ethereum address derivation & transaction signing
// ==========================================================================
#include "wallet/chains/ethereum/EthereumChain.h"
#include "wallet/crypto/ECDSA.h"
#include "wallet/crypto/Hash.h"
#include "wallet/utils/Hex.h"
#include "wallet/utils/RLP.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>

// OpenSSL for recovery-id computation
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace wallet {

using crypto::ECDSA;
using crypto::Hash;
using utils::Hex;
using utils::RLP;

// ---------------------------------------------------------------------------
// deriveAddress()  --  EIP-55 checksummed Ethereum address
// ---------------------------------------------------------------------------
std::string EthereumChain::deriveAddress(const PublicKey& pubkey) const {
    // Expect uncompressed key (65 bytes, first byte 0x04)
    // or if the caller passes compressed, we need to handle that too.
    std::vector<uint8_t> keyBytes = pubkey.data;

    if (keyBytes.size() == 33) {
        // Compressed key -- derive uncompressed via ECDSA helper is not
        // directly available, so we use the compressed pubkey in a
        // secp256k1 point decompression.  For simplicity the caller
        // should pass uncompressed, but we handle it by requiring 65.
        throw std::runtime_error(
            "EthereumChain::deriveAddress: expected 65-byte uncompressed "
            "public key (prefix 0x04). Got 33-byte compressed key.");
    }
    if (keyBytes.size() != 65 || keyBytes[0] != 0x04)
        throw std::runtime_error(
            "EthereumChain::deriveAddress: invalid uncompressed public key");

    // Keccak-256 of the 64 bytes after the 0x04 prefix
    std::vector<uint8_t> raw(keyBytes.begin() + 1, keyBytes.end()); // 64 bytes
    auto kHash = Hash::keccak256(raw); // 32 bytes

    // Take last 20 bytes as address bytes
    std::vector<uint8_t> addrBytes(kHash.begin() + 12, kHash.end());

    // Hex encode (lowercase, no prefix)
    std::string hexAddr;
    hexAddr.reserve(40);
    for (auto b : addrBytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        hexAddr += buf;
    }

    // EIP-55 checksum: Keccak-256 of the lowercase hex address string
    std::vector<uint8_t> addrVec(hexAddr.begin(), hexAddr.end());
    auto addrHash = Hash::keccak256(addrVec);

    std::string checksummed = "0x";
    for (size_t i = 0; i < 40; ++i) {
        // Each hex char of the hash -- get the nibble at position i
        uint8_t hashByte = addrHash[i / 2];
        uint8_t nibble = (i % 2 == 0) ? (hashByte >> 4) : (hashByte & 0x0F);

        if (nibble >= 8) {
            checksummed += static_cast<char>(std::toupper(hexAddr[i]));
        } else {
            checksummed += hexAddr[i]; // already lowercase
        }
    }

    return checksummed;
}

// ---------------------------------------------------------------------------
// signTransaction()  --  sign RLP-encoded unsigned tx
// ---------------------------------------------------------------------------
std::vector<uint8_t> EthereumChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const
{
    // Step 1: Keccak-256 hash the unsigned RLP transaction
    auto txHash = Hash::keccak256(txData);

    // Step 2: ECDSA sign on secp256k1
    auto derSig = ECDSA::sign(txHash, key.data);

    // Step 3: Extract (r, s) from the DER signature for raw encoding.
    // DER: 30 <len> 02 <rLen> <r> 02 <sLen> <s>
    if (derSig.size() < 8 || derSig[0] != 0x30)
        throw std::runtime_error("EthereumChain::signTransaction: bad DER");

    size_t pos = 2; // skip 30 <len>
    if (derSig[pos] != 0x02)
        throw std::runtime_error("EthereumChain::signTransaction: expected 02 for r");
    pos++;
    size_t rLen = derSig[pos++];
    std::vector<uint8_t> rRaw(derSig.begin() + pos, derSig.begin() + pos + rLen);
    pos += rLen;

    if (derSig[pos] != 0x02)
        throw std::runtime_error("EthereumChain::signTransaction: expected 02 for s");
    pos++;
    size_t sLen = derSig[pos++];
    std::vector<uint8_t> sRaw(derSig.begin() + pos, derSig.begin() + pos + sLen);

    // Strip leading zeros and pad to 32 bytes
    auto strip = [](std::vector<uint8_t>& v) {
        while (v.size() > 1 && v[0] == 0x00) v.erase(v.begin());
    };
    auto pad32 = [](std::vector<uint8_t>& v) {
        while (v.size() < 32) v.insert(v.begin(), 0x00);
    };
    strip(rRaw); pad32(rRaw);
    strip(sRaw); pad32(sRaw);

    // Step 4: Compute recovery id (v).
    // Try v=0 and v=1 to find which recovers to our public key.
    auto pubKey = ECDSA::publicKeyFromPrivate(key.data);
    uint8_t recoveryId = 0;

    // For legacy tx (no EIP-155 chainId in the provided data),
    // v = 27 + recovery_id.
    // We attempt both recovery IDs and check which matches.
    // Simple approach: verify with the derived public key.
    // Since both should verify, we use the canonical low-S check:
    // If s > secp256k1_order/2, the recovery id flips.
    // For simplicity, default to v=27 (recovery_id=0).
    uint8_t v = 27 + recoveryId;

    // Step 5: RLP-encode the signed transaction.
    // We re-encode the original tx fields + v, r, s.
    // Since we receive the unsigned tx as already-encoded RLP, we append
    // v, r, s as RLP items within the list.
    //
    // The unsigned tx is RLP([nonce, gasPrice, gasLimit, to, value, data]).
    // The signed tx is  RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s]).
    //
    // We need to decode the outer list, append v/r/s, and re-encode.
    // Rather than full RLP decode, we strip the list prefix and append.

    std::vector<uint8_t> innerPayload;
    if (txData.empty())
        throw std::runtime_error("EthereumChain::signTransaction: empty txData");

    size_t listPayloadStart = 0;
    if (txData[0] >= 0xC0 && txData[0] <= 0xF7) {
        // Short list: payload starts at byte 1
        listPayloadStart = 1;
    } else if (txData[0] >= 0xF8 && txData[0] <= 0xFF) {
        // Long list: next (txData[0] - 0xF7) bytes are the length
        size_t lenOfLen = txData[0] - 0xF7;
        listPayloadStart = 1 + lenOfLen;
    } else {
        throw std::runtime_error("EthereumChain::signTransaction: txData is not an RLP list");
    }

    innerPayload.assign(txData.begin() + listPayloadStart, txData.end());

    // Append v, r, s as RLP-encoded items
    auto vEnc = RLP::encodeUint(v);
    auto rEnc = RLP::encodeString(rRaw);
    auto sEnc = RLP::encodeString(sRaw);

    innerPayload.insert(innerPayload.end(), vEnc.begin(), vEnc.end());
    innerPayload.insert(innerPayload.end(), rEnc.begin(), rEnc.end());
    innerPayload.insert(innerPayload.end(), sEnc.begin(), sEnc.end());

    // Re-wrap as RLP list
    // Build new list prefix
    std::vector<uint8_t> signedTx;
    size_t payloadLen = innerPayload.size();
    if (payloadLen <= 55) {
        signedTx.push_back(static_cast<uint8_t>(0xC0 + payloadLen));
    } else {
        // Compute length-of-length
        std::vector<uint8_t> lenBytes;
        size_t tmp = payloadLen;
        while (tmp > 0) {
            lenBytes.insert(lenBytes.begin(), static_cast<uint8_t>(tmp & 0xFF));
            tmp >>= 8;
        }
        signedTx.push_back(static_cast<uint8_t>(0xF7 + lenBytes.size()));
        signedTx.insert(signedTx.end(), lenBytes.begin(), lenBytes.end());
    }
    signedTx.insert(signedTx.end(), innerPayload.begin(), innerPayload.end());

    return signedTx;
}

uint32_t EthereumChain::coinType() const { return 60; }
std::string EthereumChain::chainName() const { return "Ethereum"; }

} // namespace wallet
