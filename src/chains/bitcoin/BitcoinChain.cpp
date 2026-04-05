// ==========================================================================
// BitcoinChain.cpp -- Bitcoin native SegWit address derivation & tx signing
// ==========================================================================
#include "wallet/chains/bitcoin/BitcoinChain.h"
#include "wallet/crypto/ECDSA.h"
#include "wallet/crypto/Hash.h"
#include "wallet/utils/Bech32.h"

#include <stdexcept>
#include <cstring>

namespace wallet {

using crypto::ECDSA;
using crypto::Hash;
using utils::Bech32;

// ---------------------------------------------------------------------------
// Helper: serialize a uint32_t in little-endian
// ---------------------------------------------------------------------------
namespace {

void writeLE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void writeLE64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

uint32_t readLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t readLE64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// deriveAddress()  --  P2WPKH native SegWit (bech32, bc1q...)
// ---------------------------------------------------------------------------
std::string BitcoinChain::deriveAddress(const PublicKey& pubkey) const {
    // Expect compressed public key (33 bytes: 02/03 + X)
    if (pubkey.data.size() != 33)
        throw std::runtime_error(
            "BitcoinChain::deriveAddress: expected 33-byte compressed public key");

    // HASH160 = RIPEMD160(SHA256(pubkey))
    auto h160 = Hash::hash160(pubkey.data);
    std::vector<uint8_t> program(h160.begin(), h160.end()); // 20 bytes

    // Encode as Bech32 witness v0 with HRP "bc" (mainnet)
    return Bech32::encode("bc", 0, program);
}

// ---------------------------------------------------------------------------
// signTransaction()  --  sign a simplified SegWit transaction
//
// The input txData is expected to be a simplified unsigned SegWit
// transaction in our internal format:
//
// [4 bytes version]
// [1 byte  input count = 1 for now]
//   [32 bytes prev txid]
//   [4  bytes prev vout]
//   [8  bytes input value (little-endian, for BIP-143 sighash)]
// [1 byte  output count]
//   for each output:
//     [8 bytes value]
//     [1 byte  scriptPubKey length]
//     [N bytes scriptPubKey]
// [4 bytes locktime]
//
// We compute the BIP-143 sighash, sign with ECDSA, and produce
// a SegWit-format signed transaction.
// ---------------------------------------------------------------------------
std::vector<uint8_t> BitcoinChain::signTransaction(
    const std::vector<uint8_t>& txData,
    const PrivateKey& key) const
{
    if (txData.size() < 53) // minimum viable size
        throw std::runtime_error("BitcoinChain::signTransaction: txData too short");

    // Derive compressed public key
    auto pubKey = ECDSA::publicKeyFromPrivate(key.data);

    // Parse the unsigned transaction fields
    size_t pos = 0;
    uint32_t version = readLE32(txData.data() + pos); pos += 4;
    uint8_t inputCount = txData[pos++];
    if (inputCount != 1)
        throw std::runtime_error(
            "BitcoinChain::signTransaction: only single-input tx supported");

    // Input: prevTxId (32) + prevVout (4) + inputValue (8)
    std::vector<uint8_t> prevTxId(txData.begin() + pos, txData.begin() + pos + 32);
    pos += 32;
    uint32_t prevVout = readLE32(txData.data() + pos); pos += 4;
    uint64_t inputValue = readLE64(txData.data() + pos); pos += 8;

    // Outputs
    uint8_t outputCount = txData[pos++];
    std::vector<uint8_t> outputsBlob;
    for (uint8_t i = 0; i < outputCount; ++i) {
        uint64_t outVal = readLE64(txData.data() + pos); pos += 8;
        uint8_t scriptLen = txData[pos++];
        writeLE64(outputsBlob, outVal);
        outputsBlob.push_back(scriptLen);
        outputsBlob.insert(outputsBlob.end(),
                           txData.begin() + pos,
                           txData.begin() + pos + scriptLen);
        pos += scriptLen;
    }

    uint32_t locktime = readLE32(txData.data() + pos);

    // ===================================================================
    // BIP-143 sighash computation for P2WPKH
    // ===================================================================
    uint32_t sigHashType = 1; // SIGHASH_ALL

    // hashPrevouts = dSHA256(prevTxId || prevVout)
    std::vector<uint8_t> prevouts;
    prevouts.insert(prevouts.end(), prevTxId.begin(), prevTxId.end());
    writeLE32(prevouts, prevVout);
    auto hashPrevouts = Hash::doubleSha256(prevouts);

    // hashSequence = dSHA256(sequence)  -- assume 0xFFFFFFFF
    std::vector<uint8_t> seqBuf;
    writeLE32(seqBuf, 0xFFFFFFFF);
    auto hashSequence = Hash::doubleSha256(seqBuf);

    // hashOutputs = dSHA256(serialized outputs)
    auto hashOutputs = Hash::doubleSha256(outputsBlob);

    // Build the P2WPKH scriptCode: OP_DUP OP_HASH160 <20 pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    auto pubKeyHash = Hash::hash160(pubKey);
    std::vector<uint8_t> scriptCode;
    scriptCode.push_back(0x19); // length of scriptCode (25 bytes)
    scriptCode.push_back(0x76); // OP_DUP
    scriptCode.push_back(0xA9); // OP_HASH160
    scriptCode.push_back(0x14); // push 20 bytes
    scriptCode.insert(scriptCode.end(), pubKeyHash.begin(), pubKeyHash.end());
    scriptCode.push_back(0x88); // OP_EQUALVERIFY
    scriptCode.push_back(0xAC); // OP_CHECKSIG

    // Build the preimage
    std::vector<uint8_t> preimage;
    writeLE32(preimage, version);
    preimage.insert(preimage.end(), hashPrevouts.begin(), hashPrevouts.end());
    preimage.insert(preimage.end(), hashSequence.begin(), hashSequence.end());
    // outpoint
    preimage.insert(preimage.end(), prevTxId.begin(), prevTxId.end());
    writeLE32(preimage, prevVout);
    // scriptCode (without the leading length byte in BIP-143; include the varint)
    preimage.insert(preimage.end(), scriptCode.begin(), scriptCode.end());
    // value
    writeLE64(preimage, inputValue);
    // nSequence
    writeLE32(preimage, 0xFFFFFFFF);
    preimage.insert(preimage.end(), hashOutputs.begin(), hashOutputs.end());
    writeLE32(preimage, locktime);
    writeLE32(preimage, sigHashType);

    // Double SHA-256 of the preimage
    auto sigHash = Hash::doubleSha256(preimage);

    // ECDSA sign
    std::array<uint8_t, 32> sigHashArr;
    std::copy(sigHash.begin(), sigHash.end(), sigHashArr.begin());
    auto derSig = ECDSA::sign(sigHashArr, key.data);

    // Append SIGHASH_ALL byte to the DER signature
    derSig.push_back(static_cast<uint8_t>(sigHashType));

    // ===================================================================
    // Assemble the signed SegWit transaction
    // ===================================================================
    std::vector<uint8_t> signedTx;

    // Version
    writeLE32(signedTx, version);

    // SegWit marker + flag
    signedTx.push_back(0x00); // marker
    signedTx.push_back(0x01); // flag

    // Input count
    signedTx.push_back(1);

    // Input: prevTxId + prevVout + empty scriptSig + sequence
    signedTx.insert(signedTx.end(), prevTxId.begin(), prevTxId.end());
    writeLE32(signedTx, prevVout);
    signedTx.push_back(0x00); // scriptSig length = 0 (SegWit)
    writeLE32(signedTx, 0xFFFFFFFF); // nSequence

    // Output count + outputs
    signedTx.push_back(outputCount);
    signedTx.insert(signedTx.end(), outputsBlob.begin(), outputsBlob.end());

    // Witness data (for the single input)
    signedTx.push_back(0x02); // 2 witness items
    // Item 1: signature
    signedTx.push_back(static_cast<uint8_t>(derSig.size()));
    signedTx.insert(signedTx.end(), derSig.begin(), derSig.end());
    // Item 2: public key
    signedTx.push_back(static_cast<uint8_t>(pubKey.size()));
    signedTx.insert(signedTx.end(), pubKey.begin(), pubKey.end());

    // Locktime
    writeLE32(signedTx, locktime);

    return signedTx;
}

uint32_t BitcoinChain::coinType() const { return 0; }
std::string BitcoinChain::chainName() const { return "Bitcoin"; }

} // namespace wallet
