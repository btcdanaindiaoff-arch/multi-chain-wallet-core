# multi-chain-wallet-core

> C++ core library for multi-chain wallet -- HD key derivation, address generation, and transaction signing for Ethereum/EVM, Bitcoin, Solana, and custom chains.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-3.18%2B-green.svg)](https://cmake.org/)

---

## Overview

**multi-chain-wallet-core** is a high-performance, cross-platform C++ library providing the cryptographic foundation for multi-chain cryptocurrency wallets. It implements industry-standard key derivation (BIP32/BIP39/BIP44), multi-chain address generation, and transaction signing with an extensible architecture for adding custom blockchains.

Designed to be embedded into Android (NDK/JNI), iOS (via C bridge), and desktop applications, the library prioritizes security, correctness, and minimal dependencies.

---

## Supported Chains

| Chain | Address Type | Signing Algorithm | Status |
|-------|-------------|-------------------|--------|
| **Ethereum / EVM** | Keccak-256 + EIP-55 checksum | ECDSA secp256k1 (EIP-1559, Legacy) | Supported |
| **Bitcoin / UTXO** | P2PKH, P2SH, P2WPKH (SegWit), P2TR (Taproot) | ECDSA secp256k1 | Supported |
| **Solana** | Base58 (Ed25519 public key) | Ed25519 | Supported |
| **Custom Chains** | Extensible via ChainRegistry | Plugin architecture | Extensible |

---

## Features

### HD Wallet (BIP32/BIP39/BIP44)
- **Mnemonic Generation**: 12/15/18/21/24-word mnemonic phrases (BIP39)
- **Seed Derivation**: PBKDF2-HMAC-SHA512 with optional passphrase
- **Key Derivation**: Hierarchical deterministic keys (BIP32) with hardened/normal child derivation
- **Multi-Account**: BIP44 derivation paths (`m/44'/coin_type'/account'/change/index`)

### Multi-Chain Address Derivation
- Ethereum: Keccak-256 hash with EIP-55 mixed-case checksum encoding
- Bitcoin: Base58Check (P2PKH/P2SH), Bech32 (SegWit P2WPKH), Bech32m (Taproot P2TR)
- Solana: Base58-encoded Ed25519 public key
- Extensible for any chain via the `IChain` interface

### Transaction Signing
- **EVM Chains**: Legacy (pre-EIP-155), EIP-155 replay protection, EIP-1559 (type-2) transactions
- **Bitcoin**: UTXO selection, SegWit witness signing, multi-input/multi-output transactions
- **Solana**: Ed25519 message signing, transaction serialization
- **Extensible**: Register custom chain signers via `ChainRegistry`

### Extensible Chain Registry
- Plugin-based architecture for adding new blockchains
- Each chain implements `IChain` interface: address derivation + transaction signing
- Runtime chain registration and lookup by coin type or chain ID

---

## Project Structure

```
multi-chain-wallet-core/
|-- CMakeLists.txt              # Root CMake build configuration
|-- include/
|   |-- wallet/
|       |-- core/               # HD wallet, key management
|       |-- chains/             # Chain-specific interfaces
|       |-- crypto/             # Cryptographic primitives
|       |-- utils/              # Encoding, serialization utilities
|-- src/
|   |-- core/                   # HDWallet, Mnemonic, KeyDerivation
|   |-- chains/
|   |   |-- ethereum/           # EVM address + tx signing
|   |   |-- bitcoin/            # UTXO address + tx signing
|   |   |-- solana/             # Solana address + tx signing
|   |-- crypto/                 # ECDSA, Ed25519, Keccak, SHA, RIPEMD
|   |-- utils/                  # Base58, Bech32, Hex, RLP encoding
|-- tests/
|   |-- test_mnemonic.cpp
|   |-- test_key_derivation.cpp
|   |-- test_ethereum.cpp
|   |-- test_bitcoin.cpp
|   |-- test_solana.cpp
|-- third_party/                # External dependencies (submodules)
|-- cmake/                      # CMake find modules
|-- LICENSE
|-- README.md
```

---

## Build Requirements

| Dependency | Minimum Version | Purpose |
|-----------|----------------|----------|
| **CMake** | 3.18+ | Build system |
| **C++ Compiler** | C++17 (GCC 9+, Clang 10+, MSVC 2019+) | Language standard |
| **OpenSSL** | 1.1.1+ | ECDSA, SHA-256/512, RIPEMD-160, PBKDF2 |
| **Boost** | 1.71+ | Multiprecision, program_options |
| **Protobuf** | 3.15+ | Transaction serialization |
| **Google Test** | 1.11+ | Unit testing framework |

### Optional
- **libsodium** (1.0.18+): Alternative Ed25519 implementation for Solana
- **Android NDK** (r21+): For Android cross-compilation
- **Xcode** (12+): For iOS builds

---

## Build Instructions

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/btcdanaindiaoff-arch/multi-chain-wallet-core.git
cd multi-chain-wallet-core

# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y cmake g++ libssl-dev libboost-all-dev libprotobuf-dev protobuf-compiler libgtest-dev

# Configure and build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
ctest --output-on-failure
```

### Android (NDK Cross-Compilation)

```bash
mkdir build-android && cd build-android
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Basic Usage

### Generate a Wallet

```cpp
#include <wallet/core/HDWallet.h>
#include <wallet/core/Mnemonic.h>
#include <iostream>

int main() {
    // Generate a 24-word mnemonic
    auto mnemonic = wallet::Mnemonic::generate(24);
    std::cout << "Mnemonic: " << mnemonic.toString() << std::endl;

    // Create HD wallet from mnemonic
    auto hdWallet = wallet::HDWallet::fromMnemonic(mnemonic, "optional-passphrase");

    // Derive Ethereum account (BIP44: m/44'/60'/0'/0/0)
    auto ethKey = hdWallet.deriveKey(wallet::CoinType::Ethereum, 0, 0, 0);
    std::cout << "ETH Address: " << ethKey.getAddress() << std::endl;

    // Derive Bitcoin account (BIP44: m/44'/0'/0'/0/0)
    auto btcKey = hdWallet.deriveKey(wallet::CoinType::Bitcoin, 0, 0, 0);
    std::cout << "BTC Address: " << btcKey.getAddress() << std::endl;

    // Derive Solana account (BIP44: m/44'/501'/0'/0')
    auto solKey = hdWallet.deriveKey(wallet::CoinType::Solana, 0, 0, 0);
    std::cout << "SOL Address: " << solKey.getAddress() << std::endl;

    return 0;
}
```

### Sign an Ethereum Transaction

```cpp
#include <wallet/chains/ethereum/EthereumSigner.h>
#include <wallet/core/HDWallet.h>

int main() {
    auto hdWallet = wallet::HDWallet::fromMnemonic(mnemonic);
    auto ethKey = hdWallet.deriveKey(wallet::CoinType::Ethereum, 0, 0, 0);

    // Build EIP-1559 transaction
    wallet::ethereum::Transaction tx;
    tx.chainId = 1;                            // Mainnet
    tx.nonce = 0;
    tx.maxPriorityFeePerGas = 1500000000ULL;   // 1.5 Gwei
    tx.maxFeePerGas = 30000000000ULL;          // 30 Gwei
    tx.gasLimit = 21000;
    tx.to = "0xRecipientAddress...";
    tx.value = 1000000000000000000ULL;          // 1 ETH in Wei

    // Sign the transaction
    auto signedTx = wallet::ethereum::EthereumSigner::sign(tx, ethKey.getPrivateKey());
    std::cout << "Signed TX: " << signedTx.toHex() << std::endl;

    return 0;
}
```

### Register a Custom Chain

```cpp
#include <wallet/chains/ChainRegistry.h>

class MyCustomChain : public wallet::IChain {
public:
    std::string deriveAddress(const wallet::PublicKey& pubkey) override {
        // Custom address derivation logic
        return "custom_" + pubkey.toHex();
    }

    wallet::SignedTransaction sign(
        const wallet::Transaction& tx,
        const wallet::PrivateKey& key
    ) override {
        // Custom signing logic
        return wallet::SignedTransaction{/* ... */};
    }

    uint32_t coinType() const override { return 9999; }
    std::string chainName() const override { return "MyChain"; }
};

int main() {
    // Register at runtime
    wallet::ChainRegistry::instance().registerChain(
        std::make_unique<MyCustomChain>()
    );

    // Use like any built-in chain
    auto chain = wallet::ChainRegistry::instance().getChain(9999);
    // ...
}
```

---

## Testing

```bash
cd build
ctest --output-on-failure

# Or run individual test binaries
./tests/test_mnemonic
./tests/test_key_derivation
./tests/test_ethereum
./tests/test_bitcoin
./tests/test_solana
```

---

## Security Considerations

- **Memory Safety**: Private keys are zeroed from memory after use via `SecureAllocator`
- **No Key Logging**: Private keys and mnemonics are never logged or serialized to disk
- **Constant-Time Operations**: Cryptographic comparisons use constant-time algorithms
- **Input Validation**: All external inputs are validated before processing
- **Dependency Auditing**: Only well-established, audited cryptographic libraries (OpenSSL, libsodium)

---

## Roadmap

- [ ] Core: HD Wallet (BIP32/39/44) key derivation
- [ ] Core: Mnemonic generation and validation
- [ ] Chain: Ethereum/EVM address derivation and transaction signing
- [ ] Chain: Bitcoin/UTXO address derivation and transaction signing
- [ ] Chain: Solana address derivation and transaction signing
- [ ] Extensible chain registry with plugin architecture
- [ ] Android NDK build support (JNI bindings)
- [ ] iOS build support (C bridge / Swift wrapper)
- [ ] WebAssembly (Emscripten) build target
- [ ] Hardware wallet integration (Ledger/Trezor)

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-new-chain`)
3. Write tests for your changes
4. Ensure all tests pass (`ctest --output-on-failure`)
5. Commit your changes (`git commit -am 'feat: add support for MyChain'`)
6. Push to the branch (`git push origin feature/my-new-chain`)
7. Create a Pull Request

---

## License

This project is licensed under the MIT License -- see the [LICENSE](LICENSE) file for details.
