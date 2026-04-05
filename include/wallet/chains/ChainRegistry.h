#pragma once
#ifndef WALLET_CHAINS_CHAINREGISTRY_H
#define WALLET_CHAINS_CHAINREGISTRY_H

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "wallet/chains/IChain.h"

namespace wallet {

/// @brief Singleton registry for blockchain implementations.
///
/// Allows runtime registration and lookup of IChain implementations
/// keyed by their SLIP-44 coin type.  This enables the wallet core to
/// support new chains without recompilation by registering them at
/// startup.
class ChainRegistry {
public:
    /// Obtain the global registry instance.
    static ChainRegistry& instance();

    /// Register a chain implementation.  Ownership is transferred to the
    /// registry.  If a chain with the same coinType is already registered
    /// it will be replaced.
    /// @param chain  Unique pointer to an IChain implementation.
    void registerChain(std::unique_ptr<IChain> chain);

    /// Look up a chain by SLIP-44 coin type.
    /// @param coinType  The coin type to search for.
    /// @return Pointer to the chain, or nullptr if not registered.
    IChain* getChain(uint32_t coinType) const;

    /// Return the human-readable names of all registered chains.
    std::vector<std::string> listChains() const;

    // Non-copyable, non-movable singleton.
    ChainRegistry(const ChainRegistry&) = delete;
    ChainRegistry& operator=(const ChainRegistry&) = delete;

private:
    ChainRegistry() = default;

    std::unordered_map<uint32_t, std::unique_ptr<IChain>> chains_;
};

} // namespace wallet

#endif // WALLET_CHAINS_CHAINREGISTRY_H
