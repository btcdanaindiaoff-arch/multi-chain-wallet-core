#include "wallet/chains/ChainRegistry.h"

namespace wallet {

ChainRegistry& ChainRegistry::instance() {
    static ChainRegistry registry;
    return registry;
}

void ChainRegistry::registerChain(std::unique_ptr<IChain> chain) {
    if (chain) {
        uint32_t ct = chain->coinType();
        chains_[ct] = std::move(chain);
    }
}

IChain* ChainRegistry::getChain(uint32_t coinType) const {
    auto it = chains_.find(coinType);
    if (it != chains_.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<std::string> ChainRegistry::listChains() const {
    std::vector<std::string> names;
    names.reserve(chains_.size());
    for (const auto& [ct, chain] : chains_) {
        names.push_back(chain->chainName());
    }
    return names;
}

} // namespace wallet
