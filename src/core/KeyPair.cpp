#include "wallet/core/KeyPair.h"
#include "wallet/chains/ChainRegistry.h"

namespace wallet {

std::string KeyPair::getAddress(uint32_t coinType) const {
    // Delegate to the chain registered for this coin type.
    auto* chain = ChainRegistry::instance().getChain(coinType);
    if (chain) {
        return chain->deriveAddress(publicKey);
    }
    // TODO: Throw or return empty if chain not registered.
    return "";
}

} // namespace wallet
