#pragma once
#ifndef WALLET_CORE_SECUREALLOCATOR_H
#define WALLET_CORE_SECUREALLOCATOR_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace wallet {

/// @brief STL-compatible allocator that zeros memory on deallocation.
///
/// Prevents sensitive cryptographic material (seeds, private keys) from
/// lingering in freed heap memory.  Uses volatile memset to resist
/// compiler dead-store elimination.
///
/// @tparam T  Element type.
template <typename T>
class SecureAllocator {
public:
    using value_type      = T;
    using pointer         = T*;
    using const_pointer   = const T*;
    using reference       = T&;
    using const_reference = const T&;
    using size_type       = std::size_t;
    using difference_type = std::ptrdiff_t;

    template <typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    pointer allocate(size_type n) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        pointer p = static_cast<pointer>(::operator new(n * sizeof(T)));
        if (!p) {
            throw std::bad_alloc();
        }
        return p;
    }

    void deallocate(pointer p, size_type n) noexcept {
        if (p) {
            // Zero memory before releasing.  The volatile cast prevents the
            // compiler from optimising this away as a dead store.
            volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
            for (size_type i = 0; i < n * sizeof(T); ++i) {
                vp[i] = 0;
            }
            ::operator delete(p);
        }
    }

    size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

/// Convenience alias for a byte vector that securely wipes its contents
/// when the memory is freed.
using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

} // namespace wallet

#endif // WALLET_CORE_SECUREALLOCATOR_H
