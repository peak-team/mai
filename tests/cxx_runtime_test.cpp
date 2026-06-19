#include "malloc_interceptor.h"

#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

struct alignas(128) OverAlignedBlock {
    unsigned char data[8192];
};

static int load_stats(MaiStats* stats) {
    return mai_get_stats_sized(stats, sizeof(*stats));
}

static bool aligned_ptr(void* ptr, std::size_t alignment) {
    return (reinterpret_cast<std::uintptr_t>(ptr) & (alignment - 1)) == 0;
}

int main() {
    MaiStats before{};
    MaiStats after{};
    if (load_stats(&before) != 0) {
        return 1;
    }

    auto* bytes = new unsigned char[8192];
    for (std::size_t i = 0; i < 8192; i++) {
        bytes[i] = static_cast<unsigned char>(i & 0xff);
    }
    for (std::size_t i = 0; i < 8192; i++) {
        if (bytes[i] != static_cast<unsigned char>(i & 0xff)) {
            delete[] bytes;
            return 1;
        }
    }
    delete[] bytes;

    auto* object = new OverAlignedBlock();
    if (!aligned_ptr(object, alignof(OverAlignedBlock))) {
        delete object;
        return 1;
    }
    std::memset(object->data, 0xa5, sizeof(object->data));
    delete object;

    auto* nothrow_bytes = new (std::nothrow) unsigned char[8192];
    if (!nothrow_bytes) {
        return 1;
    }
    delete[] nothrow_bytes;

    void* explicit_new = ::operator new(8192);
    std::memset(explicit_new, 0x42, 8192);
    ::operator delete(explicit_new, static_cast<std::size_t>(8192));

    void* explicit_array_new = ::operator new[](8192);
    std::memset(explicit_array_new, 0x43, 8192);
    ::operator delete[](explicit_array_new, static_cast<std::size_t>(8192));

    void* explicit_aligned_new =
        ::operator new(8192, std::align_val_t{256});
    if (!aligned_ptr(explicit_aligned_new, 256)) {
        ::operator delete(explicit_aligned_new, std::align_val_t{256});
        return 1;
    }
    std::memset(explicit_aligned_new, 0x44, 8192);
    ::operator delete(explicit_aligned_new, static_cast<std::size_t>(8192),
                      std::align_val_t{256});

    void* explicit_aligned_nothrow =
        ::operator new[](8192, std::align_val_t{256}, std::nothrow);
    if (!explicit_aligned_nothrow || !aligned_ptr(explicit_aligned_nothrow, 256)) {
        ::operator delete[](explicit_aligned_nothrow, std::align_val_t{256},
                            std::nothrow);
        return 1;
    }
    std::memset(explicit_aligned_nothrow, 0x45, 8192);
    ::operator delete[](explicit_aligned_nothrow, std::align_val_t{256},
                        std::nothrow);

    MaiStats before_vector{};
    if (load_stats(&before_vector) != 0) {
        return 1;
    }
    {
        std::vector<unsigned char> vector_bytes(8192);
        for (std::size_t i = 0; i < vector_bytes.size(); i++) {
            vector_bytes[i] = static_cast<unsigned char>((i * 3) & 0xff);
        }
        for (std::size_t i = 0; i < vector_bytes.size(); i++) {
            if (vector_bytes[i] != static_cast<unsigned char>((i * 3) & 0xff)) {
                return 1;
            }
        }
    }
    MaiStats after_vector{};
    if (load_stats(&after_vector) != 0 ||
        after_vector.managed_allocations <= before_vector.managed_allocations ||
        after_vector.managed_frees <= before_vector.managed_frees ||
        after_vector.managed_bytes_total < before_vector.managed_bytes_total + 8192 ||
        after_vector.live_managed_bytes != before_vector.live_managed_bytes) {
        return 1;
    }

    if (load_stats(&after) != 0) {
        return 1;
    }
    if (after.managed_allocations <= before.managed_allocations ||
        after.managed_frees <= before.managed_frees ||
        after.managed_bytes_total < before.managed_bytes_total + 8192 * 8 ||
        after.live_managed_bytes != before.live_managed_bytes) {
        return 1;
    }

    return 0;
}
