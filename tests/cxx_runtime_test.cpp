#include "malloc_interceptor.h"

#include <cstdint>
#include <cstring>
#include <new>
#include <vector>

struct alignas(128) OverAlignedBlock {
    unsigned char data[8192];
};

static int load_stats(MaiStats* stats) {
    return mai_get_stats(stats);
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
        after.managed_bytes_total < before.managed_bytes_total + 8192 * 4 ||
        after.live_managed_bytes != before.live_managed_bytes) {
        return 1;
    }

    return 0;
}
