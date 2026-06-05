#include "malloc_interceptor.h"

#include <cstdint>
#include <cstring>
#include <new>

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

    if (load_stats(&after) != 0) {
        return 1;
    }
    if (after.managed_allocations <= before.managed_allocations ||
        after.managed_frees <= before.managed_frees) {
        return 1;
    }

    return 0;
}
