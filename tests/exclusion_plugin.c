#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define MAI_TEST_EXPORT __attribute__((visibility("default")))
#else
#define MAI_TEST_EXPORT
#endif

typedef struct {
    void* addr;
    size_t length;
} FakeMr;

MAI_TEST_EXPORT int cudaHostAlloc(void** ptr, size_t size, unsigned int flags) {
    (void)flags;
    if (!ptr) {
        return 1;
    }
    *ptr = malloc(size);
    if (!*ptr) {
        return 2;
    }
    memset(*ptr, 0x43, size);
    return 0;
}

MAI_TEST_EXPORT int cudaMallocHost(void** ptr, size_t size) {
    return cudaHostAlloc(ptr, size, 0);
}

MAI_TEST_EXPORT int cudaHostRegister(void* ptr, size_t size, unsigned int flags) {
    (void)size;
    (void)flags;
    return ptr ? 0 : 1;
}

MAI_TEST_EXPORT int cudaHostUnregister(void* ptr) {
    return ptr ? 0 : 1;
}

MAI_TEST_EXPORT int cudaFreeHost(void* ptr) {
    free(ptr);
    return 0;
}

MAI_TEST_EXPORT void* ibv_reg_mr(void* pd, void* addr, size_t length, int access) {
    (void)pd;
    (void)access;
    if (!addr || length == 0) {
        return NULL;
    }

    FakeMr* mr = malloc(sizeof(*mr));
    if (!mr) {
        return NULL;
    }
    mr->addr = addr;
    mr->length = length;
    return mr;
}

MAI_TEST_EXPORT void* ibv_reg_mr_iova(void* pd, void* addr, size_t length, uint64_t iova,
                                      int access) {
    (void)iova;
    return ibv_reg_mr(pd, addr, length, access);
}

MAI_TEST_EXPORT int ibv_dereg_mr(void* mr) {
    free(mr);
    return 0;
}

MAI_TEST_EXPORT int MPI_Alloc_mem(intptr_t size, void* info, void* baseptr) {
    (void)info;
    if (!baseptr || size <= 0) {
        return 1;
    }

    void* ptr = malloc((size_t)size);
    if (!ptr) {
        return 2;
    }
    memset(ptr, 0x4d, (size_t)size);
    *(void**)baseptr = ptr;
    return 0;
}

MAI_TEST_EXPORT int MPI_Free_mem(void* base) {
    free(base);
    return 0;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_register(void* ptr, size_t size) {
    return cudaHostRegister(ptr, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_unregister(void* ptr) {
    return cudaHostUnregister(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_alloc(size_t size, void** out) {
    return cudaHostAlloc(out, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_free(void* ptr) {
    return cudaFreeHost(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_register(void* ptr, size_t size,
                                                       void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = ibv_reg_mr(NULL, ptr, size, 0);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_deregister(void* mr) {
    return ibv_dereg_mr(mr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_mpi_alloc(size_t size, void** out) {
    return MPI_Alloc_mem((intptr_t)size, NULL, out);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_mpi_free(void* ptr) {
    return MPI_Free_mem(ptr);
}
