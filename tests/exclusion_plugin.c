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

MAI_TEST_EXPORT int cudaMallocManaged(void** ptr, size_t size, unsigned int flags) {
    (void)flags;
    if (!ptr) {
        return 1;
    }
    *ptr = malloc(size);
    if (!*ptr) {
        return 2;
    }
    memset(*ptr, 0xca, size);
    return 0;
}

MAI_TEST_EXPORT int cudaFree(void* ptr) {
    free(ptr);
    return 0;
}

MAI_TEST_EXPORT int hipHostMalloc(void** ptr, size_t size, unsigned int flags) {
    (void)flags;
    if (!ptr) {
        return 1;
    }
    *ptr = malloc(size);
    if (!*ptr) {
        return 2;
    }
    memset(*ptr, 0x48, size);
    return 0;
}

MAI_TEST_EXPORT int hipHostRegister(void* ptr, size_t size, unsigned int flags) {
    (void)size;
    (void)flags;
    return ptr ? 0 : 1;
}

MAI_TEST_EXPORT int hipHostUnregister(void* ptr) {
    return ptr ? 0 : 1;
}

MAI_TEST_EXPORT int hipHostFree(void* ptr) {
    free(ptr);
    return 0;
}

MAI_TEST_EXPORT int hipMallocManaged(void** ptr, size_t size, unsigned int flags) {
    (void)flags;
    if (!ptr) {
        return 1;
    }
    *ptr = malloc(size);
    if (!*ptr) {
        return 2;
    }
    memset(*ptr, 0x68, size);
    return 0;
}

MAI_TEST_EXPORT int hipFree(void* ptr) {
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

MAI_TEST_EXPORT int ibv_rereg_mr(void* mr, int flags, void* pd, void* addr,
                                 size_t length, int access) {
    (void)flags;
    (void)pd;
    (void)access;
    if (!mr || !addr || length == 0) {
        return 1;
    }

    FakeMr* fake = (FakeMr*)mr;
    fake->addr = addr;
    fake->length = length;
    return 0;
}

MAI_TEST_EXPORT int ibv_dereg_mr(void* mr) {
    free(mr);
    return 0;
}

MAI_TEST_EXPORT void* rdma_reg_msgs(void* id, void* addr, size_t length) {
    return ibv_reg_mr(id, addr, length, 0);
}

MAI_TEST_EXPORT void* rdma_reg_read(void* id, void* addr, size_t length) {
    return ibv_reg_mr(id, addr, length, 0);
}

MAI_TEST_EXPORT void* rdma_reg_write(void* id, void* addr, size_t length) {
    return ibv_reg_mr(id, addr, length, 0);
}

MAI_TEST_EXPORT int rdma_dereg_mr(void* mr) {
    return ibv_dereg_mr(mr);
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

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_managed_alloc(size_t size, void** out) {
    return cudaMallocManaged(out, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_cuda_managed_free(void* ptr) {
    return cudaFree(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_register(void* ptr, size_t size) {
    return hipHostRegister(ptr, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_unregister(void* ptr) {
    return hipHostUnregister(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_alloc(size_t size, void** out) {
    return hipHostMalloc(out, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_free(void* ptr) {
    return hipHostFree(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_managed_alloc(size_t size, void** out) {
    return hipMallocManaged(out, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_hip_managed_free(void* ptr) {
    return hipFree(ptr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_register(void* ptr, size_t size,
                                                       void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = ibv_reg_mr(NULL, ptr, size, 0);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_register_iova(void* ptr, size_t size,
                                                            void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = ibv_reg_mr_iova(NULL, ptr, size, (uint64_t)(uintptr_t)ptr, 0);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_reregister(void* mr, void* ptr,
                                                         size_t size) {
    return ibv_rereg_mr(mr, 0, NULL, ptr, size, 0);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_deregister(void* mr) {
    return ibv_dereg_mr(mr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_cm_msgs(void* ptr, size_t size,
                                                      void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = rdma_reg_msgs(NULL, ptr, size);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_cm_read(void* ptr, size_t size,
                                                      void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = rdma_reg_read(NULL, ptr, size);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_cm_write(void* ptr, size_t size,
                                                       void** out_mr) {
    if (!out_mr) {
        return 1;
    }
    *out_mr = rdma_reg_write(NULL, ptr, size);
    return *out_mr ? 0 : 2;
}

MAI_TEST_EXPORT int mai_exclusion_plugin_rdma_cm_deregister(void* mr) {
    return rdma_dereg_mr(mr);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_mpi_alloc(size_t size, void** out) {
    return MPI_Alloc_mem((intptr_t)size, NULL, out);
}

MAI_TEST_EXPORT int mai_exclusion_plugin_mpi_free(void* ptr) {
    return MPI_Free_mem(ptr);
}
