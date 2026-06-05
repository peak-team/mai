#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*get_stats_fn)(MaiStats*);
typedef int (*reclaim_all_fn)(void);
typedef int (*sample_hotness_fn)(void);
typedef void* (*plugin_alloc_fn)(size_t);
typedef size_t (*plugin_usable_fn)(void*);
typedef void (*plugin_free_fn)(void*);
typedef int (*plugin_register_fn)(void*, size_t);
typedef int (*plugin_unregister_fn)(void*);
typedef int (*plugin_alloc_out_fn)(size_t, void**);
typedef int (*plugin_free_status_fn)(void*);
typedef int (*plugin_rdma_register_fn)(void*, size_t, void**);
typedef int (*plugin_rdma_reregister_fn)(void*, void*, size_t);
typedef int (*runtime_register_fn)(void*, size_t, unsigned int);
typedef int (*runtime_alloc_out_fn)(void**, size_t, unsigned int);
typedef int (*runtime_mpi_alloc_fn)(intptr_t, void*, void*);
typedef void* (*runtime_ibv_register_fn)(void*, void*, size_t, int);
typedef int (*runtime_ibv_reregister_fn)(void*, int, void*, void*, size_t, int);
typedef void* (*runtime_rdma_register_fn)(void*, void*, size_t);
typedef int (*runtime_status_ptr_fn)(void*);

static int fail(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int skip(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 77;
}

static int has_prefix(const char* value, const char* prefix) {
    return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int load_stats(MaiStats* stats) {
    get_stats_fn get_stats = (get_stats_fn)dlsym(RTLD_DEFAULT, "mai_get_stats");
    if (!get_stats) {
        return -1;
    }
    return get_stats(stats);
}

static int visible_arena_files(void) {
    const char* path = getenv("MAI_PATH");
    if (!path) {
        return 0;
    }

    DIR* dir = opendir(path);
    if (!dir) {
        return -1;
    }

    int count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (has_prefix(entry->d_name, "mai-arena-")) {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static int aligned_ptr(void* ptr, size_t alignment) {
    return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

static int stats_show_managed_alloc(const MaiStats* before, const MaiStats* after, size_t size) {
    return after->managed_allocations > before->managed_allocations &&
           after->managed_bytes_total >= before->managed_bytes_total + size &&
           after->live_managed_bytes >= before->live_managed_bytes + size &&
           after->arena_segments > 0;
}

static int stats_show_managed_free(const MaiStats* before, const MaiStats* after_alloc,
                                   const MaiStats* after_free, size_t size) {
    return after_free->managed_frees > before->managed_frees &&
           after_alloc->live_managed_bytes >= after_free->live_managed_bytes + size;
}

static int stats_show_exclusion(const MaiStats* before, const MaiStats* after, size_t size) {
    return after->excluded_ranges > before->excluded_ranges &&
           after->exclusion_events > before->exclusion_events &&
           after->excluded_bytes >= before->excluded_bytes + size;
}

static int run_plugin_rdma_cycle(plugin_rdma_register_fn register_fn,
                                 plugin_free_status_fn deregister_fn,
                                 void* ptr,
                                 size_t size,
                                 const MaiStats* before,
                                 MaiStats* after_free,
                                 const char* register_failure,
                                 const char* stats_register_failure,
                                 const char* exclusion_failure,
                                 const char* deregister_failure,
                                 const char* stats_free_failure,
                                 const char* release_failure) {
    void* mr = NULL;
    MaiStats after_register;

    if (register_fn(ptr, size, &mr) != 0 || !mr) {
        return fail(register_failure);
    }
    if (load_stats(&after_register) != 0) {
        deregister_fn(mr);
        return fail(stats_register_failure);
    }
    if (!stats_show_exclusion(before, &after_register, size)) {
        deregister_fn(mr);
        return fail(exclusion_failure);
    }
    if (deregister_fn(mr) != 0) {
        return fail(deregister_failure);
    }
    if (load_stats(after_free) != 0) {
        return fail(stats_free_failure);
    }
    if (after_free->exclusion_release_events <= after_register.exclusion_release_events) {
        return fail(release_failure);
    }

    return 0;
}

static int mode_disabled(void) {
    MaiStats stats;
    void* ptr = malloc(8192);
    if (!ptr) {
        return fail("malloc failed while MAI should be disabled");
    }
    free(ptr);

    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats is unavailable");
    }
    if (stats.enabled != 0 || stats.config_error != 1) {
        return fail("invalid config did not disable MAI");
    }

    return 0;
}

static int mode_small(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed");
    }

    void* ptr = malloc(128);
    if (!ptr) {
        return fail("small malloc failed");
    }
    memset(ptr, 0x11, 128);
    free(ptr);

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after small allocation");
    }
    if (after.managed_allocations != before.managed_allocations) {
        return fail("small allocation was routed to MAI arena");
    }

    return 0;
}

static int mode_pass_through_stats_default_off(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before default pass-through stats test");
    }

    void* ptr = malloc(128);
    if (!ptr) {
        return fail("small malloc failed in default pass-through stats test");
    }
    free(ptr);

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after default pass-through stats test");
    }
    if (after.managed_allocations != before.managed_allocations) {
        return fail("default pass-through stats test routed a small allocation to MAI arena");
    }
    if (after.pass_through_allocations != before.pass_through_allocations ||
        after.pass_through_bytes_total != before.pass_through_bytes_total) {
        return fail("pass-through counters changed while MAI_STATS was disabled");
    }

    return 0;
}

static int mode_preload_symbols(void) {
    static const char* symbols[] = {
        "malloc",
        "free",
        "calloc",
        "realloc",
        "malloc_usable_size",
        "mlock",
        "mlock2",
        "mlockall",
        "munlock",
        "munlockall",
        "cudaHostRegister",
        "cudaHostUnregister",
        "cudaHostAlloc",
        "cudaMallocHost",
        "cudaFreeHost",
        "cudaMallocManaged",
        "cudaFree",
        "hipHostRegister",
        "hipHostUnregister",
        "hipHostMalloc",
        "hipHostFree",
        "hipMallocManaged",
        "hipFree",
        "MPI_Alloc_mem",
        "MPI_Free_mem",
        "ibv_reg_mr",
        "ibv_reg_mr_iova",
        "ibv_rereg_mr",
        "ibv_dereg_mr",
        "rdma_reg_msgs",
        "rdma_reg_read",
        "rdma_reg_write",
        "rdma_dereg_mr",
        NULL
    };

    for (size_t i = 0; symbols[i]; i++) {
        void* symbol = dlsym(RTLD_DEFAULT, symbols[i]);
        Dl_info info;
        if (!symbol || dladdr(symbol, &info) == 0 || !info.dli_fname ||
            !strstr(info.dli_fname, "libmai")) {
            fprintf(stderr, "%s resolved to %s\n", symbols[i],
                    info.dli_fname ? info.dli_fname : "?");
            return fail("allocator symbol did not resolve to libmai preload wrapper");
        }
    }

    return 0;
}

static int mode_missing_safety_symbols(void) {
    runtime_register_fn cuda_register =
        (runtime_register_fn)dlsym(RTLD_DEFAULT, "cudaHostRegister");
    runtime_alloc_out_fn cuda_host_alloc =
        (runtime_alloc_out_fn)dlsym(RTLD_DEFAULT, "cudaHostAlloc");
    runtime_alloc_out_fn cuda_managed_alloc =
        (runtime_alloc_out_fn)dlsym(RTLD_DEFAULT, "cudaMallocManaged");
    runtime_register_fn hip_register =
        (runtime_register_fn)dlsym(RTLD_DEFAULT, "hipHostRegister");
    runtime_alloc_out_fn hip_host_alloc =
        (runtime_alloc_out_fn)dlsym(RTLD_DEFAULT, "hipHostMalloc");
    runtime_alloc_out_fn hip_managed_alloc =
        (runtime_alloc_out_fn)dlsym(RTLD_DEFAULT, "hipMallocManaged");
    runtime_mpi_alloc_fn mpi_alloc =
        (runtime_mpi_alloc_fn)dlsym(RTLD_DEFAULT, "MPI_Alloc_mem");
    runtime_ibv_register_fn ibv_register =
        (runtime_ibv_register_fn)dlsym(RTLD_DEFAULT, "ibv_reg_mr");
    runtime_ibv_reregister_fn ibv_reregister =
        (runtime_ibv_reregister_fn)dlsym(RTLD_DEFAULT, "ibv_rereg_mr");
    runtime_rdma_register_fn rdma_reg_msgs =
        (runtime_rdma_register_fn)dlsym(RTLD_DEFAULT, "rdma_reg_msgs");
    runtime_rdma_register_fn rdma_reg_read =
        (runtime_rdma_register_fn)dlsym(RTLD_DEFAULT, "rdma_reg_read");
    runtime_rdma_register_fn rdma_reg_write =
        (runtime_rdma_register_fn)dlsym(RTLD_DEFAULT, "rdma_reg_write");
    runtime_status_ptr_fn rdma_deregister =
        (runtime_status_ptr_fn)dlsym(RTLD_DEFAULT, "rdma_dereg_mr");

    if (!cuda_register || !cuda_host_alloc || !cuda_managed_alloc ||
        !hip_register || !hip_host_alloc || !hip_managed_alloc ||
        !mpi_alloc || !ibv_register || !ibv_reregister ||
        !rdma_reg_msgs || !rdma_reg_read || !rdma_reg_write || !rdma_deregister) {
        return fail("safety preload wrappers are not exported");
    }

    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_calls;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before missing safety symbol test");
    }

    void* ptr = malloc(8192);
    if (!ptr) {
        return fail("missing safety symbol managed allocation failed");
    }
    memset(ptr, 0x21, 8192);

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after missing safety allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, 8192)) {
        free(ptr);
        return fail("missing safety symbol test allocation was not MAI-managed");
    }

    void* out = NULL;
    if (cuda_register(ptr, 8192, 0) == 0 ||
        cuda_host_alloc(&out, 8192, 0) == 0 ||
        cuda_managed_alloc(&out, 8192, 0) == 0 ||
        hip_register(ptr, 8192, 0) == 0 ||
        hip_host_alloc(&out, 8192, 0) == 0 ||
        hip_managed_alloc(&out, 8192, 0) == 0 ||
        mpi_alloc((intptr_t)8192, NULL, &out) == 0 ||
        ibv_register(NULL, ptr, 8192, 0) != NULL ||
        ibv_reregister((void*)0x1, 0, NULL, ptr, 8192, 0) == 0 ||
        rdma_reg_msgs(NULL, ptr, 8192) != NULL ||
        rdma_reg_read(NULL, ptr, 8192) != NULL ||
        rdma_reg_write(NULL, ptr, 8192) != NULL ||
        rdma_deregister((void*)0x1) == 0) {
        free(ptr);
        return fail("missing safety runtime call unexpectedly succeeded");
    }

    if (load_stats(&after_calls) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after missing safety calls");
    }
    if (after_calls.exclusion_events != after_alloc.exclusion_events ||
        after_calls.excluded_ranges != after_alloc.excluded_ranges ||
        after_calls.excluded_bytes != after_alloc.excluded_bytes) {
        free(ptr);
        return fail("failed safety runtime calls created exclusions");
    }

    free(ptr);
    return 0;
}

static int mode_preload_path_stats(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before preload path stats test");
    }
    if (before.allocator_hook_mode != 1) {
        return fail("default allocator hook mode is not direct preload");
    }
    if (before.allocator_libc_patches != 0) {
        return fail("default preload mode unexpectedly patched libc allocator symbols");
    }

    void* ptr = malloc(128);
    if (!ptr) {
        return fail("preload path stats malloc failed");
    }
    free(ptr);

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after preload path stats test");
    }
    if (after.allocator_preload_calls <= before.allocator_preload_calls) {
        return fail("direct preload allocator path was not counted");
    }
    if (after.allocator_frida_calls != before.allocator_frida_calls) {
        return fail("direct preload small allocation unexpectedly used Frida path");
    }

    return 0;
}

static int mode_frida_hook_mode(void) {
    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed in Frida hook mode test");
    }
    if (stats.allocator_hook_mode != 2) {
        return fail("forced Frida allocator hook mode was not recorded");
    }
    if (stats.allocator_libc_patches == 0) {
        return fail("forced Frida allocator hook mode did not patch libc allocator symbols");
    }

    return 0;
}

static int mode_large(void) {
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed");
    }

    unsigned char* ptr = malloc(8192);
    if (!ptr) {
        return fail("large malloc failed");
    }
    if (malloc_usable_size(ptr) < 8192) {
        free(ptr);
        return fail("malloc_usable_size did not report usable size for managed allocation");
    }
    for (size_t i = 0; i < 8192; i++) {
        ptr[i] = (unsigned char)(i & 0xff);
    }

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after large allocation");
    }
    if (after_alloc.managed_allocations <= before.managed_allocations ||
        after_alloc.live_managed_bytes < before.live_managed_bytes + 8192 ||
        after_alloc.arena_segments == 0) {
        free(ptr);
        return fail("large allocation was not routed to MAI arena");
    }
    if (visible_arena_files() != 0) {
        free(ptr);
        return fail("arena files should not remain visible after mmap");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes) {
        return fail("managed live bytes did not return to baseline");
    }

    return 0;
}

static int mode_calloc(void) {
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before calloc test");
    }

    unsigned char* ptr = calloc(1, 8192);
    if (!ptr) {
        return fail("large calloc failed");
    }
    for (size_t i = 0; i < 8192; i++) {
        if (ptr[i] != 0) {
            free(ptr);
            return fail("calloc memory was not zeroed");
        }
    }
    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after calloc allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, 8192)) {
        free(ptr);
        return fail("large calloc was not routed to MAI arena");
    }
    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after calloc free");
    }
    if (!stats_show_managed_free(&before, &after_alloc, &after_free, 8192) ||
        after_free.live_managed_bytes != before.live_managed_bytes) {
        return fail("large calloc free did not release MAI-managed bytes");
    }

    volatile size_t overflow_nmemb = (SIZE_MAX / 2) + 1;
    volatile size_t overflow_size = 3;
    errno = 0;
    void* overflow = calloc(overflow_nmemb, overflow_size);
    if (overflow || errno != ENOMEM) {
        free(overflow);
        return fail("calloc overflow did not fail with ENOMEM");
    }

    return 0;
}

static int mode_realloc(void) {
    MaiStats before;
    MaiStats after_grow;
    MaiStats after_free;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before realloc test");
    }

    unsigned char* ptr = malloc(128);
    if (!ptr) {
        return fail("initial malloc failed");
    }
    for (size_t i = 0; i < 128; i++) {
        ptr[i] = (unsigned char)i;
    }

    unsigned char* grown = realloc(ptr, 8192);
    if (!grown) {
        free(ptr);
        return fail("realloc to managed allocation failed");
    }
    for (size_t i = 0; i < 128; i++) {
        if (grown[i] != (unsigned char)i) {
            free(grown);
            return fail("realloc to managed did not preserve contents");
        }
    }
    if (load_stats(&after_grow) != 0) {
        free(grown);
        return fail("mai_get_stats failed after realloc to managed allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_grow, 8192)) {
        free(grown);
        return fail("realloc growth was not routed to MAI arena");
    }

    unsigned char* grown_again = realloc(grown, 16384);
    if (!grown_again) {
        free(grown);
        return fail("managed realloc grow failed");
    }
    for (size_t i = 0; i < 128; i++) {
        if (grown_again[i] != (unsigned char)i) {
            free(grown_again);
            return fail("managed realloc grow did not preserve contents");
        }
    }

    unsigned char* shrunk = realloc(grown_again, 1024);
    if (!shrunk) {
        free(grown_again);
        return fail("managed realloc shrink failed");
    }
    for (size_t i = 0; i < 128; i++) {
        if (shrunk[i] != (unsigned char)i) {
            free(shrunk);
            return fail("managed realloc shrink did not preserve contents");
        }
    }

    free(shrunk);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after realloc free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.managed_frees <= before.managed_frees) {
        return fail("managed realloc free did not release MAI-managed bytes");
    }
    free(NULL);
    return 0;
}

static int mode_alignment(void) {
    MaiStats before_small;
    MaiStats after_small;
    if (load_stats(&before_small) != 0) {
        return fail("mai_get_stats failed before small alignment test");
    }

    void* small_aligned = aligned_alloc(4, 128);
    if (!small_aligned || !aligned_ptr(small_aligned, 4)) {
        free(small_aligned);
        return fail("below-threshold aligned_alloc did not preserve small-alignment libc behavior");
    }
    free(small_aligned);

    void* small_memalign = memalign(4, 128);
    if (!small_memalign || !aligned_ptr(small_memalign, 4)) {
        free(small_memalign);
        return fail("below-threshold memalign did not preserve small-alignment libc behavior");
    }
    free(small_memalign);

    if (load_stats(&after_small) != 0) {
        return fail("mai_get_stats failed after small alignment test");
    }
    if (after_small.pass_through_allocations < before_small.pass_through_allocations + 2) {
        return fail("below-threshold alignment calls were not counted as pass-through allocations");
    }

    void* aligned = aligned_alloc(64, 8192);
    if (!aligned || !aligned_ptr(aligned, 64)) {
        free(aligned);
        return fail("aligned_alloc did not return a 64-byte aligned pointer");
    }
    memset(aligned, 0xa5, 8192);
    free(aligned);

    errno = 0;
    void* invalid = aligned_alloc(64, 8193);
    if (invalid || errno != EINVAL) {
        free(invalid);
        return fail("invalid aligned_alloc did not fail with EINVAL");
    }

    void* unchanged = (void*)0x1234;
    int ret = posix_memalign(&unchanged, 3, 8192);
    if (ret != EINVAL || unchanged != (void*)0x1234) {
        return fail("invalid posix_memalign did not return EINVAL without changing memptr");
    }

    void* posix_ptr = NULL;
    ret = posix_memalign(&posix_ptr, 128, 8192);
    if (ret != 0 || !posix_ptr || !aligned_ptr(posix_ptr, 128)) {
        free(posix_ptr);
        return fail("posix_memalign did not return a 128-byte aligned pointer");
    }
    memset(posix_ptr, 0x5a, 8192);
    free(posix_ptr);

    void* memalign_ptr = memalign(256, 8192);
    if (!memalign_ptr || !aligned_ptr(memalign_ptr, 256)) {
        free(memalign_ptr);
        return fail("memalign did not return a 256-byte aligned pointer");
    }
    free(memalign_ptr);

    void* valloc_ptr = valloc(8192);
    long page_size = sysconf(_SC_PAGESIZE);
    if (!valloc_ptr || !aligned_ptr(valloc_ptr, (size_t)page_size)) {
        free(valloc_ptr);
        return fail("valloc did not return a page-aligned pointer");
    }
    free(valloc_ptr);

    void* pvalloc_ptr = pvalloc(8193);
    if (!pvalloc_ptr || !aligned_ptr(pvalloc_ptr, (size_t)page_size)) {
        free(pvalloc_ptr);
        return fail("pvalloc did not return a page-aligned pointer");
    }
    free(pvalloc_ptr);

    return 0;
}

static int mode_many(void) {
    enum { count = 256 };
    void* ptrs[count];
    memset(ptrs, 0, sizeof(ptrs));

    for (int i = 0; i < count; i++) {
        ptrs[i] = malloc(8192);
        if (!ptrs[i]) {
            return fail("many allocation loop failed");
        }
        memset(ptrs[i], i, 8192);
    }

    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed in many mode");
    }
    if (stats.managed_allocations < count || stats.arena_segments >= count / 2) {
        return fail("many large allocations did not use shared arena segments");
    }
    if (visible_arena_files() != 0) {
        return fail("many allocations left visible arena files");
    }

    for (int i = 0; i < count; i++) {
        free(ptrs[i]);
    }

    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed after many frees");
    }
    if (stats.live_managed_bytes != 0) {
        return fail("many allocation frees leaked managed live bytes");
    }

    return 0;
}

static void* thread_worker(void* arg) {
    uintptr_t id = (uintptr_t)arg;
    for (int i = 0; i < 128; i++) {
        unsigned char* ptr = malloc(8192);
        if (!ptr) {
            return (void*)1;
        }
        ptr[0] = (unsigned char)id;
        ptr[8191] = (unsigned char)i;
        if (ptr[0] != (unsigned char)id || ptr[8191] != (unsigned char)i) {
            free(ptr);
            return (void*)1;
        }
        free(ptr);
    }
    return NULL;
}

static int mode_thread(void) {
    enum { thread_count = 4 };
    pthread_t threads[thread_count];

    for (uintptr_t i = 0; i < thread_count; i++) {
        if (pthread_create(&threads[i], NULL, thread_worker, (void*)i) != 0) {
            return fail("pthread_create failed");
        }
    }

    for (int i = 0; i < thread_count; i++) {
        void* result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            return fail("thread allocation stress failed");
        }
    }

    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed after thread stress");
    }
    if (stats.live_managed_bytes != 0) {
        return fail("thread stress leaked managed live bytes");
    }

    return 0;
}

static void* small_thread_worker(void* arg) {
    uintptr_t id = (uintptr_t)arg;
    for (int i = 0; i < 256; i++) {
        unsigned char* ptr = malloc(128);
        if (!ptr) {
            return (void*)1;
        }
        ptr[0] = (unsigned char)id;
        ptr[127] = (unsigned char)i;
        if (ptr[0] != (unsigned char)id || ptr[127] != (unsigned char)i) {
            free(ptr);
            return (void*)1;
        }
        free(ptr);
    }
    return NULL;
}

static int mode_thread_small_stats(void) {
    enum { thread_count = 4, allocations_per_thread = 256 };
    pthread_t threads[thread_count];
    MaiStats before;
    MaiStats after;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before small thread stats test");
    }

    for (uintptr_t i = 0; i < thread_count; i++) {
        if (pthread_create(&threads[i], NULL, small_thread_worker, (void*)i) != 0) {
            return fail("pthread_create failed in small thread stats test");
        }
    }

    for (int i = 0; i < thread_count; i++) {
        void* result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            return fail("small thread allocation stress failed");
        }
    }

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after small thread stats test");
    }
    if (after.managed_allocations != before.managed_allocations) {
        return fail("small threaded allocations were routed to MAI arena");
    }
    if (after.pass_through_allocations <
        before.pass_through_allocations + thread_count * allocations_per_thread) {
        return fail("small threaded pass-through counters were not flushed");
    }

    return 0;
}

static int mode_reclaim(void) {
    reclaim_all_fn reclaim_all = (reclaim_all_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_all");
    if (!reclaim_all) {
        return fail("mai_reclaim_all is unavailable");
    }

    unsigned char* ptr = malloc(32768);
    if (!ptr) {
        return fail("reclaim allocation failed");
    }

    for (size_t i = 0; i < 32768; i++) {
        ptr[i] = (unsigned char)(i & 0xff);
    }

    if (reclaim_all() != 0) {
        free(ptr);
        return fail("mai_reclaim_all failed");
    }

    for (size_t i = 0; i < 32768; i++) {
        if (ptr[i] != (unsigned char)(i & 0xff)) {
            free(ptr);
            return fail("data changed after MADV_DONTNEED reclaim and re-access");
        }
    }

    MaiStats stats;
    if (load_stats(&stats) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after reclaim");
    }
    if (stats.reclaim_calls == 0) {
        free(ptr);
        return fail("reclaim call was not recorded");
    }

    free(ptr);
    return 0;
}

static int mode_mlock_exclusion(void) {
    return skip("real mlock syscall test is environment-dependent; preload_symbols covers exported mlock wrappers");
}

static int mode_target_rss(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before target RSS test");
    }

    void* ptrs[4];
    for (size_t i = 0; i < 4; i++) {
        ptrs[i] = calloc(1, 8192);
        if (!ptrs[i]) {
            return fail("target RSS allocation failed");
        }
    }

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after target RSS test");
    }
    if (after.target_rss == 0 || after.current_rss_bytes == 0 ||
        after.high_water_rss_bytes < after.current_rss_bytes ||
        after.policy_reclaim_calls <= before.policy_reclaim_calls ||
        after.reclaimed_bytes <= before.reclaimed_bytes) {
        return fail("target RSS policy reclaim did not run");
    }

    for (size_t i = 0; i < 4; i++) {
        unsigned char* ptr = ptrs[i];
        if (ptr[0] != 0 || ptr[8191] != 0) {
            return fail("target RSS reclaim corrupted allocation contents");
        }
        free(ptrs[i]);
    }

    return 0;
}

static int mode_profile(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before profile test");
    }

    void* first = malloc(8192);
    void* second = malloc(16384);
    if (!first || !second) {
        free(first);
        free(second);
        return fail("profile allocations failed");
    }
    free(first);
    free(second);

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after profile test");
    }
    if (after.profile_sites <= before.profile_sites) {
        return fail("profile site counter did not increase");
    }

    return 0;
}

static int mode_hotness(void) {
    sample_hotness_fn sample_hotness =
        (sample_hotness_fn)dlsym(RTLD_DEFAULT, "mai_sample_hotness");
    if (!sample_hotness) {
        return fail("mai_sample_hotness is unavailable");
    }

    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_sample;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before hotness test");
    }

    unsigned char* ptr = calloc(1, 32768);
    if (!ptr) {
        return fail("hotness allocation failed");
    }
    for (size_t i = 0; i < 32768; i += 4096) {
        ptr[i] = 0x4b;
    }

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after hotness allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, 32768)) {
        free(ptr);
        return fail("hotness allocation was not MAI-managed");
    }

    if (sample_hotness() != 0) {
        free(ptr);
        return fail("mai_sample_hotness failed");
    }
    if (load_stats(&after_sample) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after hotness sample");
    }
    if (after_sample.hotness_samples <= before.hotness_samples ||
        after_sample.hotness_sampled_pages <= before.hotness_sampled_pages ||
        after_sample.hotness_resident_pages <= before.hotness_resident_pages) {
        free(ptr);
        return fail("hotness sampling did not record resident managed pages");
    }

    free(ptr);
    return 0;
}

static int mode_hotness_live_exit(void) {
    unsigned char* ptr = calloc(1, 32768);
    if (!ptr) {
        return fail("hotness live-exit allocation failed");
    }
    for (size_t i = 0; i < 32768; i += 4096) {
        ptr[i] = 0x2a;
    }

    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed after hotness live-exit allocation");
    }
    if (stats.managed_allocations == 0 || stats.live_managed_bytes < 32768) {
        return fail("hotness live-exit allocation was not MAI-managed");
    }

    return 0;
}

static int mode_diagnostics(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before diagnostics test");
    }

    void* mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return fail("diagnostic mmap failed");
    }

#ifdef MREMAP_MAYMOVE
    void* remapped = mremap(mapping, 4096, 8192, MREMAP_MAYMOVE);
    if (remapped != MAP_FAILED) {
        mapping = remapped;
        munmap(mapping, 8192);
    } else {
        munmap(mapping, 4096);
    }
#else
    munmap(mapping, 4096);
#endif

    void* current_break = sbrk(0);
    if (current_break == (void*)-1) {
        return fail("sbrk(0) failed");
    }
    if (brk(current_break) != 0) {
        return fail("brk(current_break) failed");
    }

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after diagnostics test");
    }
    if (after.mmap_calls <= before.mmap_calls ||
        after.munmap_calls <= before.munmap_calls ||
        after.brk_calls <= before.brk_calls ||
        after.sbrk_calls <= before.sbrk_calls) {
        return fail("mmap/brk diagnostics counters did not increase");
    }

#ifdef MREMAP_MAYMOVE
    if (after.mremap_calls <= before.mremap_calls) {
        return fail("mremap diagnostics counter did not increase");
    }
#endif

    return 0;
}

static int mode_dlopen(void) {
    const char* plugin_path = getenv("MAI_TEST_PLUGIN");
    if (!plugin_path || plugin_path[0] == '\0') {
        return fail("MAI_TEST_PLUGIN is not set");
    }

    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before dlopen test");
    }

    void* handle = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return fail("dlopen plugin failed");
    }

    plugin_alloc_fn plugin_alloc = NULL;
    plugin_usable_fn plugin_usable = NULL;
    plugin_free_fn plugin_free = NULL;
    *(void**)(&plugin_alloc) = dlsym(handle, "mai_plugin_alloc");
    *(void**)(&plugin_usable) = dlsym(handle, "mai_plugin_usable");
    *(void**)(&plugin_free) = dlsym(handle, "mai_plugin_free");
    if (!plugin_alloc || !plugin_usable || !plugin_free) {
        dlclose(handle);
        return fail("dlsym plugin functions failed");
    }

    unsigned char* ptr = plugin_alloc(8192);
    if (!ptr) {
        dlclose(handle);
        return fail("plugin allocation failed");
    }
    if (ptr[0] != 0x3c || ptr[8191] != 0x3c) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("plugin allocation contents were not initialized");
    }
    if (plugin_usable(ptr) < 8192) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("plugin malloc_usable_size did not handle managed allocation");
    }

    if (load_stats(&after_alloc) != 0) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after plugin allocation");
    }
    if (after_alloc.managed_allocations <= before.managed_allocations) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("dlopened plugin allocation was not managed");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, 8192)) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("dlopened plugin allocation did not increase MAI managed bytes");
    }

    plugin_free(ptr);
    if (load_stats(&after_free) != 0) {
        dlclose(handle);
        return fail("mai_get_stats failed after plugin free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes) {
        dlclose(handle);
        return fail("dlopened plugin free leaked managed bytes");
    }
    if (!stats_show_managed_free(&before, &after_alloc, &after_free, 8192)) {
        dlclose(handle);
        return fail("dlopened plugin free did not release MAI-managed bytes");
    }

    dlclose(handle);
    return 0;
}

static int mode_dlopen_local_allocator(void) {
    const char* plugin_path = getenv("MAI_TEST_LOCAL_ALLOCATOR_PLUGIN");
    if (!plugin_path || plugin_path[0] == '\0') {
        return fail("MAI_TEST_LOCAL_ALLOCATOR_PLUGIN is not set");
    }

    void* handle = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return fail("dlopen local allocator plugin failed");
    }

    plugin_alloc_fn plugin_alloc = NULL;
    plugin_usable_fn plugin_usable = NULL;
    plugin_free_fn plugin_free = NULL;
    *(void**)(&plugin_alloc) = dlsym(handle, "mai_local_alloc");
    *(void**)(&plugin_usable) = dlsym(handle, "mai_local_usable");
    *(void**)(&plugin_free) = dlsym(handle, "mai_local_free");
    if (!plugin_alloc || !plugin_usable || !plugin_free) {
        dlclose(handle);
        return fail("dlsym local allocator plugin functions failed");
    }

    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    if (load_stats(&before) != 0) {
        dlclose(handle);
        return fail("mai_get_stats failed before local allocator plugin test");
    }

    unsigned char* ptr = plugin_alloc(8192);
    if (!ptr) {
        dlclose(handle);
        return fail("local allocator plugin allocation failed");
    }
    if (ptr[0] != 0x7d || ptr[8191] != 0x7d) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("local allocator plugin contents were not initialized");
    }
    if (plugin_usable(ptr) < 8192) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("dlopen refresh did not hook plugin-local malloc_usable_size");
    }

    if (load_stats(&after_alloc) != 0) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after local allocator plugin allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, 8192)) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("dlopen refresh did not hook plugin-local malloc");
    }
    if (getenv("MAI_PATH_STATS") &&
        after_alloc.allocator_frida_calls <= before.allocator_frida_calls) {
        plugin_free(ptr);
        dlclose(handle);
        return fail("plugin-local allocator fallback did not use Frida path");
    }

    plugin_free(ptr);
    if (load_stats(&after_free) != 0) {
        dlclose(handle);
        return fail("mai_get_stats failed after local allocator plugin free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        !stats_show_managed_free(&before, &after_alloc, &after_free, 8192)) {
        dlclose(handle);
        return fail("dlopen refresh did not hook plugin-local free");
    }

    dlclose(handle);
    return 0;
}

static int mode_dlopen_exclusions(void) {
    const char* plugin_path = getenv("MAI_TEST_EXCLUSION_PLUGIN");
    if (!plugin_path || plugin_path[0] == '\0') {
        return fail("MAI_TEST_EXCLUSION_PLUGIN is not set");
    }

    reclaim_all_fn reclaim_all = (reclaim_all_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_all");
    if (!reclaim_all) {
        return fail("mai_reclaim_all is unavailable");
    }

    void* handle = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return fail("dlopen exclusion plugin failed");
    }

    plugin_register_fn cuda_register = NULL;
    plugin_unregister_fn cuda_unregister = NULL;
    plugin_alloc_out_fn cuda_alloc = NULL;
    plugin_free_status_fn cuda_free = NULL;
    plugin_alloc_out_fn cuda_managed_alloc = NULL;
    plugin_free_status_fn cuda_managed_free = NULL;
    plugin_register_fn hip_register = NULL;
    plugin_unregister_fn hip_unregister = NULL;
    plugin_alloc_out_fn hip_alloc = NULL;
    plugin_free_status_fn hip_free = NULL;
    plugin_alloc_out_fn hip_managed_alloc = NULL;
    plugin_free_status_fn hip_managed_free = NULL;
    plugin_rdma_register_fn rdma_register = NULL;
    plugin_rdma_register_fn rdma_register_iova = NULL;
    plugin_rdma_reregister_fn rdma_reregister = NULL;
    plugin_free_status_fn rdma_deregister = NULL;
    plugin_rdma_register_fn rdma_cm_msgs = NULL;
    plugin_rdma_register_fn rdma_cm_read = NULL;
    plugin_rdma_register_fn rdma_cm_write = NULL;
    plugin_free_status_fn rdma_cm_deregister = NULL;
    plugin_alloc_out_fn mpi_alloc = NULL;
    plugin_free_status_fn mpi_free = NULL;

    *(void**)(&cuda_register) = dlsym(handle, "mai_exclusion_plugin_cuda_register");
    *(void**)(&cuda_unregister) = dlsym(handle, "mai_exclusion_plugin_cuda_unregister");
    *(void**)(&cuda_alloc) = dlsym(handle, "mai_exclusion_plugin_cuda_alloc");
    *(void**)(&cuda_free) = dlsym(handle, "mai_exclusion_plugin_cuda_free");
    *(void**)(&cuda_managed_alloc) =
        dlsym(handle, "mai_exclusion_plugin_cuda_managed_alloc");
    *(void**)(&cuda_managed_free) =
        dlsym(handle, "mai_exclusion_plugin_cuda_managed_free");
    *(void**)(&hip_register) = dlsym(handle, "mai_exclusion_plugin_hip_register");
    *(void**)(&hip_unregister) = dlsym(handle, "mai_exclusion_plugin_hip_unregister");
    *(void**)(&hip_alloc) = dlsym(handle, "mai_exclusion_plugin_hip_alloc");
    *(void**)(&hip_free) = dlsym(handle, "mai_exclusion_plugin_hip_free");
    *(void**)(&hip_managed_alloc) =
        dlsym(handle, "mai_exclusion_plugin_hip_managed_alloc");
    *(void**)(&hip_managed_free) =
        dlsym(handle, "mai_exclusion_plugin_hip_managed_free");
    *(void**)(&rdma_register) = dlsym(handle, "mai_exclusion_plugin_rdma_register");
    *(void**)(&rdma_register_iova) =
        dlsym(handle, "mai_exclusion_plugin_rdma_register_iova");
    *(void**)(&rdma_reregister) =
        dlsym(handle, "mai_exclusion_plugin_rdma_reregister");
    *(void**)(&rdma_deregister) = dlsym(handle, "mai_exclusion_plugin_rdma_deregister");
    *(void**)(&rdma_cm_msgs) = dlsym(handle, "mai_exclusion_plugin_rdma_cm_msgs");
    *(void**)(&rdma_cm_read) = dlsym(handle, "mai_exclusion_plugin_rdma_cm_read");
    *(void**)(&rdma_cm_write) = dlsym(handle, "mai_exclusion_plugin_rdma_cm_write");
    *(void**)(&rdma_cm_deregister) =
        dlsym(handle, "mai_exclusion_plugin_rdma_cm_deregister");
    *(void**)(&mpi_alloc) = dlsym(handle, "mai_exclusion_plugin_mpi_alloc");
    *(void**)(&mpi_free) = dlsym(handle, "mai_exclusion_plugin_mpi_free");
    if (!cuda_register || !cuda_unregister || !cuda_alloc || !cuda_free ||
        !cuda_managed_alloc || !cuda_managed_free ||
        !hip_register || !hip_unregister || !hip_alloc || !hip_free ||
        !hip_managed_alloc || !hip_managed_free ||
        !rdma_register || !rdma_register_iova || !rdma_reregister ||
        !rdma_deregister ||
        !rdma_cm_msgs || !rdma_cm_read || !rdma_cm_write || !rdma_cm_deregister ||
        !mpi_alloc || !mpi_free) {
        dlclose(handle);
        return fail("dlsym exclusion plugin functions failed");
    }

    const size_t size = 8192;
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_cuda_register;
    MaiStats after_cuda_reclaim;
    MaiStats after_cuda_unregister;
    MaiStats after_rdma_register;
    MaiStats after_rdma_reregister;
    MaiStats after_rdma_deregister;
    MaiStats after_cuda_alloc;
    MaiStats after_cuda_free;
    MaiStats after_cuda_managed_alloc;
    MaiStats after_cuda_managed_free;
    MaiStats after_hip_register;
    MaiStats after_hip_unregister;
    MaiStats after_hip_alloc;
    MaiStats after_hip_free;
    MaiStats after_hip_managed_alloc;
    MaiStats after_hip_managed_free;
    MaiStats after_rdma_iova_register;
    MaiStats after_rdma_iova_deregister;
    MaiStats after_rdma_cm_msgs_free;
    MaiStats after_rdma_cm_read_free;
    MaiStats after_rdma_cm_write_free;
    MaiStats after_mpi_alloc;
    MaiStats after_mpi_free;

    if (load_stats(&before) != 0) {
        dlclose(handle);
        return fail("mai_get_stats failed before dlopen exclusion test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        dlclose(handle);
        return fail("dlopen exclusion managed allocation failed");
    }
    memset(ptr, 0x55, size);

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after exclusion allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, size)) {
        free(ptr);
        dlclose(handle);
        return fail("exclusion test allocation was not MAI-managed");
    }

    if (cuda_register(ptr, size) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaHostRegister failed");
    }
    if (load_stats(&after_cuda_register) != 0) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA register");
    }
    if (!stats_show_exclusion(&after_alloc, &after_cuda_register, size)) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("dlopen CUDA register did not mark exclusion");
    }

    if (reclaim_all() != 0) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("reclaim failed after CUDA register exclusion");
    }
    if (load_stats(&after_cuda_reclaim) != 0) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA excluded reclaim");
    }
    if (after_cuda_reclaim.reclaimed_bytes != after_cuda_register.reclaimed_bytes ||
        after_cuda_reclaim.reclaim_skipped_excluded <=
            after_cuda_register.reclaim_skipped_excluded) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("reclaim did not skip CUDA-registered managed range");
    }

    if (cuda_unregister(ptr) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaHostUnregister failed");
    }
    if (load_stats(&after_cuda_unregister) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA unregister");
    }
    if (after_cuda_unregister.exclusion_release_events <=
            after_cuda_register.exclusion_release_events ||
        after_cuda_unregister.excluded_ranges >= after_cuda_register.excluded_ranges) {
        free(ptr);
        dlclose(handle);
        return fail("CUDA unregister did not release exclusion");
    }

    void* mr = NULL;
    if (rdma_register(ptr, size, &mr) != 0 || !mr) {
        free(ptr);
        dlclose(handle);
        return fail("plugin ibv_reg_mr failed");
    }
    if (load_stats(&after_rdma_register) != 0) {
        rdma_deregister(mr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after RDMA register");
    }
    if (!stats_show_exclusion(&after_cuda_unregister, &after_rdma_register, size)) {
        rdma_deregister(mr);
        free(ptr);
        dlclose(handle);
        return fail("dlopen RDMA register did not mark exclusion");
    }
    if (rdma_reregister(mr, ptr, size / 2) != 0) {
        rdma_deregister(mr);
        free(ptr);
        dlclose(handle);
        return fail("plugin ibv_rereg_mr failed");
    }
    if (load_stats(&after_rdma_reregister) != 0) {
        rdma_deregister(mr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after RDMA reregister");
    }
    if (after_rdma_reregister.exclusion_events <= after_rdma_register.exclusion_events ||
        after_rdma_reregister.exclusion_release_events <=
            after_rdma_register.exclusion_release_events ||
        after_rdma_reregister.excluded_bytes >= after_rdma_register.excluded_bytes) {
        rdma_deregister(mr);
        free(ptr);
        dlclose(handle);
        return fail("RDMA reregister did not replace exclusion range");
    }
    if (rdma_deregister(mr) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin ibv_dereg_mr failed");
    }
    if (load_stats(&after_rdma_deregister) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after RDMA deregister");
    }
    if (after_rdma_deregister.exclusion_release_events <=
            after_rdma_register.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("RDMA deregister did not release exclusion");
    }

    void* pinned = NULL;
    if (cuda_alloc(size, &pinned) != 0 || !pinned) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaHostAlloc failed");
    }
    if (load_stats(&after_cuda_alloc) != 0) {
        cuda_free(pinned);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA host alloc");
    }
    if (!stats_show_exclusion(&after_rdma_deregister, &after_cuda_alloc, size) ||
        after_cuda_alloc.managed_allocations != after_rdma_deregister.managed_allocations) {
        cuda_free(pinned);
        free(ptr);
        dlclose(handle);
        return fail("CUDA host allocation was not marked excluded pass-through memory");
    }
    if (cuda_free(pinned) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaFreeHost failed");
    }
    if (load_stats(&after_cuda_free) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA host free");
    }
    if (after_cuda_free.exclusion_release_events <=
            after_cuda_alloc.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("CUDA host free did not release exclusion");
    }

    void* cuda_managed = NULL;
    if (cuda_managed_alloc(size, &cuda_managed) != 0 || !cuda_managed) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaMallocManaged failed");
    }
    if (load_stats(&after_cuda_managed_alloc) != 0) {
        cuda_managed_free(cuda_managed);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA managed alloc");
    }
    if (!stats_show_exclusion(&after_cuda_free, &after_cuda_managed_alloc, size) ||
        after_cuda_managed_alloc.managed_allocations !=
            after_cuda_free.managed_allocations) {
        cuda_managed_free(cuda_managed);
        free(ptr);
        dlclose(handle);
        return fail("CUDA managed allocation was not marked excluded pass-through memory");
    }
    if (cuda_managed_free(cuda_managed) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaFree failed for managed allocation");
    }
    if (load_stats(&after_cuda_managed_free) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after CUDA managed free");
    }
    if (after_cuda_managed_free.exclusion_release_events <=
            after_cuda_managed_alloc.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("CUDA managed free did not release exclusion");
    }

    if (hip_register(ptr, size) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipHostRegister failed");
    }
    if (load_stats(&after_hip_register) != 0) {
        hip_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP register");
    }
    if (!stats_show_exclusion(&after_cuda_managed_free, &after_hip_register, size)) {
        hip_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("dlopen HIP register did not mark exclusion");
    }
    if (hip_unregister(ptr) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipHostUnregister failed");
    }
    if (load_stats(&after_hip_unregister) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP unregister");
    }
    if (after_hip_unregister.exclusion_release_events <=
            after_hip_register.exclusion_release_events ||
        after_hip_unregister.excluded_ranges >= after_hip_register.excluded_ranges) {
        free(ptr);
        dlclose(handle);
        return fail("HIP unregister did not release exclusion");
    }

    void* hip_pinned = NULL;
    if (hip_alloc(size, &hip_pinned) != 0 || !hip_pinned) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipHostMalloc failed");
    }
    if (load_stats(&after_hip_alloc) != 0) {
        hip_free(hip_pinned);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP host alloc");
    }
    if (!stats_show_exclusion(&after_hip_unregister, &after_hip_alloc, size) ||
        after_hip_alloc.managed_allocations != after_hip_unregister.managed_allocations) {
        hip_free(hip_pinned);
        free(ptr);
        dlclose(handle);
        return fail("HIP host allocation was not marked excluded pass-through memory");
    }
    if (hip_free(hip_pinned) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipHostFree failed");
    }
    if (load_stats(&after_hip_free) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP host free");
    }
    if (after_hip_free.exclusion_release_events <=
            after_hip_alloc.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("HIP host free did not release exclusion");
    }

    void* hip_managed = NULL;
    if (hip_managed_alloc(size, &hip_managed) != 0 || !hip_managed) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipMallocManaged failed");
    }
    if (load_stats(&after_hip_managed_alloc) != 0) {
        hip_managed_free(hip_managed);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP managed alloc");
    }
    if (!stats_show_exclusion(&after_hip_free, &after_hip_managed_alloc, size) ||
        after_hip_managed_alloc.managed_allocations !=
            after_hip_free.managed_allocations) {
        hip_managed_free(hip_managed);
        free(ptr);
        dlclose(handle);
        return fail("HIP managed allocation was not marked excluded pass-through memory");
    }
    if (hip_managed_free(hip_managed) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin hipFree failed for managed allocation");
    }
    if (load_stats(&after_hip_managed_free) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after HIP managed free");
    }
    if (after_hip_managed_free.exclusion_release_events <=
            after_hip_managed_alloc.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("HIP managed free did not release exclusion");
    }

    void* mr_iova = NULL;
    if (rdma_register_iova(ptr, size, &mr_iova) != 0 || !mr_iova) {
        free(ptr);
        dlclose(handle);
        return fail("plugin ibv_reg_mr_iova failed");
    }
    if (load_stats(&after_rdma_iova_register) != 0) {
        rdma_deregister(mr_iova);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after RDMA iova register");
    }
    if (!stats_show_exclusion(&after_hip_managed_free, &after_rdma_iova_register,
                              size)) {
        rdma_deregister(mr_iova);
        free(ptr);
        dlclose(handle);
        return fail("dlopen RDMA iova register did not mark exclusion");
    }
    if (rdma_deregister(mr_iova) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin ibv_dereg_mr failed for iova MR");
    }
    if (load_stats(&after_rdma_iova_deregister) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after RDMA iova deregister");
    }
    if (after_rdma_iova_deregister.exclusion_release_events <=
            after_rdma_iova_register.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("RDMA iova deregister did not release exclusion");
    }

    if (run_plugin_rdma_cycle(rdma_cm_msgs, rdma_cm_deregister, ptr, size,
                              &after_rdma_iova_deregister, &after_rdma_cm_msgs_free,
                              "plugin rdma_reg_msgs failed",
                              "mai_get_stats failed after rdma_reg_msgs",
                              "dlopen rdma_reg_msgs did not mark exclusion",
                              "plugin rdma_dereg_mr failed after rdma_reg_msgs",
                              "mai_get_stats failed after rdma_reg_msgs deregister",
                              "rdma_reg_msgs deregister did not release exclusion") != 0) {
        free(ptr);
        dlclose(handle);
        return 1;
    }
    if (run_plugin_rdma_cycle(rdma_cm_read, rdma_cm_deregister, ptr, size,
                              &after_rdma_cm_msgs_free, &after_rdma_cm_read_free,
                              "plugin rdma_reg_read failed",
                              "mai_get_stats failed after rdma_reg_read",
                              "dlopen rdma_reg_read did not mark exclusion",
                              "plugin rdma_dereg_mr failed after rdma_reg_read",
                              "mai_get_stats failed after rdma_reg_read deregister",
                              "rdma_reg_read deregister did not release exclusion") != 0) {
        free(ptr);
        dlclose(handle);
        return 1;
    }
    if (run_plugin_rdma_cycle(rdma_cm_write, rdma_cm_deregister, ptr, size,
                              &after_rdma_cm_read_free, &after_rdma_cm_write_free,
                              "plugin rdma_reg_write failed",
                              "mai_get_stats failed after rdma_reg_write",
                              "dlopen rdma_reg_write did not mark exclusion",
                              "plugin rdma_dereg_mr failed after rdma_reg_write",
                              "mai_get_stats failed after rdma_reg_write deregister",
                              "rdma_reg_write deregister did not release exclusion") != 0) {
        free(ptr);
        dlclose(handle);
        return 1;
    }

    void* mpi_ptr = NULL;
    if (mpi_alloc(size, &mpi_ptr) != 0 || !mpi_ptr) {
        free(ptr);
        dlclose(handle);
        return fail("plugin MPI_Alloc_mem failed");
    }
    if (load_stats(&after_mpi_alloc) != 0) {
        mpi_free(mpi_ptr);
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after MPI alloc");
    }
    if (!stats_show_exclusion(&after_rdma_cm_write_free, &after_mpi_alloc, size) ||
        after_mpi_alloc.managed_allocations !=
            after_rdma_cm_write_free.managed_allocations) {
        mpi_free(mpi_ptr);
        free(ptr);
        dlclose(handle);
        return fail("MPI_Alloc_mem was not marked excluded pass-through memory");
    }
    if (mpi_free(mpi_ptr) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin MPI_Free_mem failed");
    }
    if (load_stats(&after_mpi_free) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("mai_get_stats failed after MPI free");
    }
    if (after_mpi_free.exclusion_release_events <= after_mpi_alloc.exclusion_release_events) {
        free(ptr);
        dlclose(handle);
        return fail("MPI_Free_mem did not release exclusion");
    }

    free(ptr);
    dlclose(handle);
    return 0;
}

static int mode_backing_failure(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before backing failure test");
    }

    errno = 0;
    void* ptr = malloc(8192);
    if (ptr) {
        free(ptr);
        return fail("large allocation unexpectedly fell back after arena creation failure");
    }
    if (errno != ENOMEM) {
        return fail("arena creation failure did not surface as ENOMEM");
    }

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after backing failure test");
    }
    if (after.managed_allocations != before.managed_allocations ||
        after.pass_through_allocations != before.pass_through_allocations) {
        return fail("failed managed allocation changed allocation counters");
    }

    return 0;
}

static int mode_unprivileged(void) {
    if (geteuid() == 0) {
        return 77;
    }

    reclaim_all_fn reclaim_all = (reclaim_all_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_all");
    if (!reclaim_all) {
        return fail("mai_reclaim_all is unavailable");
    }

    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before unprivileged smoke test");
    }

    unsigned char* ptr = malloc(8192);
    if (!ptr) {
        return fail("unprivileged large allocation failed");
    }
    memset(ptr, 0x61, 8192);

    if (reclaim_all() != 0) {
        free(ptr);
        return fail("unprivileged reclaim failed");
    }
    if (ptr[0] != 0x61 || ptr[8191] != 0x61) {
        free(ptr);
        return fail("unprivileged reclaim corrupted allocation contents");
    }

    if (load_stats(&after) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after unprivileged smoke test");
    }
    if (after.managed_allocations <= before.managed_allocations ||
        after.reclaim_calls <= before.reclaim_calls) {
        free(ptr);
        return fail("unprivileged smoke test did not exercise managed allocation and reclaim");
    }

    free(ptr);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        return fail("expected exactly one mode argument");
    }

    if (strcmp(argv[1], "disabled") == 0) return mode_disabled();
    if (strcmp(argv[1], "small") == 0) return mode_small();
    if (strcmp(argv[1], "pass_through_stats_default_off") == 0) {
        return mode_pass_through_stats_default_off();
    }
    if (strcmp(argv[1], "preload_symbols") == 0) return mode_preload_symbols();
    if (strcmp(argv[1], "missing_safety_symbols") == 0) {
        return mode_missing_safety_symbols();
    }
    if (strcmp(argv[1], "preload_path_stats") == 0) return mode_preload_path_stats();
    if (strcmp(argv[1], "frida_hook_mode") == 0) return mode_frida_hook_mode();
    if (strcmp(argv[1], "large") == 0) return mode_large();
    if (strcmp(argv[1], "calloc") == 0) return mode_calloc();
    if (strcmp(argv[1], "realloc") == 0) return mode_realloc();
    if (strcmp(argv[1], "alignment") == 0) return mode_alignment();
    if (strcmp(argv[1], "many") == 0) return mode_many();
    if (strcmp(argv[1], "thread") == 0) return mode_thread();
    if (strcmp(argv[1], "thread_small_stats") == 0) return mode_thread_small_stats();
    if (strcmp(argv[1], "reclaim") == 0) return mode_reclaim();
    if (strcmp(argv[1], "mlock_exclusion") == 0) return mode_mlock_exclusion();
    if (strcmp(argv[1], "target_rss") == 0) return mode_target_rss();
    if (strcmp(argv[1], "profile") == 0) return mode_profile();
    if (strcmp(argv[1], "hotness") == 0) return mode_hotness();
    if (strcmp(argv[1], "hotness_live_exit") == 0) return mode_hotness_live_exit();
    if (strcmp(argv[1], "diagnostics") == 0) return mode_diagnostics();
    if (strcmp(argv[1], "dlopen") == 0) return mode_dlopen();
    if (strcmp(argv[1], "dlopen_local_allocator") == 0) return mode_dlopen_local_allocator();
    if (strcmp(argv[1], "dlopen_exclusions") == 0) return mode_dlopen_exclusions();
    if (strcmp(argv[1], "backing_failure") == 0) return mode_backing_failure();
    if (strcmp(argv[1], "unprivileged") == 0) return mode_unprivileged();

    return fail("unknown mode");
}
