#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*get_stats_fn)(MaiStats*);
typedef int (*get_stats_sized_fn)(MaiStats*, size_t);
typedef int (*reclaim_all_fn)(void);
typedef int (*sample_hotness_fn)(void);
typedef int (*hint_range_fn)(void*, size_t, uint32_t, const MaiHintOptions*);
typedef int (*reclaim_range_fn)(void*, size_t);
typedef int (*prefetch_fn)(void*, size_t);
typedef int (*prepare_write_fn)(void*, size_t);
typedef int (*trace_access_fn)(void*, size_t, const MaiAccessTraceOptions*);
typedef int (*get_access_trace_fn)(void*, MaiAccessTraceSnapshot*);
typedef int (*stop_access_trace_fn)(void*);
typedef int (*heartbeat_fn)(const MaiHeartbeatOptions*, MaiHeartbeatSnapshot*);
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
    get_stats_sized_fn get_stats_sized =
        (get_stats_sized_fn)dlsym(RTLD_DEFAULT, "mai_get_stats_sized");
    if (get_stats_sized) {
        return get_stats_sized(stats, sizeof(*stats));
    }
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
           (after->anon_allocations > before->anon_allocations ||
            after->file_allocations > before->file_allocations ||
            after->uffd_pager_allocations > before->uffd_pager_allocations ||
            after->arena_segments > 0);
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
    if (!stats_show_managed_alloc(&before, &after_alloc, 8192)) {
        free(ptr);
        return fail("large allocation was not routed to MAI management");
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
        return fail("large calloc was not routed to MAI management");
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
        return fail("realloc growth was not routed to MAI management");
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

    size_t small_alignment = sizeof(void*);
    void* small_aligned = aligned_alloc(small_alignment, 128);
    if (!small_aligned || !aligned_ptr(small_aligned, small_alignment)) {
        free(small_aligned);
        return fail("below-threshold aligned_alloc did not preserve small-alignment libc behavior");
    }
    free(small_aligned);

    void* small_memalign = memalign(small_alignment, 128);
    if (!small_memalign || !aligned_ptr(small_memalign, small_alignment)) {
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

static int stats_reclaim_unchanged(const MaiStats* before, const MaiStats* after) {
    return after->reclaim_calls == before->reclaim_calls &&
           after->policy_reclaim_calls == before->policy_reclaim_calls &&
           after->memory_cap_reclaim_calls == before->memory_cap_reclaim_calls &&
           after->reclaimed_bytes == before->reclaimed_bytes &&
           after->memory_cap_failures == before->memory_cap_failures;
}

static int mode_sufficient_memory_fast_path(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before sufficient-memory fast path");
    }

    const size_t size = 65536;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("sufficient-memory allocation failed");
    }
    for (size_t i = 0; i < size; i += 4096) {
        ptr[i] = (unsigned char)(i & 0xff);
    }
    for (size_t i = 0; i < size; i += 4096) {
        if (ptr[i] != (unsigned char)(i & 0xff)) {
            free(ptr);
            return fail("sufficient-memory allocation data changed");
        }
    }

    if (load_stats(&after) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after sufficient-memory fast path");
    }
    if (!stats_show_managed_alloc(&before, &after, size)) {
        free(ptr);
        return fail("sufficient-memory fast path did not record managed allocation");
    }
    if (!stats_reclaim_unchanged(&before, &after)) {
        free(ptr);
        return fail("sufficient-memory fast path performed reclaim");
    }
    if (after.anon_allocations <= before.anon_allocations ||
        after.file_allocations != before.file_allocations ||
        after.migrated_to_file_bytes != before.migrated_to_file_bytes ||
        after.promoted_to_anon_bytes != before.promoted_to_anon_bytes) {
        free(ptr);
        return fail("sufficient-memory fast path did not stay anonymous");
    }

    free(ptr);
    return 0;
}

static int mode_predictive_range_api(void) {
    hint_range_fn hint_range = (hint_range_fn)dlsym(RTLD_DEFAULT, "mai_hint_range");
    reclaim_range_fn reclaim_range =
        (reclaim_range_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_range");
    prefetch_fn prefetch = (prefetch_fn)dlsym(RTLD_DEFAULT, "mai_prefetch");
    prepare_write_fn prepare_write =
        (prepare_write_fn)dlsym(RTLD_DEFAULT, "mai_prepare_write");
    if (!hint_range || !reclaim_range || !prefetch || !prepare_write) {
        return fail("predictive range API symbols are unavailable");
    }

    unsigned char unmanaged[256];
    MaiHintOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.hotset_bytes = 4096;
    opts.window_bytes = 8192;

    if (hint_range(unmanaged, sizeof(unmanaged), MAI_HINT_SEQUENTIAL, &opts) != 0 ||
        reclaim_range(unmanaged, sizeof(unmanaged)) != 0 ||
        prefetch(unmanaged, sizeof(unmanaged)) != 0 ||
        prepare_write(unmanaged, sizeof(unmanaged)) != 0) {
        return fail("predictive APIs did not no-op for unmanaged memory");
    }

    errno = 0;
    if (reclaim_range(NULL, 4096) == 0 || errno != EINVAL) {
        return fail("mai_reclaim_range accepted NULL with nonzero length");
    }
    errno = 0;
    if (hint_range(unmanaged, sizeof(unmanaged), 9999, &opts) == 0 || errno != EINVAL) {
        return fail("mai_hint_range accepted an invalid hint kind");
    }
    opts.size = 0;
    errno = 0;
    if (hint_range(unmanaged, sizeof(unmanaged), MAI_HINT_SEQUENTIAL, &opts) == 0 ||
        errno != EINVAL) {
        return fail("mai_hint_range accepted invalid options size");
    }
    opts.size = sizeof(opts);

    MaiStats before;
    MaiStats after;
    const size_t size = 32768;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("predictive range allocation failed");
    }

    for (size_t i = 0; i < size; i++) {
        ptr[i] = (unsigned char)(i & 0xff);
    }
    if (load_stats(&before) != 0) {
        free(ptr);
        return fail("mai_get_stats failed before predictive range test");
    }

    if (hint_range(ptr, 8192, MAI_HINT_SEQUENTIAL, &opts) != 0 ||
        hint_range(ptr, 8192, MAI_HINT_RANDOM_HOTSET, &opts) != 0 ||
        hint_range(ptr, 8192, MAI_HINT_SPARSE, &opts) != 0) {
        free(ptr);
        return fail("mai_hint_range rejected a valid managed hint");
    }
    errno = 0;
    if (hint_range(ptr + size - 1024, 4096, MAI_HINT_SEQUENTIAL, &opts) == 0 ||
        errno != EINVAL) {
        free(ptr);
        return fail("mai_hint_range accepted a partial managed overlap");
    }

    if (reclaim_range(ptr + 4096, 8192) != 0) {
        free(ptr);
        return fail("mai_reclaim_range failed on a valid managed range");
    }
    MaiStats after_reclaim;
    if (load_stats(&after_reclaim) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after range reclaim");
    }
    if (after_reclaim.migrated_to_file_bytes <= before.migrated_to_file_bytes) {
        free(ptr);
        return fail("range reclaim did not migrate anonymous bytes to storage");
    }

    if (prefetch(ptr + 4096, 8192) != 0) {
        free(ptr);
        return fail("mai_prefetch failed on a valid managed range");
    }

    for (size_t i = 0; i < size; i++) {
        if (ptr[i] != (unsigned char)(i & 0xff)) {
            free(ptr);
            return fail("data changed after range reclaim/prefetch");
        }
    }

    if (load_stats(&after) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after predictive range test");
    }
    if (after.reclaim_calls <= before.reclaim_calls ||
        after.reclaimed_bytes <= before.reclaimed_bytes) {
        free(ptr);
        return fail("range reclaim did not update reclaim stats");
    }
    if (after.promoted_to_anon_bytes <= after_reclaim.promoted_to_anon_bytes) {
        free(ptr);
        return fail("range prefetch did not promote storage-backed bytes");
    }

    MaiStats before_prepare;
    if (load_stats(&before_prepare) != 0) {
        free(ptr);
        return fail("mai_get_stats failed before prepare-write test");
    }
    if (reclaim_range(ptr + 16384, 8192) != 0 ||
        prepare_write(ptr + 16384, 8192) != 0) {
        free(ptr);
        return fail("mai_prepare_write failed on a valid managed range");
    }
    memset(ptr + 16384, 0x5a, 8192);
    for (size_t i = 16384; i < 16384 + 8192; i++) {
        if (ptr[i] != 0x5a) {
            free(ptr);
            return fail("prepared write range did not accept overwrite");
        }
    }
    MaiStats after_prepare;
    if (load_stats(&after_prepare) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after prepare-write test");
    }
    if (after_prepare.promoted_to_anon_bytes <= before_prepare.promoted_to_anon_bytes) {
        free(ptr);
        return fail("mai_prepare_write did not promote storage-backed bytes");
    }

    free(ptr);
    return 0;
}

static int mode_access_trace(void) {
    trace_access_fn trace_access =
        (trace_access_fn)dlsym(RTLD_DEFAULT, "mai_trace_access");
    get_access_trace_fn get_trace =
        (get_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_get_access_trace");
    stop_access_trace_fn stop_trace =
        (stop_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_stop_access_trace");
    if (!trace_access || !get_trace || !stop_trace) {
        return fail("access trace symbols are unavailable");
    }

    MaiAccessTraceOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.max_pages = 4;

    errno = 0;
    if (trace_access(NULL, 4096, &opts) == 0 || errno != EINVAL) {
        return fail("mai_trace_access accepted NULL with nonzero length");
    }
    opts.size = 0;
    errno = 0;
    unsigned char unmanaged[256];
    if (trace_access(unmanaged, sizeof(unmanaged), &opts) == 0 || errno != EINVAL) {
        return fail("mai_trace_access accepted invalid options size");
    }
    opts.size = sizeof(opts);
    if (trace_access(unmanaged, sizeof(unmanaged), &opts) != 0) {
        return fail("mai_trace_access did not no-op for unmanaged memory");
    }

    const size_t size = 65536;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("access trace allocation failed");
    }
    memset(ptr, 0x11, size);

    if (trace_access(ptr, size, &opts) != 0) {
        free(ptr);
        return fail("mai_trace_access failed on managed memory");
    }

    MaiAccessTraceSnapshot before_touch;
    if (get_trace(ptr, &before_touch) != 0) {
        free(ptr);
        return fail("mai_get_access_trace failed before touch");
    }
    if (before_touch.armed_pages == 0 ||
        before_touch.armed_pages > opts.max_pages ||
        before_touch.touched_pages != 0) {
        free(ptr);
        return fail("unexpected initial access trace snapshot");
    }

    memset(ptr, 0x5a, size);

    MaiAccessTraceSnapshot after_touch;
    if (get_trace(ptr, &after_touch) != 0) {
        free(ptr);
        return fail("mai_get_access_trace failed after touch");
    }
    if (after_touch.armed_pages != before_touch.armed_pages ||
        after_touch.touched_pages != after_touch.armed_pages ||
        after_touch.touched_bitmap == 0 ||
        after_touch.first_touch_sequence == 0 ||
        after_touch.last_touch_sequence < after_touch.first_touch_sequence) {
        free(ptr);
        return fail("access trace did not record sampled first touches");
    }

    if (stop_trace(ptr) != 0) {
        free(ptr);
        return fail("mai_stop_access_trace failed");
    }
    memset(ptr, 0xa5, size);
    for (size_t i = 0; i < size; i += 4096) {
        if (ptr[i] != 0xa5) {
            free(ptr);
            return fail("access trace stop did not restore access");
        }
    }

    free(ptr);
    return 0;
}

static int mode_adaptive_heartbeat(void) {
    heartbeat_fn heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    if (!heartbeat) {
        return fail("mai_heartbeat symbol is unavailable");
    }

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = 4;
    opts.chunk_bytes = 16384;

    MaiHeartbeatSnapshot snapshot;
    errno = 0;
    MaiHeartbeatOptions invalid = opts;
    invalid.size = 0;
    if (heartbeat(&invalid, &snapshot) == 0 || errno != EINVAL) {
        return fail("mai_heartbeat accepted invalid options size");
    }

    const size_t size = 65536;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("adaptive heartbeat allocation failed");
    }
    memset(ptr, 0x21, size);

    if (heartbeat(&opts, &snapshot) != 0) {
        free(ptr);
        return fail("mai_heartbeat failed to arm initial samples");
    }
    if (snapshot.epoch == 0 ||
        snapshot.observed_allocations == 0 ||
        snapshot.armed_pages == 0 ||
        snapshot.armed_pages > opts.observe_pages ||
        snapshot.touched_pages != 0 ||
        snapshot.busy) {
        free(ptr);
        return fail("unexpected initial heartbeat snapshot");
    }

    for (size_t offset = 0; offset < size; offset += opts.chunk_bytes) {
        ptr[offset] = (unsigned char)(ptr[offset] + 1);
    }

    MaiHeartbeatSnapshot busy_snapshot;
    if (heartbeat(&opts, &busy_snapshot) != 0) {
        free(ptr);
        return fail("mai_heartbeat failed after sampled touches");
    }
    if (!busy_snapshot.busy ||
        busy_snapshot.touched_pages == 0 ||
        busy_snapshot.armed_pages == 0 ||
        busy_snapshot.armed_pages >= snapshot.armed_pages) {
        free(ptr);
        return fail("heartbeat did not adapt to busy access");
    }

    opts.migrate_bytes = 32768;
    for (size_t quiet_epoch = 0; quiet_epoch < 2; quiet_epoch++) {
        MaiHeartbeatSnapshot early_quiet_snapshot;
        if (heartbeat(&opts, &early_quiet_snapshot) != 0) {
            free(ptr);
            return fail("mai_heartbeat failed during early quiet epoch");
        }
        if (early_quiet_snapshot.busy ||
            early_quiet_snapshot.touched_pages != 0 ||
            early_quiet_snapshot.reclaimed_bytes != 0) {
            free(ptr);
            return fail("heartbeat reclaimed before the minimum quiet epochs");
        }
    }

    MaiHeartbeatSnapshot quiet_snapshot;
    if (heartbeat(&opts, &quiet_snapshot) != 0) {
        free(ptr);
        return fail("mai_heartbeat failed during quiet migration");
    }
    if (quiet_snapshot.busy ||
        quiet_snapshot.touched_pages != 0 ||
        quiet_snapshot.reclaimed_bytes == 0 ||
        quiet_snapshot.reclaimed_bytes > opts.migrate_bytes ||
        quiet_snapshot.armed_pages < busy_snapshot.armed_pages) {
        free(ptr);
        return fail("heartbeat did not reclaim and re-arm during quiet epoch");
    }

    for (size_t offset = 0; offset < size; offset += opts.chunk_bytes) {
        if (ptr[offset] != 0x22) {
            free(ptr);
            return fail("heartbeat migration did not preserve data");
        }
    }

    free(ptr);
    return 0;
}

static int mode_heartbeat_busy_no_migration(void) {
    heartbeat_fn heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    if (!heartbeat) {
        return fail("mai_heartbeat symbol is unavailable");
    }

    const size_t size = 65536;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("busy heartbeat allocation failed");
    }
    memset(ptr, 0x31, size);

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = 4;
    opts.chunk_bytes = 16384;
    opts.migrate_bytes = 32768;

    MaiHeartbeatSnapshot snapshot;
    if (heartbeat(&opts, &snapshot) != 0 || snapshot.armed_pages != 4) {
        free(ptr);
        return fail("busy heartbeat failed to arm initial samples");
    }

    for (size_t offset = 0; offset < size; offset += opts.chunk_bytes) {
        ptr[offset] = (unsigned char)(ptr[offset] + 1);
    }

    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        free(ptr);
        return fail("mai_get_stats failed before busy heartbeat tick");
    }

    MaiHeartbeatSnapshot busy_snapshot;
    if (heartbeat(&opts, &busy_snapshot) != 0) {
        free(ptr);
        return fail("busy heartbeat tick failed");
    }

    if (load_stats(&after) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after busy heartbeat tick");
    }
    if (!busy_snapshot.busy ||
        busy_snapshot.touched_pages == 0 ||
        busy_snapshot.reclaimed_bytes != 0 ||
        !stats_reclaim_unchanged(&before, &after)) {
        free(ptr);
        return fail("busy heartbeat reclaimed despite migration budget");
    }

    free(ptr);
    return 0;
}

static int heartbeat_quiet_reclaimed_bytes(heartbeat_fn heartbeat,
                                           size_t chunk_bytes,
                                           size_t* reclaimed_out) {
    const size_t observe_pages = 4;
    const size_t size = 256 * 1024;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return -1;
    }
    memset(ptr, 0x41, size);

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = observe_pages;
    opts.chunk_bytes = chunk_bytes;
    opts.migrate_bytes = size;

    MaiHeartbeatSnapshot arm_snapshot;
    MaiHeartbeatSnapshot first_quiet_snapshot;
    MaiHeartbeatSnapshot second_quiet_snapshot;
    MaiHeartbeatSnapshot reclaim_snapshot;
    int rc = 0;
    if (heartbeat(&opts, &arm_snapshot) != 0 ||
        arm_snapshot.armed_pages != observe_pages ||
        heartbeat(&opts, &first_quiet_snapshot) != 0 ||
        first_quiet_snapshot.busy ||
        first_quiet_snapshot.reclaimed_bytes != 0 ||
        heartbeat(&opts, &second_quiet_snapshot) != 0 ||
        second_quiet_snapshot.busy ||
        second_quiet_snapshot.reclaimed_bytes != 0 ||
        heartbeat(&opts, &reclaim_snapshot) != 0 ||
        reclaim_snapshot.busy ||
        reclaim_snapshot.reclaimed_bytes == 0) {
        rc = -1;
    } else {
        *reclaimed_out = reclaim_snapshot.reclaimed_bytes;
    }

    for (size_t offset = 0; offset < size; offset += chunk_bytes) {
        if (ptr[offset] != 0x41) {
            rc = -1;
            break;
        }
    }

    free(ptr);
    return rc;
}

static int mode_heartbeat_chunk_sensitivity(void) {
    heartbeat_fn heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    if (!heartbeat) {
        return fail("mai_heartbeat symbol is unavailable");
    }

    size_t reclaimed_4k = 0;
    size_t reclaimed_16k = 0;
    size_t reclaimed_64k = 0;
    if (heartbeat_quiet_reclaimed_bytes(heartbeat, 4096, &reclaimed_4k) != 0 ||
        heartbeat_quiet_reclaimed_bytes(heartbeat, 16384, &reclaimed_16k) != 0 ||
        heartbeat_quiet_reclaimed_bytes(heartbeat, 65536, &reclaimed_64k) != 0) {
        return fail("heartbeat chunk sensitivity setup failed");
    }

    if (reclaimed_4k != 4 * 4096 ||
        reclaimed_16k != 4 * 16384 ||
        reclaimed_64k != 4 * 65536 ||
        !(reclaimed_4k < reclaimed_16k && reclaimed_16k < reclaimed_64k)) {
        fprintf(stderr,
                "heartbeat reclaimed bytes did not scale with chunk size: "
                "4K=%zu 16K=%zu 64K=%zu\n",
                reclaimed_4k, reclaimed_16k, reclaimed_64k);
        return 1;
    }

    return 0;
}

typedef struct {
    unsigned char* ptr;
    size_t size;
    atomic_int* stop;
    atomic_size_t touches;
} TraceStressArgs;

static void* trace_stress_worker(void* arg) {
    TraceStressArgs* worker = (TraceStressArgs*)arg;
    size_t pass = 0;

    while (!atomic_load_explicit(worker->stop, memory_order_acquire)) {
        for (size_t offset = 0; offset < worker->size; offset += 4096) {
            worker->ptr[offset] = (unsigned char)((offset + pass) & 0xff);
            atomic_fetch_add_explicit(&worker->touches, 1, memory_order_relaxed);
        }
        pass++;
    }

    return NULL;
}

static int mode_access_trace_concurrent_stress(void) {
    trace_access_fn trace_access =
        (trace_access_fn)dlsym(RTLD_DEFAULT, "mai_trace_access");
    stop_access_trace_fn stop_trace =
        (stop_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_stop_access_trace");
    heartbeat_fn heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    if (!trace_access || !stop_trace || !heartbeat) {
        return fail("trace stress symbols are unavailable");
    }

    const size_t size = 65536;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("trace stress allocation failed");
    }
    memset(ptr, 0, size);

    atomic_int stop;
    atomic_init(&stop, 0);
    TraceStressArgs args = {
        .ptr = ptr,
        .size = size,
        .stop = &stop,
    };
    atomic_init(&args.touches, 0);

    pthread_t thread;
    if (pthread_create(&thread, NULL, trace_stress_worker, &args) != 0) {
        free(ptr);
        return fail("trace stress worker create failed");
    }

    MaiAccessTraceOptions trace_opts;
    memset(&trace_opts, 0, sizeof(trace_opts));
    trace_opts.size = sizeof(trace_opts);
    trace_opts.max_pages = 8;
    trace_opts.chunk_bytes = 8192;

    MaiHeartbeatOptions heartbeat_opts;
    memset(&heartbeat_opts, 0, sizeof(heartbeat_opts));
    heartbeat_opts.size = sizeof(heartbeat_opts);
    heartbeat_opts.observe_pages = 8;
    heartbeat_opts.chunk_bytes = 8192;
    heartbeat_opts.migrate_bytes = 0;

    int rc = 0;
    for (size_t i = 0; i < 64; i++) {
        if (trace_access(ptr, size, &trace_opts) != 0) {
            rc = -1;
            break;
        }
        if (i % 2 == 0) {
            MaiHeartbeatSnapshot snapshot;
            if (heartbeat(&heartbeat_opts, &snapshot) != 0) {
                rc = -1;
                break;
            }
        } else if (stop_trace(ptr) != 0) {
            rc = -1;
            break;
        }
    }

    atomic_store_explicit(&stop, 1, memory_order_release);
    if (pthread_join(thread, NULL) != 0) {
        free(ptr);
        return fail("trace stress worker join failed");
    }

    if (stop_trace(ptr) != 0) {
        rc = -1;
    }
    if (atomic_load_explicit(&args.touches, memory_order_relaxed) == 0) {
        rc = -1;
    }

    for (size_t offset = 0; offset < size; offset += 4096) {
        ptr[offset] = 0xa7;
        if (ptr[offset] != 0xa7) {
            rc = -1;
            break;
        }
    }

    free(ptr);
    return rc == 0 ? 0 : fail("access trace concurrent stress failed");
}

static int mode_heartbeat_round_robin_fairness(void) {
    heartbeat_fn heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    get_access_trace_fn get_trace =
        (get_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_get_access_trace");
    if (!heartbeat || !get_trace) {
        return fail("heartbeat fairness symbols are unavailable");
    }

    enum { allocation_count = 4 };
    const size_t size = 16384;
    unsigned char* ptrs[allocation_count];
    memset(ptrs, 0, sizeof(ptrs));

    for (size_t i = 0; i < allocation_count; i++) {
        ptrs[i] = malloc(size);
        if (!ptrs[i]) {
            for (size_t j = 0; j < i; j++) {
                free(ptrs[j]);
            }
            return fail("heartbeat fairness allocation failed");
        }
        memset(ptrs[i], (int)(0x20 + i), size);
    }

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = 1;
    opts.chunk_bytes = size;

    int observed[allocation_count] = {0};
    for (size_t epoch = 0; epoch < allocation_count; epoch++) {
        MaiHeartbeatSnapshot snapshot;
        if (heartbeat(&opts, &snapshot) != 0 || snapshot.armed_pages != 1) {
            for (size_t i = 0; i < allocation_count; i++) {
                free(ptrs[i]);
            }
            return fail("heartbeat fairness tick failed");
        }

        for (size_t i = 0; i < allocation_count; i++) {
            MaiAccessTraceSnapshot trace_snapshot;
            if (get_trace(ptrs[i], &trace_snapshot) != 0) {
                for (size_t j = 0; j < allocation_count; j++) {
                    free(ptrs[j]);
                }
                return fail("heartbeat fairness trace snapshot failed");
            }
            if (trace_snapshot.armed_pages != 0) {
                observed[i] = 1;
            }
        }
    }

    int all_observed = 1;
    for (size_t i = 0; i < allocation_count; i++) {
        if (!observed[i]) {
            all_observed = 0;
        }
        free(ptrs[i]);
    }

    return all_observed ? 0 :
        fail("heartbeat did not rotate observation across allocations");
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
    if (getenv("MAI_EXPECT_ADAPTIVE_RECLAIM") &&
        (after.hotness_samples <= before.hotness_samples ||
         after.hotness_sampled_pages <= before.hotness_sampled_pages)) {
        return fail("adaptive target RSS reclaim did not sample candidate residency");
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

static int mode_memory_cap_auto(void) {
    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed for memory cap auto test");
    }
    if (stats.max_rss == 0 || stats.current_rss_bytes == 0) {
        return fail("auto memory cap was not detected");
    }
    return 0;
}

static int mode_memory_cap_off(void) {
    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed for memory cap off test");
    }
    if (stats.max_rss != 0) {
        return fail("MAI_MAX_RSS=off did not disable memory cap");
    }
    return 0;
}

static int mode_memory_cap_chunked_calloc(void) {
    MaiStats before;
    MaiStats after;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before memory cap chunked calloc test");
    }

    size_t size = 96 * 1024 * 1024;
    unsigned char* ptr = calloc(1, size);
    if (!ptr) {
        return fail("memory cap chunked calloc failed");
    }
    if (ptr[0] != 0 || ptr[size / 2] != 0 || ptr[size - 1] != 0) {
        free(ptr);
        return fail("memory cap chunked calloc did not return zeroed memory");
    }

    if (load_stats(&after) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after memory cap chunked calloc test");
    }
    if (!stats_show_managed_alloc(&before, &after, size) ||
        after.memory_cap_reclaim_calls <= before.memory_cap_reclaim_calls ||
        after.reclaimed_bytes <= before.reclaimed_bytes ||
        after.memory_cap_failures != before.memory_cap_failures) {
        free(ptr);
        return fail("memory cap chunked calloc was not reclaimed correctly");
    }
    free(ptr);
    return 0;
}

static int mode_backend_auto_pressure_file(void) {
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before auto backend pressure test");
    }

    size_t size = 15 * 1024 * 1024;
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("auto backend pressure allocation failed");
    }
    ptr[0] = 0x5a;
    ptr[size - 1] = 0xa5;

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after auto backend pressure allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, size) ||
        after_alloc.anon_allocations <= before.anon_allocations ||
        after_alloc.migrated_to_file_bytes <= before.migrated_to_file_bytes) {
        free(ptr);
        return fail("auto backend did not migrate pressure allocation to file backing");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after auto backend pressure free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes) {
        return fail("auto backend pressure allocation leaked managed bytes");
    }
    return 0;
}

static int mode_legacy_stats_abi(void) {
    typedef int (*legacy_get_stats_fn)(MaiStats*);
    legacy_get_stats_fn legacy_get_stats =
        (legacy_get_stats_fn)dlsym(RTLD_DEFAULT, "mai_get_stats");
    if (!legacy_get_stats) {
        return fail("legacy mai_get_stats symbol is unavailable");
    }

    size_t legacy_size = offsetof(MaiStats, uffd_pager_available);
    unsigned char buffer[sizeof(MaiStats) + 32];
    memset(buffer, 0, sizeof(buffer));
    memset(buffer + legacy_size, 0xa5, sizeof(buffer) - legacy_size);

    if (legacy_get_stats((MaiStats*)buffer) != 0) {
        return fail("legacy mai_get_stats failed");
    }
    for (size_t i = legacy_size; i < sizeof(buffer); i++) {
        if (buffer[i] != 0xa5) {
            return fail("legacy mai_get_stats wrote past the stable stats prefix");
        }
    }
    return 0;
}

static int mode_uffd_pager_probe(void) {
    MaiStats stats;
    if (load_stats(&stats) != 0) {
        return fail("mai_get_stats failed for UFFD pager probe");
    }

    if (stats.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (stats.config_error != 0) {
        return fail("UFFD pager probe caused a configuration error");
    }
    if (getenv("MAI_UFFD_EXPECT_AVAILABLE") &&
        stats.uffd_pager_available == 0) {
        return fail("UFFD pager was expected but is unavailable");
    }

    return 0;
}

static int mode_uffd_pager_auto_register_fallback(void) {
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    const size_t size = 15 * 1024 * 1024;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD auto fallback test");
    }
    if (before.config_error != 0) {
        return fail("UFFD auto fallback test started with configuration error");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("optional UFFD register failure did not fall back");
    }
    ptr[0] = 0x36;
    ptr[size - 1] = 0x63;
    if (ptr[0] != 0x36 || ptr[size - 1] != 0x63) {
        free(ptr);
        return fail("optional UFFD fallback allocation lost data");
    }

    if (load_stats(&after_alloc) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD auto fallback allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, size) ||
        after_alloc.uffd_fallbacks <= before.uffd_fallbacks ||
        after_alloc.migrated_to_file_bytes <= before.migrated_to_file_bytes) {
        free(ptr);
        return fail("optional UFFD register failure did not use pressure fallback");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD auto fallback free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes) {
        return fail("optional UFFD fallback allocation leaked managed bytes");
    }
    return 0;
}

static int mode_uffd_pager_faults(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 24 * 1024 * 1024;
    const size_t stride = 2 * 1024 * 1024;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD pager fault test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for fault test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD pager pressure allocation failed");
    }

    for (size_t i = 0; i < size; i += stride) {
        ptr[i] = (unsigned char)((i / stride) + 1);
    }
    ptr[size - 1] = 0xa7;

    for (size_t i = 0; i < size; i += stride) {
        unsigned char expected = (unsigned char)((i / stride) + 1);
        if (ptr[i] != expected) {
            free(ptr);
            return fail("UFFD pager lost data after fault resolution");
        }
    }
    if (ptr[size - 1] != 0xa7) {
        free(ptr);
        return fail("UFFD pager lost tail data after fault resolution");
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD pager touches");
    }
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_resident_bytes == 0) {
        free(ptr);
        return fail("UFFD pager did not service the allocation fault path");
    }
    if (getenv("MAI_UFFD_EXPECT_EVICTIONS") &&
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD pager resident limit did not trigger evictions");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD pager free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD pager allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_spatial_prefetch(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 16 * 1024 * 1024;
    const size_t stride = 2 * 1024 * 1024;
    const size_t chunks = size / stride;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD prefetch test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for prefetch test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD pager prefetch allocation failed");
    }

    for (size_t i = 0; i < size; i += stride) {
        ptr[i] = (unsigned char)((i / stride) + 13);
    }
    ptr[size - 1] = 0x5d;

    for (size_t i = 0; i < size; i += stride) {
        unsigned char expected = (unsigned char)((i / stride) + 13);
        if (ptr[i] != expected) {
            free(ptr);
            return fail("UFFD pager prefetch lost chunk data");
        }
    }
    if (ptr[size - 1] != 0x5d) {
        free(ptr);
        return fail("UFFD pager prefetch lost tail data");
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD prefetch touches");
    }
    size_t fault_delta = after_touch.uffd_faults - before.uffd_faults;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations) {
        fprintf(stderr,
                "prefetch stats: managed_allocs before=%zu after=%zu "
                "uffd_allocs before=%zu after=%zu live_before=%zu live_after=%zu\n",
                before.managed_allocations, after_touch.managed_allocations,
                before.uffd_pager_allocations, after_touch.uffd_pager_allocations,
                before.live_managed_bytes, after_touch.live_managed_bytes);
        free(ptr);
        return fail("UFFD spatial prefetch did not use pager allocation");
    }
    if (fault_delta == 0 || fault_delta > (chunks / 2 + 1)) {
        fprintf(stderr, "prefetch stats: chunks=%zu fault_delta=%zu\n",
                chunks, fault_delta);
        free(ptr);
        return fail("UFFD spatial prefetch did not reduce sequential faults");
    }
    if (after_touch.policy_prefetch_requests <= before.policy_prefetch_requests ||
        after_touch.policy_prefetch_completed <= before.policy_prefetch_completed) {
        fprintf(stderr,
                "policy prefetch stats: requests before=%zu after=%zu "
                "completed before=%zu after=%zu\n",
                before.policy_prefetch_requests,
                after_touch.policy_prefetch_requests,
                before.policy_prefetch_completed,
                after_touch.policy_prefetch_completed);
        free(ptr);
        return fail("UFFD spatial prefetch did not update policy counters");
    }
    if (after_touch.uffd_resident_bytes < size) {
        fprintf(stderr, "prefetch stats: resident=%zu size=%zu\n",
                after_touch.uffd_resident_bytes, size);
        free(ptr);
        return fail("UFFD spatial prefetch did not keep prefetched chunks resident");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD prefetch free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD prefetch allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_stride_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t streams = 4;
    const size_t passes = 3;
    const size_t units = size / unit;
    size_t active_streams = streams;
    const char* active_streams_env = getenv("MAI_UFFD_STRIDE_ACTIVE_STREAMS");
    if (active_streams_env && active_streams_env[0] != '\0') {
        char* end = NULL;
        unsigned long long parsed = strtoull(active_streams_env, &end, 10);
        if (end && *end == '\0' && parsed > 0 && parsed <= streams) {
            active_streams = (size_t)parsed;
        }
    }

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD stride policy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for stride policy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD stride policy allocation failed");
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t stream = 0; stream < active_streams; stream++) {
            for (size_t step = 0; step < units; step++) {
                size_t chunk = stream + step * streams;
                if (chunk >= units) {
                    continue;
                }
                ptr[chunk * unit] = (unsigned char)(0x20 + pass + chunk);
            }
        }
        for (size_t stream = 0; stream < active_streams; stream++) {
            for (size_t step = 0; step < units; step++) {
                size_t chunk = stream + step * streams;
                if (chunk >= units) {
                    continue;
                }
                unsigned char expected = (unsigned char)(0x20 + pass + chunk);
                if (ptr[chunk * unit] != expected) {
                    free(ptr);
                    return fail("UFFD stride policy lost chunk data");
                }
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD stride policy touches");
    }
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    size_t prefetch_useful =
        after_touch.policy_prefetch_useful - before.policy_prefetch_useful;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        fprintf(stderr,
                "stride policy stats: managed before=%zu after=%zu "
                "uffd_alloc before=%zu after=%zu faults before=%zu after=%zu "
                "evictions before=%zu after=%zu\n",
                before.managed_allocations, after_touch.managed_allocations,
                before.uffd_pager_allocations, after_touch.uffd_pager_allocations,
                before.uffd_faults, after_touch.uffd_faults,
                before.uffd_evictions, after_touch.uffd_evictions);
        free(ptr);
        return fail("UFFD stride policy did not exercise pager pressure");
    }
    if (getenv("MAI_UFFD_EXPECT_NO_USEFUL_PREFETCH")) {
        if (prefetch_completed == 0 || prefetch_useful != 0) {
            fprintf(stderr,
                    "stride negative-control stats: completed=%zu useful=%zu\n",
                    prefetch_completed, prefetch_useful);
            free(ptr);
            return fail("UFFD forward prefetch was useful in isolated stride test");
        }
    } else if (prefetch_completed == 0 || prefetch_useful == 0) {
        fprintf(stderr,
                "stride policy prefetch stats: completed=%zu useful=%zu\n",
                prefetch_completed, prefetch_useful);
        free(ptr);
        return fail("UFFD stride policy did not produce useful prefetches");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD stride policy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD stride policy allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_lfu_hotset_scan(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t hot_units = 4;
    const size_t hot_rounds = 4;
    const size_t scan_passes = 3;
    unsigned char expected[16] = {0};

    if (units > sizeof(expected)) {
        return fail("LFU hotset test expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD LFU hotset test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for LFU hotset test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD LFU hotset allocation failed");
    }
    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t round = 0; round < hot_rounds; round++) {
            for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
                expected[unit_index]++;
                ptr[unit_index * unit] = expected[unit_index];
                if (ptr[unit_index * unit] != expected[unit_index]) {
                    free(ptr);
                    return fail("UFFD LFU hotset lost hot data");
                }
            }
        }
        for (size_t unit_index = hot_units; unit_index < units; unit_index++) {
            expected[unit_index]++;
            ptr[unit_index * unit] = expected[unit_index];
            if (ptr[unit_index * unit] != expected[unit_index]) {
                free(ptr);
                return fail("UFFD LFU hotset lost scan data");
            }
        }
        for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
            if (ptr[unit_index * unit] != expected[unit_index]) {
                free(ptr);
                return fail("UFFD LFU hotset verification failed");
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD LFU hotset touches");
    }
    size_t admission_requests =
        after_touch.policy_admission_requests - before.policy_admission_requests;
    size_t admission_rejected =
        after_touch.policy_admission_rejected - before.policy_admission_rejected;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        fprintf(stderr,
                "LFU hotset pager stats: managed before=%zu after=%zu "
                "live before=%zu after=%zu uffd_alloc before=%zu after=%zu "
                "faults before=%zu after=%zu evictions before=%zu after=%zu\n",
                before.managed_allocations, after_touch.managed_allocations,
                before.live_managed_bytes, after_touch.live_managed_bytes,
                before.uffd_pager_allocations, after_touch.uffd_pager_allocations,
                before.uffd_faults, after_touch.uffd_faults,
                before.uffd_evictions, after_touch.uffd_evictions);
        free(ptr);
        return fail("UFFD LFU hotset test did not exercise pager pressure");
    }
    if (admission_requests == 0 || admission_rejected == 0) {
        fprintf(stderr,
                "LFU hotset admission stats: requests=%zu rejected=%zu\n",
                admission_requests, admission_rejected);
        free(ptr);
        return fail("UFFD LFU hotset test did not reject speculative admission");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD LFU hotset free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD LFU hotset allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_successor_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t passes = 4;
    const size_t multiplier = 5;
    const size_t addend = 3;
    unsigned char expected[32] = {0};

    if (units > sizeof(expected)) {
        return fail("successor policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD successor policy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for successor policy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD successor policy allocation failed");
    }
    for (size_t pass = 0; pass < passes; pass++) {
        size_t index = 0;
        for (size_t step = 0; step < units; step++) {
            expected[index]++;
            ptr[index * unit] = expected[index];
            if (ptr[index * unit] != expected[index]) {
                free(ptr);
                return fail("UFFD successor policy lost write data");
            }
            index = (multiplier * index + addend) % units;
        }
        index = 0;
        for (size_t step = 0; step < units; step++) {
            if (ptr[index * unit] != expected[index]) {
                free(ptr);
                return fail("UFFD successor policy lost read data");
            }
            index = (multiplier * index + addend) % units;
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD successor policy touches");
    }
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    size_t prefetch_useful =
        after_touch.policy_prefetch_useful - before.policy_prefetch_useful;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD successor policy did not exercise pager pressure");
    }
    if (prefetch_completed == 0 || prefetch_useful == 0) {
        fprintf(stderr,
                "successor policy prefetch stats: completed=%zu useful=%zu\n",
                prefetch_completed, prefetch_useful);
        free(ptr);
        return fail("UFFD successor policy did not produce useful prefetches");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD successor policy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD successor policy allocation leaked managed or resident bytes");
    }
    return 0;
}

typedef struct {
    int id;
    int iterations;
    size_t size;
    int failed;
} UffdStressArgs;

static void* uffd_stress_worker(void* arg) {
    UffdStressArgs* worker = (UffdStressArgs*)arg;
    const size_t page_stride = 4096;

    for (int iter = 0; iter < worker->iterations; iter++) {
        unsigned char value = (unsigned char)(0x30 + worker->id + iter);
        unsigned char* ptr = malloc(worker->size);
        if (!ptr) {
            worker->failed = 1;
            return NULL;
        }
        for (size_t offset = 0; offset < worker->size; offset += page_stride) {
            ptr[offset] = value;
        }
        ptr[worker->size - 1] = (unsigned char)(value ^ 0x5a);
        for (size_t offset = 0; offset < worker->size; offset += page_stride) {
            if (ptr[offset] != value) {
                worker->failed = 1;
                free(ptr);
                return NULL;
            }
        }
        if (ptr[worker->size - 1] != (unsigned char)(value ^ 0x5a)) {
            worker->failed = 1;
            free(ptr);
            return NULL;
        }
        free(ptr);
    }

    return NULL;
}

static int mode_uffd_pager_concurrent_stress(void) {
    enum { thread_count = 4, iterations = 3 };
    pthread_t threads[thread_count];
    UffdStressArgs args[thread_count];
    MaiStats before;
    MaiStats after;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD concurrent stress");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for concurrent stress");
    }

    for (int i = 0; i < thread_count; i++) {
        args[i].id = i;
        args[i].iterations = iterations;
        args[i].size = 12 * 1024 * 1024;
        args[i].failed = 0;
        if (pthread_create(&threads[i], NULL, uffd_stress_worker, &args[i]) != 0) {
            return fail("UFFD concurrent stress thread creation failed");
        }
    }
    for (int i = 0; i < thread_count; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            return fail("UFFD concurrent stress thread join failed");
        }
        if (args[i].failed) {
            return fail("UFFD concurrent stress worker failed");
        }
    }

    if (load_stats(&after) != 0) {
        return fail("mai_get_stats failed after UFFD concurrent stress");
    }
    if (after.uffd_pager_allocations < before.uffd_pager_allocations +
            (size_t)(thread_count * iterations) ||
        after.uffd_faults <= before.uffd_faults ||
        after.live_managed_bytes != before.live_managed_bytes) {
        return fail("UFFD concurrent stress did not exercise or release pager allocations");
    }
    return 0;
}

static int mode_file_dedicated_segments(void) {
    enum { count = 3 };
    const size_t size = 8 * 1024 * 1024;
    unsigned char* ptrs[count];
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;

    memset(ptrs, 0, sizeof(ptrs));
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before file dedicated segment test");
    }

    for (int i = 0; i < count; i++) {
        ptrs[i] = malloc(size);
        if (!ptrs[i]) {
            for (int j = 0; j < i; j++) {
                free(ptrs[j]);
            }
            return fail("file dedicated segment allocation failed");
        }
        ptrs[i][0] = (unsigned char)i;
        ptrs[i][size - 1] = (unsigned char)(0xa0 + i);
    }

    if (load_stats(&after_alloc) != 0) {
        for (int i = 0; i < count; i++) {
            free(ptrs[i]);
        }
        return fail("mai_get_stats failed after file dedicated segment allocation");
    }
    if (!stats_show_managed_alloc(&before, &after_alloc, count * size) ||
        after_alloc.file_allocations < before.file_allocations + count ||
        after_alloc.arena_segments < before.arena_segments + count) {
        for (int i = 0; i < count; i++) {
            free(ptrs[i]);
        }
        return fail("large file-backed allocations were packed into shared arena segments");
    }

    for (int i = 0; i < count; i++) {
        if (ptrs[i][0] != (unsigned char)i ||
            ptrs[i][size - 1] != (unsigned char)(0xa0 + i)) {
            for (int j = 0; j < count; j++) {
                free(ptrs[j]);
            }
            return fail("file dedicated segment allocation contents changed");
        }
        free(ptrs[i]);
    }

    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after file dedicated segment free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes) {
        return fail("file dedicated segment allocation leaked managed bytes");
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
    trace_access_fn trace_access =
        (trace_access_fn)dlsym(RTLD_DEFAULT, "mai_trace_access");
    get_access_trace_fn get_trace =
        (get_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_get_access_trace");
    if (!trace_access || !get_trace) {
        return fail("access trace symbols are unavailable");
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

    MaiAccessTraceOptions trace_opts;
    memset(&trace_opts, 0, sizeof(trace_opts));
    trace_opts.size = sizeof(trace_opts);
    trace_opts.max_pages = 2;
    if (trace_access(ptr, size, &trace_opts) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("exclusion test trace setup failed");
    }
    MaiAccessTraceSnapshot trace_before_exclusion;
    if (get_trace(ptr, &trace_before_exclusion) != 0 ||
        trace_before_exclusion.armed_pages == 0) {
        free(ptr);
        dlclose(handle);
        return fail("exclusion test trace did not arm");
    }

    if (cuda_register(ptr, size) != 0) {
        free(ptr);
        dlclose(handle);
        return fail("plugin cudaHostRegister failed");
    }
    MaiAccessTraceSnapshot trace_after_exclusion;
    if (get_trace(ptr, &trace_after_exclusion) != 0 ||
        trace_after_exclusion.armed_pages != 0 ||
        trace_after_exclusion.touched_pages != 0) {
        cuda_unregister(ptr);
        free(ptr);
        dlclose(handle);
        return fail("CUDA register did not disarm overlapping trace");
    }
    ptr[0] = 0x56;
    ptr[size - 1] = 0x57;
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
    if (strcmp(argv[1], "sufficient_memory_fast_path") == 0) {
        return mode_sufficient_memory_fast_path();
    }
    if (strcmp(argv[1], "predictive_range_api") == 0) {
        return mode_predictive_range_api();
    }
    if (strcmp(argv[1], "access_trace") == 0) return mode_access_trace();
    if (strcmp(argv[1], "adaptive_heartbeat") == 0) {
        return mode_adaptive_heartbeat();
    }
    if (strcmp(argv[1], "heartbeat_busy_no_migration") == 0) {
        return mode_heartbeat_busy_no_migration();
    }
    if (strcmp(argv[1], "heartbeat_chunk_sensitivity") == 0) {
        return mode_heartbeat_chunk_sensitivity();
    }
    if (strcmp(argv[1], "access_trace_concurrent_stress") == 0) {
        return mode_access_trace_concurrent_stress();
    }
    if (strcmp(argv[1], "heartbeat_round_robin_fairness") == 0) {
        return mode_heartbeat_round_robin_fairness();
    }
    if (strcmp(argv[1], "mlock_exclusion") == 0) return mode_mlock_exclusion();
    if (strcmp(argv[1], "target_rss") == 0) return mode_target_rss();
    if (strcmp(argv[1], "memory_cap_auto") == 0) return mode_memory_cap_auto();
    if (strcmp(argv[1], "memory_cap_off") == 0) return mode_memory_cap_off();
    if (strcmp(argv[1], "memory_cap_chunked_calloc") == 0) {
        return mode_memory_cap_chunked_calloc();
    }
    if (strcmp(argv[1], "backend_auto_pressure_file") == 0) {
        return mode_backend_auto_pressure_file();
    }
    if (strcmp(argv[1], "legacy_stats_abi") == 0) {
        return mode_legacy_stats_abi();
    }
    if (strcmp(argv[1], "file_dedicated_segments") == 0) {
        return mode_file_dedicated_segments();
    }
    if (strcmp(argv[1], "uffd_pager_probe") == 0) {
        return mode_uffd_pager_probe();
    }
    if (strcmp(argv[1], "uffd_pager_auto_register_fallback") == 0) {
        return mode_uffd_pager_auto_register_fallback();
    }
    if (strcmp(argv[1], "uffd_pager_faults") == 0) {
        return mode_uffd_pager_faults();
    }
    if (strcmp(argv[1], "uffd_pager_spatial_prefetch") == 0) {
        return mode_uffd_pager_spatial_prefetch();
    }
    if (strcmp(argv[1], "uffd_pager_stride_policy") == 0) {
        return mode_uffd_pager_stride_policy();
    }
    if (strcmp(argv[1], "uffd_pager_lfu_hotset_scan") == 0) {
        return mode_uffd_pager_lfu_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_successor_policy") == 0) {
        return mode_uffd_pager_successor_policy();
    }
    if (strcmp(argv[1], "uffd_pager_concurrent_stress") == 0) {
        return mode_uffd_pager_concurrent_stress();
    }
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
