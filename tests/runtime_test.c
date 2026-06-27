#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
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

static volatile unsigned char runtime_byte_sink;

static __attribute__((noinline)) void runtime_compiler_barrier(void) {
    __asm__ __volatile__("" ::: "memory");
}

static __attribute__((noinline)) unsigned char
runtime_load_byte(volatile unsigned char* ptr, size_t offset) {
    runtime_compiler_barrier();
    unsigned char value = ptr[offset];
    runtime_byte_sink = value;
    runtime_compiler_barrier();
    return value;
}

static __attribute__((noinline)) void
runtime_store_byte(volatile unsigned char* ptr, size_t offset,
                   unsigned char value) {
    runtime_compiler_barrier();
    ptr[offset] = value;
    runtime_byte_sink = value;
    runtime_compiler_barrier();
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

static int wait_for_uffd_evictions(size_t target, MaiStats* out) {
    MaiStats stats;
    for (size_t wait = 0; wait < 200; wait++) {
        if (load_stats(&stats) != 0) {
            return -1;
        }
        if (stats.uffd_evictions >= target) {
            if (out) {
                *out = stats;
            }
            return 0;
        }
        usleep(1000);
    }
    if (out) {
        *out = stats;
    }
    return 1;
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

    long sys_page_size = sysconf(_SC_PAGESIZE);
    if (sys_page_size <= 0) {
        free(ptr);
        return fail("access trace page size unavailable");
    }
    uintptr_t first_page =
        (uintptr_t)ptr & ~((uintptr_t)sys_page_size - (uintptr_t)1);
    pid_t child = fork();
    if (child < 0) {
        free(ptr);
        return fail("access trace post-stop fork failed");
    }
    if (child == 0) {
        if (mprotect((void*)first_page, (size_t)sys_page_size, PROT_NONE) != 0) {
            _exit(2);
        }
        volatile unsigned char value = *(volatile unsigned char*)ptr;
        (void)value;
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        free(ptr);
        return fail("access trace post-stop child wait failed");
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV) {
        free(ptr);
        return fail("access trace consumed an unrelated post-stop protection fault");
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
    size_t page_stride;
    atomic_int* stop;
    atomic_size_t touches;
} TraceStressArgs;

static void* trace_stress_worker(void* arg) {
    TraceStressArgs* worker = (TraceStressArgs*)arg;
    size_t pass = 0;

    while (!atomic_load_explicit(worker->stop, memory_order_acquire)) {
        for (size_t offset = 0; offset < worker->size; offset += worker->page_stride) {
            worker->ptr[offset] = (unsigned char)((offset + pass) & 0xff);
            atomic_fetch_add_explicit(&worker->touches, 1, memory_order_relaxed);
        }
        pass++;
    }

    return NULL;
}

static int wait_trace_touches_above(atomic_size_t* touches, size_t previous) {
    for (size_t spin = 0; spin < 1000; spin++) {
        if (atomic_load_explicit(touches, memory_order_acquire) > previous) {
            return 1;
        }
        usleep(1000);
    }
    return 0;
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

    long sys_page_size = sysconf(_SC_PAGESIZE);
    if (sys_page_size <= 0) {
        return fail("trace stress page size unavailable");
    }
    size_t page_stride = (size_t)sys_page_size;
    const size_t size = 65536;
    unsigned char* ptr = NULL;
    if (posix_memalign((void**)&ptr, page_stride, size) != 0) {
        return fail("trace stress allocation failed");
    }
    memset(ptr, 0, size);

    atomic_int stop;
    atomic_init(&stop, 0);
    TraceStressArgs args = {
        .ptr = ptr,
        .size = size,
        .page_stride = page_stride,
        .stop = &stop,
    };
    atomic_init(&args.touches, 0);

    pthread_t thread;
    if (pthread_create(&thread, NULL, trace_stress_worker, &args) != 0) {
        free(ptr);
        return fail("trace stress worker create failed");
    }
    if (!wait_trace_touches_above(&args.touches, 0)) {
        atomic_store_explicit(&stop, 1, memory_order_release);
        (void)pthread_join(thread, NULL);
        free(ptr);
        return fail("trace stress worker did not start");
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
    const char* reason = NULL;
    for (size_t i = 0; i < 64; i++) {
        size_t before =
            atomic_load_explicit(&args.touches, memory_order_acquire);
        if (trace_access(ptr, size, &trace_opts) != 0) {
            reason = "trace stress trace_access failed";
            rc = -1;
            break;
        }
        if (!wait_trace_touches_above(&args.touches, before)) {
            reason = "trace stress worker stalled during trace";
            rc = -1;
            break;
        }
        if (i % 2 == 0) {
            MaiHeartbeatSnapshot snapshot;
            if (heartbeat(&heartbeat_opts, &snapshot) != 0) {
                reason = "trace stress heartbeat failed";
                rc = -1;
                break;
            }
        } else if (stop_trace(ptr) != 0) {
            reason = "trace stress stop failed";
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
        reason = "trace stress final stop failed";
        rc = -1;
    }
    if (atomic_load_explicit(&args.touches, memory_order_relaxed) == 0) {
        reason = "trace stress worker did not touch memory";
        rc = -1;
    }

    for (size_t offset = 0; offset < size; offset += page_stride) {
        ptr[offset] = 0xa7;
        if (ptr[offset] != 0xa7) {
            reason = "trace stress post-stop write verification failed";
            rc = -1;
            break;
        }
    }

    free(ptr);
    return rc == 0 ? 0 : fail(reason ? reason : "access trace concurrent stress failed");
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

static int mode_uffd_pager_memory_cap_reclaim(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_cap_reclaim;
    MaiStats after_free;
    enum { alloc_count = 64 };
    const size_t alloc_size = 2 * 1024 * 1024;
    unsigned char* ptrs[alloc_count];
    unsigned char* trigger = NULL;
    memset(ptrs, 0, sizeof(ptrs));

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD memory cap reclaim test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for memory cap reclaim test");
    }

    for (size_t i = 0; i < alloc_count; i++) {
        ptrs[i] = malloc(alloc_size);
        if (!ptrs[i]) {
            for (size_t j = 0; j < i; j++) {
                free(ptrs[j]);
            }
            return fail("UFFD memory cap reclaim allocation failed");
        }
        for (size_t offset = 0; offset < alloc_size; offset += 4096) {
            ptrs[i][offset] = (unsigned char)(i + 1);
        }
        ptrs[i][alloc_size - 1] = (unsigned char)(0xa0 + (i & 0x0f));
    }

    if (load_stats(&after_touch) != 0) {
        for (size_t i = 0; i < alloc_count; i++) {
            free(ptrs[i]);
        }
        return fail("mai_get_stats failed after UFFD memory cap reclaim touches");
    }
    trigger = malloc(alloc_size);
    if (!trigger) {
        for (size_t i = 0; i < alloc_count; i++) {
            free(ptrs[i]);
        }
        return fail("UFFD memory cap reclaim trigger allocation failed");
    }
    trigger[0] = 0x6d;

    if (load_stats(&after_cap_reclaim) != 0) {
        free(trigger);
        for (size_t i = 0; i < alloc_count; i++) {
            free(ptrs[i]);
        }
        return fail("mai_get_stats failed after UFFD memory cap reclaim");
    }
    if (!stats_show_managed_alloc(&before, &after_touch,
                                  alloc_count * alloc_size) ||
        after_cap_reclaim.uffd_pager_allocations <
            before.uffd_pager_allocations + alloc_count + 1 ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_cap_reclaim.uffd_evictions <= before.uffd_evictions ||
        after_cap_reclaim.memory_cap_reclaim_calls <=
            before.memory_cap_reclaim_calls ||
        after_cap_reclaim.memory_cap_failures != before.memory_cap_failures) {
        free(trigger);
        for (size_t i = 0; i < alloc_count; i++) {
            free(ptrs[i]);
        }
        return fail("UFFD memory cap reclaim did not evict without cap failure");
    }

    for (size_t i = 0; i < alloc_count; i++) {
        if (ptrs[i][0] != (unsigned char)(i + 1) ||
            ptrs[i][alloc_size - 1] != (unsigned char)(0xa0 + (i & 0x0f))) {
            free(trigger);
            for (size_t j = 0; j < alloc_count; j++) {
                free(ptrs[j]);
            }
            return fail("UFFD memory cap reclaim lost allocation data");
        }
    }
    if (trigger[0] != 0x6d) {
        free(trigger);
        for (size_t i = 0; i < alloc_count; i++) {
            free(ptrs[i]);
        }
        return fail("UFFD memory cap reclaim lost trigger data");
    }

    free(trigger);
    for (size_t i = 0; i < alloc_count; i++) {
        free(ptrs[i]);
    }
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD memory cap reclaim free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD memory cap reclaim leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_fault_headroom(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 8 * 1024 * 1024;
    const size_t resident_limit = 32 * 1024 * 1024;
    const size_t chunks = size / unit;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD fault headroom test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for fault headroom test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD fault headroom allocation failed");
    }

    for (size_t i = 0; i < chunks; i++) {
        ptr[i * unit] = (unsigned char)(0x30 + i);
    }
    ptr[size - 1] = 0xe4;

    for (size_t i = 0; i < chunks; i++) {
        if (ptr[i * unit] != (unsigned char)(0x30 + i)) {
            free(ptr);
            return fail("UFFD fault headroom lost chunk data");
        }
    }
    if (ptr[size - 1] != 0xe4) {
        free(ptr);
        return fail("UFFD fault headroom lost tail data");
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD fault headroom touches");
    }
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults < before.uffd_faults + chunks - 1 ||
        after_touch.uffd_evictions <= before.uffd_evictions ||
        after_touch.uffd_resident_bytes > resident_limit ||
        after_touch.memory_cap_failures != before.memory_cap_failures) {
        fprintf(stderr,
                "fault headroom stats: uffd_alloc before=%zu after=%zu "
                "faults before=%zu after=%zu evictions before=%zu after=%zu "
                "resident=%zu resident_limit=%zu failures before=%zu after=%zu\n",
                before.uffd_pager_allocations,
                after_touch.uffd_pager_allocations,
                before.uffd_faults, after_touch.uffd_faults,
                before.uffd_evictions, after_touch.uffd_evictions,
                after_touch.uffd_resident_bytes, resident_limit,
                before.memory_cap_failures,
                after_touch.memory_cap_failures);
        free(ptr);
        return fail("UFFD fault population did not preserve resident headroom");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD fault headroom free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD fault headroom allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_aligned_required(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t alignment = 2 * 1024 * 1024;
    const size_t pressure_size = 24 * 1024 * 1024;
    const size_t reserve_size = 128 * 1024 * 1024;
    const size_t aligned_size = 2 * 1024 * 1024;
    unsigned char* pressure = NULL;
    unsigned char* plain = NULL;
    unsigned char* zeroed = NULL;
    unsigned char* reserve = NULL;
    unsigned char* aligned = NULL;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD aligned allocation test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for aligned allocation test");
    }

    if (posix_memalign((void**)&pressure, alignment, pressure_size) != 0 ||
        !pressure || !aligned_ptr(pressure, alignment)) {
        free(pressure);
        return fail("UFFD posix_memalign pressure allocation failed");
    }
    for (size_t offset = 0; offset < pressure_size; offset += alignment) {
        pressure[offset] = (unsigned char)((offset / alignment) + 1);
    }
    pressure[pressure_size - 1] = 0x7b;

    aligned = aligned_alloc(alignment, aligned_size);
    if (!aligned || !aligned_ptr(aligned, alignment)) {
        free(aligned);
        free(pressure);
        return fail("UFFD aligned_alloc allocation failed");
    }
    aligned[0] = 0x42;
    aligned[aligned_size - 1] = 0x24;

    plain = malloc(aligned_size);
    if (!plain) {
        free(aligned);
        free(pressure);
        return fail("UFFD malloc allocation failed");
    }
    plain[0] = 0x31;
    plain[aligned_size - 1] = 0x13;

    zeroed = calloc(1, aligned_size);
    if (!zeroed) {
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD calloc allocation failed");
    }
    if (zeroed[0] != 0 || zeroed[aligned_size - 1] != 0) {
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD calloc allocation was not zero-filled");
    }
    zeroed[0] = 0x64;
    zeroed[aligned_size - 1] = 0x46;

    if (posix_memalign((void**)&reserve, alignment, reserve_size) != 0 ||
        !reserve || !aligned_ptr(reserve, alignment)) {
        free(reserve);
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD large no-reserve posix_memalign allocation failed");
    }
    reserve[0] = 0x5c;
    reserve[reserve_size - 1] = 0xc5;

    for (size_t offset = 0; offset < pressure_size; offset += alignment) {
        unsigned char expected = (unsigned char)((offset / alignment) + 1);
        if (pressure[offset] != expected) {
            free(reserve);
            free(zeroed);
            free(plain);
            free(aligned);
            free(pressure);
            return fail("UFFD posix_memalign pressure allocation lost data");
        }
    }
    if (pressure[pressure_size - 1] != 0x7b ||
        aligned[0] != 0x42 || aligned[aligned_size - 1] != 0x24 ||
        plain[0] != 0x31 || plain[aligned_size - 1] != 0x13 ||
        zeroed[0] != 0x64 || zeroed[aligned_size - 1] != 0x46 ||
        reserve[0] != 0x5c || reserve[reserve_size - 1] != 0xc5) {
        free(reserve);
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD aligned or no-reserve allocation lost tail data");
    }

    if (wait_for_uffd_evictions(before.uffd_evictions + 1, &after_touch) != 0) {
        free(reserve);
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD aligned allocation resident limit did not trigger evictions");
    }
    if (!stats_show_managed_alloc(&before, &after_touch,
                                  pressure_size + (3 * aligned_size) +
                                      reserve_size) ||
        after_touch.uffd_pager_allocations < before.uffd_pager_allocations + 5 ||
        after_touch.uffd_faults <= before.uffd_faults) {
        free(reserve);
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD allocation family did not use the pager fault path");
    }
    if (after_touch.uffd_fallbacks != before.uffd_fallbacks) {
        free(reserve);
        free(zeroed);
        free(plain);
        free(aligned);
        free(pressure);
        return fail("UFFD allocation family unexpectedly fell back");
    }

    free(reserve);
    free(zeroed);
    free(plain);
    free(aligned);
    free(pressure);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD aligned allocation free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD aligned allocation leaked managed or resident bytes");
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

static int mode_uffd_pager_async_prefetch(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 16 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t resident_limit = 8 * 1024 * 1024;
    const size_t resident_slack = 4 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected[8] = {0};

    if (chunks > sizeof(expected)) {
        return fail("async prefetch expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD async prefetch test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for async prefetch test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD async prefetch allocation failed");
    }

    for (size_t i = 0; i < chunks; i++) {
        expected[i] = (unsigned char)(0x40 + i);
        ptr[i * unit] = expected[i];
        usleep(1000);
    }
    ptr[size - 1] = 0xc3;
    for (size_t wait = 0; wait < 100; wait++) {
        if (load_stats(&after_touch) != 0) {
            free(ptr);
            return fail("mai_get_stats failed while waiting for UFFD async prefetch");
        }
        if (after_touch.policy_async_prefetch_completed >
            before.policy_async_prefetch_completed) {
            break;
        }
        usleep(1000);
    }

    for (size_t i = 0; i < chunks; i++) {
        if (ptr[i * unit] != expected[i]) {
            free(ptr);
            return fail("UFFD async prefetch lost chunk data");
        }
    }
    if (ptr[size - 1] != 0xc3) {
        free(ptr);
        return fail("UFFD async prefetch lost tail data");
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD async prefetch touches");
    }
    size_t async_enqueued =
        after_touch.policy_async_prefetch_enqueued -
        before.policy_async_prefetch_enqueued;
    size_t async_completed =
        after_touch.policy_async_prefetch_completed -
        before.policy_async_prefetch_completed;
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults) {
        free(ptr);
        return fail("UFFD async prefetch did not exercise pager faults");
    }
    if (async_enqueued == 0 || async_completed == 0) {
        fprintf(stderr,
                "async worker stats: enqueued=%zu completed=%zu dropped=%zu\n",
                async_enqueued, async_completed,
                after_touch.policy_async_prefetch_dropped -
                before.policy_async_prefetch_dropped);
        free(ptr);
        return fail("UFFD async prefetch worker did not run");
    }
    if (prefetch_completed == 0) {
        fprintf(stderr,
                "async prefetch stats: completed before=%zu after=%zu\n",
                before.policy_prefetch_completed,
                after_touch.policy_prefetch_completed);
        free(ptr);
        return fail("UFFD async prefetch worker did not complete prefetches");
    }
    if (after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD async prefetch did not exercise pressure eviction");
    }
    if (after_touch.uffd_resident_bytes > resident_limit + resident_slack) {
        fprintf(stderr,
                "async resident stats: resident=%zu limit=%zu slack=%zu\n",
                after_touch.uffd_resident_bytes, resident_limit, resident_slack);
        free(ptr);
        return fail("UFFD async prefetch exceeded resident slack bound");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD async prefetch free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD async prefetch allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_record_protect_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 16 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected_a[8] = {0};
    unsigned char expected_b[8] = {0};

    if (chunks > sizeof(expected_a) || chunks > sizeof(expected_b)) {
        return fail("record protect expected arrays are too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD record protect test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for record protect test");
    }

    unsigned char* a = malloc(size);
    unsigned char* b = malloc(size);
    if (!a || !b) {
        free(a);
        free(b);
        return fail("UFFD record protect allocations failed");
    }

    for (size_t i = 0; i < 4; i++) {
        expected_a[i] = (unsigned char)(0x70 + i);
        a[i * unit] = expected_a[i];
    }
    for (size_t i = 0; i < chunks; i++) {
        expected_b[i] = (unsigned char)(0x90 + i);
        b[i * unit] = expected_b[i];
    }
    for (size_t i = 0; i < 4; i++) {
        if (a[i * unit] != expected_a[i]) {
            free(a);
            free(b);
            return fail("UFFD record protect lost hot record data");
        }
    }
    for (size_t i = 0; i < chunks; i++) {
        if (b[i * unit] != expected_b[i]) {
            free(a);
            free(b);
            return fail("UFFD record protect lost scan record data");
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed after UFFD record protect touches");
    }
    size_t unused_evictions =
        after_touch.policy_prefetch_unused_evictions -
        before.policy_prefetch_unused_evictions;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.managed_allocations < before.managed_allocations + 2 ||
        after_touch.uffd_pager_allocations < before.uffd_pager_allocations + 2 ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(a);
        free(b);
        return fail("UFFD record protect did not exercise two-record pressure");
    }
    if (unused_evictions == 0) {
        free(a);
        free(b);
        return fail("UFFD record protect did not evict unused prefetches");
    }

    free(a);
    free(b);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD record protect free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD record protect allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_active_record_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t records = 3;
    const size_t record_size = 4 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t resident_limit = 8 * 1024 * 1024;
    const size_t configured_low = 2 * 1024 * 1024;
    unsigned char* ptrs[3] = {0};

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD active record test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for active record test");
    }

    for (size_t r = 0; r < records; r++) {
        ptrs[r] = malloc(record_size);
        if (!ptrs[r]) {
            for (size_t i = 0; i < r; i++) {
                free(ptrs[i]);
            }
            return fail("UFFD active record allocation failed");
        }
    }

    for (size_t r = 0; r < records; r++) {
        ptrs[r][0] = (unsigned char)(0x60 + r);
        ptrs[r][unit] = (unsigned char)(0x70 + r);
    }

    if (load_stats(&after_touch) != 0) {
        for (size_t r = 0; r < records; r++) {
            free(ptrs[r]);
        }
        return fail("mai_get_stats failed after UFFD active record touches");
    }
    if (after_touch.uffd_evictions <= before.uffd_evictions) {
        for (size_t r = 0; r < records; r++) {
            free(ptrs[r]);
        }
        return fail("UFFD active record test did not exercise pressure eviction");
    }
    if (after_touch.uffd_resident_bytes > resident_limit) {
        fprintf(stderr,
                "active record resident above limit: resident=%zu limit=%zu\n",
                after_touch.uffd_resident_bytes, resident_limit);
        for (size_t r = 0; r < records; r++) {
            free(ptrs[r]);
        }
        return fail("UFFD active record controller exceeded resident limit");
    }
    if (after_touch.uffd_resident_bytes <= configured_low + unit) {
        fprintf(stderr,
                "active record resident too low: resident=%zu low=%zu unit=%zu\n",
                after_touch.uffd_resident_bytes, configured_low, unit);
        for (size_t r = 0; r < records; r++) {
            free(ptrs[r]);
        }
        return fail("UFFD active record controller reclaimed to configured low watermark");
    }

    for (size_t r = 0; r < records; r++) {
        if (ptrs[r][0] != (unsigned char)(0x60 + r) ||
            ptrs[r][unit] != (unsigned char)(0x70 + r)) {
            for (size_t i = 0; i < records; i++) {
                free(ptrs[i]);
            }
            return fail("UFFD active record controller lost data");
        }
    }

    for (size_t r = 0; r < records; r++) {
        free(ptrs[r]);
    }
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD active record free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD active record allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_active_record_prefetch_guard(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected[16] = {0};

    if (chunks > sizeof(expected)) {
        return fail("active prefetch guard expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before active prefetch guard test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for active prefetch guard test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("active prefetch guard allocation failed");
    }

    for (size_t i = 0; i < chunks; i++) {
        expected[i] = (unsigned char)(0x80 + i);
        ptr[i * unit] = expected[i];
    }
    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after active prefetch guard touches");
    }

    size_t rejected =
        after_touch.policy_admission_rejected -
        before.policy_admission_rejected;
    size_t requests =
        after_touch.policy_admission_requests -
        before.policy_admission_requests;
    size_t admitted =
        after_touch.policy_prefetch_admitted -
        before.policy_prefetch_admitted;
    size_t completed =
        after_touch.policy_prefetch_completed -
        before.policy_prefetch_completed;
    if (requests == 0) {
        free(ptr);
        return fail("active prefetch guard did not exercise speculative admission");
    }
    if (after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("active prefetch guard did not exercise pressure eviction");
    }
    if (admitted == 0 || completed == 0) {
        fprintf(stderr,
                "active prefetch guard counters: requests=%zu admitted=%zu "
                "completed=%zu rejected=%zu evictions_delta=%zu\n",
                requests,
                admitted,
                completed,
                rejected,
                after_touch.uffd_evictions - before.uffd_evictions);
        free(ptr);
        return fail("active prefetch guard did not admit bounded prefetches");
    }
    if (completed > chunks) {
        fprintf(stderr,
                "active prefetch guard completed too much prefetch: completed=%zu chunks=%zu\n",
                completed, chunks);
        free(ptr);
        return fail("active prefetch guard over-admitted protected prefetches");
    }
    for (size_t i = 0; i < chunks; i++) {
        if (ptr[i * unit] != expected[i]) {
            free(ptr);
            return fail("active prefetch guard lost data");
        }
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after active prefetch guard free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("active prefetch guard allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_adaptive_policy_throttle(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected[16] = {0};

    if (chunks > sizeof(expected)) {
        return fail("adaptive policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before adaptive policy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for adaptive policy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD adaptive policy allocation failed");
    }

    for (size_t pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i + 1 < chunks; i += 2) {
            expected[i]++;
            ptr[i * unit] = expected[i];
            expected[i + 1]++;
            ptr[(i + 1) * unit] = expected[i + 1];
        }
    }

    for (size_t pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < chunks; i += 2) {
            expected[i]++;
            ptr[i * unit] = expected[i];
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after adaptive policy touches");
    }
    size_t throttle_events =
        after_touch.policy_throttle_events - before.policy_throttle_events;
    size_t admission_rejected =
        after_touch.policy_admission_rejected - before.policy_admission_rejected;
    const char* budget_gate_env = getenv("MAI_POLICY_ADAPTIVE_BUDGET_GATE");
    int budget_gate_expected =
        budget_gate_env && strcmp(budget_gate_env, "0") != 0;
    if (budget_gate_expected) {
        if (after_touch.policy_adaptive_budget_gate == 0 ||
            after_touch.policy_adaptive_budget_bytes != unit) {
            fprintf(stderr,
                    "adaptive budget gate stats: gate=%zu budget=%zu "
                    "expected_budget=%zu window_debt=%zu\n",
                    after_touch.policy_adaptive_budget_gate,
                    after_touch.policy_adaptive_budget_bytes, unit,
                    after_touch.policy_adaptive_window_migration_bytes);
            free(ptr);
            return fail("UFFD adaptive budget gate stats were not exposed");
        }
    } else if (after_touch.policy_adaptive_budget_gate != 0) {
        free(ptr);
        return fail("UFFD adaptive budget gate enabled without env opt-in");
    }
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD adaptive policy did not exercise pager pressure");
    }
    if (throttle_events == 0) {
        fprintf(stderr,
                "adaptive policy stats: throttle=%zu rejected=%zu "
                "unused_evictions=%zu hot_evicted=%zu\n",
                throttle_events, admission_rejected,
                after_touch.policy_prefetch_unused_evictions -
                before.policy_prefetch_unused_evictions,
                after_touch.policy_evicted_hot_bytes -
                before.policy_evicted_hot_bytes);
        free(ptr);
        return fail("UFFD adaptive policy did not throttle harmful speculation");
    }
    if (after_touch.policy_adaptive_windows <= before.policy_adaptive_windows ||
        after_touch.policy_adaptive_level_changes <=
            before.policy_adaptive_level_changes ||
        after_touch.policy_adaptive_admission_rejected <=
            before.policy_adaptive_admission_rejected) {
        fprintf(stderr,
                "adaptive policy counters: windows=%zu level=%zu "
                "changes=%zu adaptive_rejects=%zu\n",
                after_touch.policy_adaptive_windows -
                before.policy_adaptive_windows,
                after_touch.policy_adaptive_level,
                after_touch.policy_adaptive_level_changes -
                before.policy_adaptive_level_changes,
                after_touch.policy_adaptive_admission_rejected -
                before.policy_adaptive_admission_rejected);
        free(ptr);
        return fail("UFFD adaptive policy did not report adaptive Markov gating");
    }
    for (size_t i = 0; i < chunks; i += 2) {
        if (ptr[i * unit] != expected[i]) {
            free(ptr);
            return fail("UFFD adaptive policy lost data");
        }
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after adaptive policy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD adaptive policy allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_adaptive_legacy_noop(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected[16] = {0};

    if (chunks > sizeof(expected)) {
        return fail("adaptive legacy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before adaptive legacy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for adaptive legacy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD adaptive legacy allocation failed");
    }

    for (size_t pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < chunks; i += 2) {
            expected[i]++;
            ptr[i * unit] = expected[i];
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after adaptive legacy touches");
    }
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD adaptive legacy did not exercise pager pressure");
    }
    if (after_touch.policy_adaptive_level != 0 ||
        after_touch.policy_adaptive_budget_gate != 0 ||
        after_touch.policy_adaptive_level_changes !=
            before.policy_adaptive_level_changes ||
        after_touch.policy_adaptive_prefetch_capped !=
            before.policy_adaptive_prefetch_capped ||
        after_touch.policy_adaptive_admission_rejected !=
            before.policy_adaptive_admission_rejected) {
        fprintf(stderr,
                "adaptive legacy counters: level=%zu changes=%zu capped=%zu "
                "rejects=%zu\n",
                after_touch.policy_adaptive_level,
                after_touch.policy_adaptive_level_changes -
                before.policy_adaptive_level_changes,
                after_touch.policy_adaptive_prefetch_capped -
                before.policy_adaptive_prefetch_capped,
                after_touch.policy_adaptive_admission_rejected -
                before.policy_adaptive_admission_rejected);
        free(ptr);
        return fail("UFFD adaptive control changed legacy baseline behavior");
    }
    for (size_t i = 0; i < chunks; i += 2) {
        if (ptr[i * unit] != expected[i]) {
            free(ptr);
            return fail("UFFD adaptive legacy lost data");
        }
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after adaptive legacy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD adaptive legacy allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_clean_shadow_skip(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 8 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before clean shadow skip test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for clean shadow skip test");
    }

    volatile unsigned char* ptr = (volatile unsigned char*)malloc(size);
    if (!ptr) {
        return fail("UFFD clean shadow allocation failed");
    }

    size_t base_evictions = before.uffd_evictions;
    runtime_store_byte(ptr, 0, 0x11);
    runtime_store_byte(ptr, unit, 0x22);
    if (wait_for_uffd_evictions(base_evictions + 1, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow skip did not demote initial chunk");
    }
    unsigned char restored = runtime_load_byte(ptr, 0);
    if (wait_for_uffd_evictions(base_evictions + 2, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow skip did not demote post-restore chunk");
    }
    runtime_store_byte(ptr, 2 * unit, 0x33);
    if (wait_for_uffd_evictions(base_evictions + 3, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow skip did not demote restored chunk");
    }
    if (restored != 0x11 || runtime_load_byte(ptr, 0) != 0x11) {
        free((void*)ptr);
        return fail("UFFD clean shadow lost restored data");
    }

    if (load_stats(&after_touch) != 0) {
        free((void*)ptr);
        return fail("mai_get_stats failed after clean shadow skip touches");
    }
    size_t skipped =
        after_touch.policy_clean_shadow_write_skipped_bytes -
        before.policy_clean_shadow_write_skipped_bytes;
    size_t skipped_chunks =
        after_touch.policy_clean_shadow_write_skipped_chunks -
        before.policy_clean_shadow_write_skipped_chunks;
    size_t write_faults =
        after_touch.policy_clean_shadow_write_faults -
        before.policy_clean_shadow_write_faults;
    size_t tracked =
        after_touch.policy_clean_shadow_tracked_chunks -
        before.policy_clean_shadow_tracked_chunks;
    size_t protect_failures =
        after_touch.policy_clean_shadow_protect_failures -
        before.policy_clean_shadow_protect_failures;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free((void*)ptr);
        return fail("UFFD clean shadow skip did not exercise pager pressure");
    }
    if (skipped < unit || skipped_chunks == 0 || tracked == 0 ||
        protect_failures != 0) {
        fprintf(stderr,
                "clean shadow skip stats: skipped=%zu chunks=%zu "
                "write_faults=%zu tracked=%zu protect_failures=%zu "
                "evictions=%zu demand_faults=%zu read_bytes=%zu "
                "write_bytes=%zu useful_prefetch=%zu late_prefetch=%zu\n",
                skipped, skipped_chunks, write_faults, tracked,
                protect_failures,
                after_touch.uffd_evictions - before.uffd_evictions,
                after_touch.policy_demand_faults - before.policy_demand_faults,
                after_touch.policy_migration_read_bytes -
                    before.policy_migration_read_bytes,
                after_touch.policy_migration_write_bytes -
                    before.policy_migration_write_bytes,
                after_touch.policy_prefetch_useful -
                    before.policy_prefetch_useful,
                after_touch.policy_prefetch_late -
                    before.policy_prefetch_late);
        free((void*)ptr);
        return fail("UFFD clean shadow did not skip a clean demotion write");
    }

    free((void*)ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after clean shadow skip free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD clean shadow skip allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_clean_shadow_dirty(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 8 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before clean shadow dirty test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for clean shadow dirty test");
    }

    volatile unsigned char* ptr = (volatile unsigned char*)malloc(size);
    if (!ptr) {
        return fail("UFFD clean shadow dirty allocation failed");
    }

    size_t base_evictions = before.uffd_evictions;
    runtime_store_byte(ptr, 0, 0x41);
    runtime_store_byte(ptr, unit, 0x52);
    if (wait_for_uffd_evictions(base_evictions + 1, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty did not demote initial chunk");
    }
    if (runtime_load_byte(ptr, 0) != 0x41) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty failed to restore clean chunk");
    }
    if (wait_for_uffd_evictions(base_evictions + 2, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty did not demote post-restore chunk");
    }
    runtime_store_byte(ptr, 0, 0x63);
    if (runtime_load_byte(ptr, 0) != 0x63) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty lost updated resident data");
    }
    runtime_store_byte(ptr, 2 * unit, 0x74);
    if (wait_for_uffd_evictions(base_evictions + 3, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty did not demote dirty chunk");
    }
    if (runtime_load_byte(ptr, 0) != 0x63) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty lost updated data");
    }

    if (load_stats(&after_touch) != 0) {
        free((void*)ptr);
        return fail("mai_get_stats failed after clean shadow dirty touches");
    }
    size_t skipped =
        after_touch.policy_clean_shadow_write_skipped_bytes -
        before.policy_clean_shadow_write_skipped_bytes;
    size_t write_faults =
        after_touch.policy_clean_shadow_write_faults -
        before.policy_clean_shadow_write_faults;
    size_t write_bytes =
        after_touch.policy_migration_write_bytes -
        before.policy_migration_write_bytes;
    size_t tracked =
        after_touch.policy_clean_shadow_tracked_chunks -
        before.policy_clean_shadow_tracked_chunks;
    size_t protect_failures =
        after_touch.policy_clean_shadow_protect_failures -
        before.policy_clean_shadow_protect_failures;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free((void*)ptr);
        return fail("UFFD clean shadow dirty did not exercise pager pressure");
    }
    if (skipped == 0 || write_faults == 0 || write_bytes >= 3 * unit) {
        fprintf(stderr,
                "clean shadow dirty stats: skipped=%zu write_faults=%zu "
                "dirty_write_bytes=%zu tracked=%zu protect_failures=%zu evictions=%zu "
                "demand_faults=%zu read_bytes=%zu write_bytes=%zu "
                "useful_prefetch=%zu late_prefetch=%zu\n",
                skipped, write_faults, write_bytes, tracked, protect_failures,
                after_touch.uffd_evictions - before.uffd_evictions,
                after_touch.policy_demand_faults - before.policy_demand_faults,
                after_touch.policy_migration_read_bytes -
                    before.policy_migration_read_bytes,
                after_touch.policy_migration_write_bytes -
                    before.policy_migration_write_bytes,
                after_touch.policy_prefetch_useful -
                    before.policy_prefetch_useful,
                after_touch.policy_prefetch_late -
                    before.policy_prefetch_late);
        free((void*)ptr);
        return fail("UFFD clean shadow did not invalidate on write");
    }

    free((void*)ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after clean shadow dirty free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD clean shadow dirty allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_clean_shadow_fallback(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 8 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before clean shadow fallback test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for clean shadow fallback test");
    }

    volatile unsigned char* ptr = (volatile unsigned char*)malloc(size);
    if (!ptr) {
        return fail("UFFD clean shadow fallback allocation failed");
    }

    size_t base_evictions = before.uffd_evictions;
    runtime_store_byte(ptr, 0, 0x21);
    runtime_store_byte(ptr, unit, 0x32);
    if (wait_for_uffd_evictions(base_evictions + 1, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow fallback did not demote initial chunk");
    }
    if (runtime_load_byte(ptr, 0) != 0x21) {
        free((void*)ptr);
        return fail("UFFD clean shadow fallback failed to restore data");
    }
    if (wait_for_uffd_evictions(base_evictions + 2, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow fallback did not demote after restore");
    }
    runtime_store_byte(ptr, 2 * unit, 0x43);
    if (wait_for_uffd_evictions(base_evictions + 3, NULL) != 0) {
        free((void*)ptr);
        return fail("UFFD clean shadow fallback did not demote restored chunk");
    }
    if (runtime_load_byte(ptr, 0) != 0x21) {
        free((void*)ptr);
        return fail("UFFD clean shadow fallback lost restored data");
    }

    if (load_stats(&after_touch) != 0) {
        free((void*)ptr);
        return fail("mai_get_stats failed after clean shadow fallback touches");
    }
    size_t skipped =
        after_touch.policy_clean_shadow_write_skipped_bytes -
        before.policy_clean_shadow_write_skipped_bytes;
    size_t tracked =
        after_touch.policy_clean_shadow_tracked_chunks -
        before.policy_clean_shadow_tracked_chunks;
    size_t protect_failures =
        after_touch.policy_clean_shadow_protect_failures -
        before.policy_clean_shadow_protect_failures;
    if (skipped != 0 || tracked != 0 || protect_failures == 0) {
        fprintf(stderr,
                "clean shadow fallback stats: skipped=%zu tracked=%zu "
                "protect_failures=%zu\n",
                skipped, tracked, protect_failures);
        free((void*)ptr);
        return fail("UFFD clean shadow fallback tracked an unsafe clean shadow");
    }

    free((void*)ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after clean shadow fallback free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD clean shadow fallback allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_async_queue_saturation_no_sync_prefetch(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 16 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t chunks = size / unit;
    unsigned char expected[8] = {0};

    if (chunks > sizeof(expected)) {
        return fail("async saturation expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD async saturation test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for async saturation test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD async saturation allocation failed");
    }

    for (size_t i = 0; i < chunks; i++) {
        expected[i] = (unsigned char)(0x60 + i);
        ptr[i * unit] = expected[i];
    }
    for (size_t i = 0; i < chunks; i++) {
        if (ptr[i * unit] != expected[i]) {
            free(ptr);
            return fail("UFFD async saturation lost chunk data");
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD async saturation touches");
    }
    size_t async_enqueued =
        after_touch.policy_async_prefetch_enqueued -
        before.policy_async_prefetch_enqueued;
    size_t async_dropped =
        after_touch.policy_async_prefetch_dropped -
        before.policy_async_prefetch_dropped;
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    size_t throttle_events =
        after_touch.policy_throttle_events - before.policy_throttle_events;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults) {
        free(ptr);
        return fail("UFFD async saturation did not exercise pager faults");
    }
    if (async_enqueued != 0 || async_dropped == 0 ||
        prefetch_completed != 0 || throttle_events < async_dropped) {
        fprintf(stderr,
                "async saturation stats: enqueued=%zu dropped=%zu "
                "prefetch_completed=%zu throttle_events=%zu\n",
                async_enqueued, async_dropped, prefetch_completed,
                throttle_events);
        free(ptr);
        return fail("UFFD async saturation fell back to sync prefetch");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD async saturation free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD async saturation allocation leaked managed or resident bytes");
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

static int mode_uffd_pager_hotset_scan_policy(const char* policy_name,
                                              int expect_car_activity,
                                              int expect_tinylfu_activity,
                                              int expect_wtinylfu_activity,
                                              int expect_irr_activity) {
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
        return fail("UFFD hotset test expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hotset test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hotset test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD hotset allocation failed");
    }
    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t round = 0; round < hot_rounds; round++) {
            for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
                expected[unit_index]++;
                ptr[unit_index * unit] = expected[unit_index];
                if (ptr[unit_index * unit] != expected[unit_index]) {
                    free(ptr);
                    return fail("UFFD hotset lost hot data");
                }
            }
        }
        for (size_t unit_index = hot_units; unit_index < units; unit_index++) {
            expected[unit_index]++;
            ptr[unit_index * unit] = expected[unit_index];
            if (ptr[unit_index * unit] != expected[unit_index]) {
                free(ptr);
                return fail("UFFD hotset lost scan data");
            }
        }
        for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
            if (ptr[unit_index * unit] != expected[unit_index]) {
                free(ptr);
                return fail("UFFD hotset verification failed");
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD hotset touches");
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
                "%s hotset pager stats: managed before=%zu after=%zu "
                "live before=%zu after=%zu uffd_alloc before=%zu after=%zu "
                "faults before=%zu after=%zu evictions before=%zu after=%zu\n",
                policy_name,
                before.managed_allocations, after_touch.managed_allocations,
                before.live_managed_bytes, after_touch.live_managed_bytes,
                before.uffd_pager_allocations, after_touch.uffd_pager_allocations,
                before.uffd_faults, after_touch.uffd_faults,
                before.uffd_evictions, after_touch.uffd_evictions);
        free(ptr);
        return fail("UFFD hotset test did not exercise pager pressure");
    }
    if (admission_requests == 0) {
        fprintf(stderr,
                "%s hotset admission stats: requests=%zu rejected=%zu\n",
                policy_name, admission_requests, admission_rejected);
        free(ptr);
        return fail("UFFD hotset test did not exercise speculative admission");
    }
    if (expect_car_activity) {
        size_t car_events =
            (after_touch.policy_car_recent_ghost_hits -
             before.policy_car_recent_ghost_hits) +
            (after_touch.policy_car_frequent_ghost_hits -
             before.policy_car_frequent_ghost_hits) +
            (after_touch.policy_car_target_increases -
             before.policy_car_target_increases) +
            (after_touch.policy_car_target_decreases -
             before.policy_car_target_decreases) +
            (after_touch.policy_car_second_chances -
             before.policy_car_second_chances);
        if (car_events == 0) {
            fprintf(stderr, "CAR hotset stats did not move\n");
            free(ptr);
            return fail("UFFD CAR hotset test did not exercise CAR state");
        }
    }
    if (expect_tinylfu_activity) {
        size_t updates =
            after_touch.policy_tinylfu_sketch_updates -
            before.policy_tinylfu_sketch_updates;
        size_t rejected =
            after_touch.policy_tinylfu_admission_rejected -
            before.policy_tinylfu_admission_rejected;
        if (updates == 0) {
            fprintf(stderr,
                    "TinyLFU hotset stats: updates=%zu rejected=%zu\n",
                    updates, rejected);
            free(ptr);
            return fail("UFFD TinyLFU hotset test did not exercise sketch admission");
        }
    }
    if (expect_wtinylfu_activity) {
        size_t updates =
            after_touch.policy_tinylfu_sketch_updates -
            before.policy_tinylfu_sketch_updates;
        size_t rejected =
            after_touch.policy_wtinylfu_main_admission_rejected -
            before.policy_wtinylfu_main_admission_rejected;
        size_t state_chunks =
            after_touch.policy_wtinylfu_window_chunks +
            after_touch.policy_wtinylfu_probation_chunks +
            after_touch.policy_wtinylfu_protected_chunks;
        size_t prefetch_completed =
            after_touch.policy_prefetch_completed -
            before.policy_prefetch_completed;
        size_t prefetch_useful =
            after_touch.policy_prefetch_useful -
            before.policy_prefetch_useful;
        size_t victim_rejected =
            after_touch.policy_wtinylfu_victim_score_rejected -
            before.policy_wtinylfu_victim_score_rejected;
        if (updates == 0 || prefetch_completed == 0 || prefetch_useful == 0 ||
            (state_chunks == 0 && rejected == 0 && victim_rejected == 0)) {
            fprintf(stderr,
                    "W-TinyLFU hotset stats: updates=%zu rejected=%zu "
                    "victim_rejected=%zu completed=%zu useful=%zu "
                    "window=%zu probation=%zu protected=%zu\n",
                    updates, rejected, victim_rejected,
                    prefetch_completed, prefetch_useful,
                    after_touch.policy_wtinylfu_window_chunks,
                    after_touch.policy_wtinylfu_probation_chunks,
                    after_touch.policy_wtinylfu_protected_chunks);
            free(ptr);
            return fail("UFFD W-TinyLFU hotset test did not exercise states");
        }
    }
    if (expect_irr_activity) {
        size_t ghost_hits =
            after_touch.policy_irr_ghost_hits - before.policy_irr_ghost_hits;
        size_t promotions =
            after_touch.policy_irr_promotions - before.policy_irr_promotions;
        size_t demotions =
            after_touch.policy_irr_demotions - before.policy_irr_demotions;
        size_t pressure_rejected =
            after_touch.policy_irr_pressure_rejected -
            before.policy_irr_pressure_rejected;
        size_t immature_rejected =
            after_touch.policy_irr_immature_rejected -
            before.policy_irr_immature_rejected;
        if (after_touch.policy_irr_resident_chunks == 0 ||
            after_touch.policy_irr_target_protected_chunks == 0 ||
            ghost_hits == 0 || promotions == 0 || demotions == 0 ||
            pressure_rejected == 0 || immature_rejected == 0 ||
            after_touch.policy_irr_max_interval_epochs == 0) {
            fprintf(stderr,
                    "IRR hotset stats: resident=%zu protected=%zu ghost=%zu "
                    "target=%zu ghost_hits=%zu promotions=%zu demotions=%zu "
                    "pressure_rejected=%zu immature_rejected=%zu "
                    "max_interval=%zu\n",
                    after_touch.policy_irr_resident_chunks,
                    after_touch.policy_irr_protected_chunks,
                    after_touch.policy_irr_ghost_chunks,
                    after_touch.policy_irr_target_protected_chunks,
                    ghost_hits, promotions, demotions, pressure_rejected,
                    immature_rejected,
                    after_touch.policy_irr_max_interval_epochs);
            free(ptr);
            return fail("UFFD IRR hotset test did not exercise IRR state");
        }
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hotset free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hotset allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_lfu_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("LFU", 0, 0, 0, 0);
}

static int mode_uffd_pager_lruk_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("LRU-K", 0, 0, 0, 0);
}

static int mode_uffd_pager_car_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("CAR", 1, 0, 0, 0);
}

static int mode_uffd_pager_irr_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("IRR", 0, 0, 0, 1);
}

static int mode_uffd_pager_arc_pivot_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t hot_units = 2;
    const size_t warm_rounds = 8;
    const size_t burst_groups = 3;
    const size_t burst_rounds = 3;
    const size_t scan_passes = 2;
    const size_t return_rounds = 6;
    const size_t scan_start = (burst_groups + 1) * hot_units;
    unsigned char expected[16] = {0};

    if (units > sizeof(expected) || units <= scan_start) {
        return fail("UFFD ARC pivot expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD ARC pivot test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for ARC pivot test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD ARC pivot allocation failed");
    }

    for (size_t round = 0; round < warm_rounds; round++) {
        for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
            expected[unit_index]++;
            ptr[unit_index * unit] = expected[unit_index];
            if (ptr[unit_index * unit] != expected[unit_index]) {
                free(ptr);
                return fail("UFFD ARC pivot lost warm hot data");
            }
        }
    }

    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t group = 0; group < burst_groups; group++) {
            size_t base = (group + 1) * hot_units;
            for (size_t round = 0; round < burst_rounds; round++) {
                for (size_t unit_index = 0; unit_index < hot_units;
                     unit_index++) {
                    size_t index = base + unit_index;
                    expected[index]++;
                    ptr[index * unit] = expected[index];
                    if (ptr[index * unit] != expected[index]) {
                        free(ptr);
                        return fail("UFFD ARC pivot lost burst data");
                    }
                }
            }
            for (size_t index = scan_start; index < units; index++) {
                expected[index]++;
                ptr[index * unit] = expected[index];
                if (ptr[index * unit] != expected[index]) {
                    free(ptr);
                    return fail("UFFD ARC pivot lost scan data");
                }
            }
            for (size_t unit_index = 0; unit_index < hot_units;
                 unit_index++) {
                size_t index = base + unit_index;
                if (ptr[index * unit] != expected[index]) {
                    free(ptr);
                    return fail("UFFD ARC pivot burst verification failed");
                }
            }
        }
        for (size_t round = 0; round < return_rounds; round++) {
            for (size_t unit_index = 0; unit_index < hot_units; unit_index++) {
                expected[unit_index]++;
                ptr[unit_index * unit] = expected[unit_index];
                if (ptr[unit_index * unit] != expected[unit_index]) {
                    free(ptr);
                    return fail("UFFD ARC pivot lost return hot data");
                }
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD ARC pivot touches");
    }

    size_t recent_ghost_hits =
        after_touch.policy_arc_b1_hits - before.policy_arc_b1_hits;
    size_t frequent_ghost_hits =
        after_touch.policy_arc_b2_hits - before.policy_arc_b2_hits;
    size_t target_increases =
        after_touch.policy_arc_target_increases -
        before.policy_arc_target_increases;
    size_t target_decreases =
        after_touch.policy_arc_target_decreases -
        before.policy_arc_target_decreases;
    size_t prefetch_admitted_t1 =
        after_touch.policy_arc_prefetch_admitted_t1 -
        before.policy_arc_prefetch_admitted_t1;
    size_t prefetch_rejected_pressure =
        after_touch.policy_arc_prefetch_rejected_pressure -
        before.policy_arc_prefetch_rejected_pressure;
    size_t prefetch_promoted_to_t2 =
        after_touch.policy_arc_prefetch_promoted_to_t2 -
        before.policy_arc_prefetch_promoted_to_t2;
    size_t unused_prefetch_evictions =
        after_touch.policy_prefetch_unused_evictions -
        before.policy_prefetch_unused_evictions;
    size_t second_chances =
        after_touch.policy_car_second_chances -
        before.policy_car_second_chances;

    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions ||
        after_touch.policy_demand_faults <= before.policy_demand_faults) {
        free(ptr);
        return fail("UFFD ARC pivot did not exercise pager pressure");
    }
    if (after_touch.uffd_resident_bytes > 12 * 1024 * 1024) {
        fprintf(stderr, "ARC resident bytes=%zu\n",
                after_touch.uffd_resident_bytes);
        free(ptr);
        return fail("UFFD ARC pivot exceeded resident cap");
    }
    if (after_touch.policy_arc_t1_chunks + after_touch.policy_arc_t2_chunks >
            6 ||
        after_touch.policy_arc_b1_chunks + after_touch.policy_arc_b2_chunks >
            6) {
        fprintf(stderr,
                "ARC bounded counts: t1=%zu t2=%zu b1=%zu b2=%zu\n",
                after_touch.policy_arc_t1_chunks,
                after_touch.policy_arc_t2_chunks,
                after_touch.policy_arc_b1_chunks,
                after_touch.policy_arc_b2_chunks);
        free(ptr);
        return fail("UFFD ARC pivot exceeded bounded list sizes");
    }
    /*
     * Frequent ghost hits can arrive while ARC p is already zero on the CI
     * host. Keep target_decreases in the diagnostics, but rely on the bounded
     * list/replacement checks below for the frequent-side pivot proof.
     */
    if (recent_ghost_hits == 0 || frequent_ghost_hits == 0 ||
        target_increases == 0 ||
        prefetch_admitted_t1 == 0 ||
        prefetch_promoted_to_t2 == 0 ||
        unused_prefetch_evictions > prefetch_promoted_to_t2 ||
        after_touch.policy_arc_t1_to_t2_promotions <=
            before.policy_arc_t1_to_t2_promotions ||
        after_touch.policy_arc_replace_t1 <= before.policy_arc_replace_t1 ||
        after_touch.policy_arc_replace_t2 <= before.policy_arc_replace_t2) {
        fprintf(stderr,
                "ARC pivot stats: recent_ghost=%zu frequent_ghost=%zu "
                "target_inc=%zu target_dec=%zu t1=%zu t2=%zu b1=%zu b2=%zu "
                "target=%zu promotions=%zu replace_t1=%zu replace_t2=%zu "
                "prefetch_admit=%zu prefetch_reject_pressure=%zu "
                "prefetch_promote=%zu unused_prefetch=%zu\n",
                recent_ghost_hits, frequent_ghost_hits, target_increases,
                target_decreases, after_touch.policy_arc_t1_chunks,
                after_touch.policy_arc_t2_chunks,
                after_touch.policy_arc_b1_chunks,
                after_touch.policy_arc_b2_chunks,
                after_touch.policy_arc_p_chunks,
                after_touch.policy_arc_t1_to_t2_promotions -
                    before.policy_arc_t1_to_t2_promotions,
                after_touch.policy_arc_replace_t1 -
                    before.policy_arc_replace_t1,
                after_touch.policy_arc_replace_t2 -
                    before.policy_arc_replace_t2,
                prefetch_admitted_t1, prefetch_rejected_pressure,
                prefetch_promoted_to_t2, unused_prefetch_evictions);
        free(ptr);
        return fail("UFFD ARC pivot did not exercise bounded ARC admission");
    }
    if (second_chances != 0) {
        fprintf(stderr, "ARC second-chance count=%zu\n", second_chances);
        free(ptr);
        return fail("UFFD ARC pivot unexpectedly used CAR second chances");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD ARC pivot free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD ARC pivot allocation leaked managed or resident bytes");
    }
    if (after_free.policy_arc_t1_chunks != before.policy_arc_t1_chunks ||
        after_free.policy_arc_t2_chunks != before.policy_arc_t2_chunks ||
        after_free.policy_arc_b1_chunks != before.policy_arc_b1_chunks ||
        after_free.policy_arc_b2_chunks != before.policy_arc_b2_chunks) {
        fprintf(stderr,
                "ARC counts after free: before t1=%zu t2=%zu b1=%zu b2=%zu "
                "after t1=%zu t2=%zu b1=%zu b2=%zu\n",
                before.policy_arc_t1_chunks, before.policy_arc_t2_chunks,
                before.policy_arc_b1_chunks, before.policy_arc_b2_chunks,
                after_free.policy_arc_t1_chunks,
                after_free.policy_arc_t2_chunks,
                after_free.policy_arc_b1_chunks,
                after_free.policy_arc_b2_chunks);
        return fail("UFFD ARC pivot leaked ARC list membership");
    }
    return 0;
}

static int mode_uffd_pager_tinylfu_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("TinyLFU", 0, 1, 0, 0);
}

static int mode_uffd_pager_wtinylfu_hotset_scan(void) {
    return mode_uffd_pager_hotset_scan_policy("W-TinyLFU", 0, 1, 1, 0);
}

static int mode_uffd_pager_bestoffset_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t offset_chunks = 16;
    const size_t passes = 4;
    const size_t pair_count = offset_chunks;
    const size_t order[16] = {
        5, 0, 11, 2, 14, 7, 1, 13,
        4, 10, 3, 15, 6, 12, 8, 9
    };
    unsigned char expected[32] = {0};

    if (units > sizeof(expected) || pair_count == 0 ||
        pair_count != sizeof(order) / sizeof(order[0])) {
        return fail("UFFD best-offset expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD best-offset test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for best-offset test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD best-offset allocation failed");
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t step = 0; step < pair_count; step++) {
            size_t anchor = order[(step + pass) % pair_count];
            expected[anchor]++;
            ptr[anchor * unit] = expected[anchor];
            if (ptr[anchor * unit] != expected[anchor]) {
                free(ptr);
                return fail("UFFD best-offset lost anchor data");
            }
            size_t target = anchor + offset_chunks;
            expected[target]++;
            ptr[target * unit] = expected[target];
            if (ptr[target * unit] != expected[target]) {
                free(ptr);
                return fail("UFFD best-offset lost target data");
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD best-offset touches");
    }
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD best-offset test did not exercise pager pressure");
    }
    size_t samples =
        after_touch.policy_bestoffset_train_samples -
        before.policy_bestoffset_train_samples;
    size_t hits =
        after_touch.policy_bestoffset_train_hits -
        before.policy_bestoffset_train_hits;
    size_t slots =
        after_touch.policy_bestoffset_slots_created -
        before.policy_bestoffset_slots_created;
    size_t candidates =
        after_touch.policy_bestoffset_candidates -
        before.policy_bestoffset_candidates;
    if (samples == 0 || hits == 0 || slots == 0 || candidates == 0 ||
        after_touch.policy_bestoffset_top_score == 0 ||
        after_touch.policy_bestoffset_top_offset_sign != 1 ||
        after_touch.policy_bestoffset_top_offset_magnitude != offset_chunks) {
        fprintf(stderr,
                "best-offset stats: samples=%zu hits=%zu slots=%zu "
                "candidates=%zu "
                "top_score=%zu top_sign=%zu top_mag=%zu\n",
                samples, hits, slots, candidates,
                after_touch.policy_bestoffset_top_score,
                after_touch.policy_bestoffset_top_offset_sign,
                after_touch.policy_bestoffset_top_offset_magnitude);
        free(ptr);
        return fail("UFFD best-offset test did not exercise offset predictor");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD best-offset free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD best-offset allocation leaked managed or resident bytes");
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
    if (getenv("MAI_EXPECT_MARKOV_LEAD")) {
        size_t lead_candidates =
            after_touch.policy_markov_lead_candidates -
            before.policy_markov_lead_candidates;
        size_t lead_admitted =
            after_touch.policy_markov_lead_admitted -
            before.policy_markov_lead_admitted;
        size_t lead_completed =
            after_touch.policy_markov_lead_completed -
            before.policy_markov_lead_completed;
        size_t lead_useful =
            after_touch.policy_markov_lead_useful -
            before.policy_markov_lead_useful;
        if (after_touch.policy_successor_chain_depth != 1 ||
            lead_candidates == 0 || lead_admitted == 0 ||
            lead_completed == 0 || lead_useful == 0) {
            fprintf(stderr,
                    "markov lead stats: candidates=%zu admitted=%zu "
                    "completed=%zu useful=%zu depth=%zu\n",
                    lead_candidates, lead_admitted, lead_completed,
                    lead_useful, after_touch.policy_successor_chain_depth);
            free(ptr);
            return fail("UFFD Markov lead-ahead did not produce useful prefetches");
        }
    } else if (getenv("MAI_EXPECT_SUCCESSOR_CHAIN")) {
        size_t chain_candidates =
            after_touch.policy_successor_chain_candidates -
            before.policy_successor_chain_candidates;
        if (chain_candidates == 0 ||
            after_touch.policy_successor_chain_depth < 2) {
            fprintf(stderr,
                    "successor chain stats: candidates=%zu depth=%zu\n",
                    chain_candidates,
                    after_touch.policy_successor_chain_depth);
            free(ptr);
            return fail("UFFD successor chain did not emit candidates");
        }
    } else if (after_touch.policy_successor_chain_depth != 1 ||
               after_touch.policy_successor_chain_candidates !=
                   before.policy_successor_chain_candidates) {
        fprintf(stderr,
                "successor default chain stats: candidates_before=%zu "
                "candidates_after=%zu depth=%zu\n",
                before.policy_successor_chain_candidates,
                after_touch.policy_successor_chain_candidates,
                after_touch.policy_successor_chain_depth);
        free(ptr);
        return fail("UFFD successor default depth did not preserve one-step behavior");
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

static int mode_uffd_pager_signature_like_policy(const char* policy_name,
                                                 int expect_hybrid_activity) {
    static const size_t context_a[] = {0, 2, 3, 5, 7};
    static const size_t context_b[] = {1, 4, 3, 6, 4};
    const size_t context_len = sizeof(context_a) / sizeof(context_a[0]);
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t region_units = 8;
    const size_t regions = size / unit / region_units;
    const size_t passes = 6;
    unsigned char expected[32] = {0};

    if (regions * region_units > sizeof(expected)) {
        return fail("signature-like policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD signature-like policy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for signature-like policy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD signature-like policy allocation failed");
    }
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t region = 0; region < regions; region++) {
            size_t base = region * region_units;
            for (size_t context = 0; context < 2; context++) {
                const size_t* pattern = ((pass + region + context) & 1u) == 0 ?
                    context_a : context_b;
                for (size_t pos = 0; pos < context_len; pos++) {
                    size_t index = base + pattern[pos];
                    expected[index]++;
                    ptr[index * unit] = expected[index];
                    if (ptr[index * unit] != expected[index]) {
                        free(ptr);
                        return fail("UFFD signature-like policy lost write data");
                    }
                }
            }
        }
    }
    for (size_t index = 0; index < regions * region_units; index++) {
        if (ptr[index * unit] != expected[index]) {
            free(ptr);
            return fail("UFFD signature-like policy lost read data");
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD signature-like policy touches");
    }
    size_t train_samples =
        after_touch.policy_signature_train_samples -
        before.policy_signature_train_samples;
    size_t train_hits =
        after_touch.policy_signature_train_hits -
        before.policy_signature_train_hits;
    size_t slots_created =
        after_touch.policy_signature_slots_created -
        before.policy_signature_slots_created;
    size_t candidates =
        after_touch.policy_signature_candidates -
        before.policy_signature_candidates;
    size_t chain_candidates =
        after_touch.policy_signature_chain_candidates -
        before.policy_signature_chain_candidates;
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    size_t prefetch_useful =
        after_touch.policy_prefetch_useful - before.policy_prefetch_useful;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD signature-like policy did not exercise pager pressure");
    }
    if (train_samples == 0 || train_hits == 0 || slots_created == 0 ||
        candidates == 0 || chain_candidates == 0 ||
        prefetch_completed == 0 || prefetch_useful == 0 ||
        after_touch.policy_signature_chain_depth < 2 ||
        after_touch.policy_signature_top_score == 0) {
        fprintf(stderr,
                "%s stats: train=%zu hits=%zu slots=%zu "
                "candidates=%zu chain_candidates=%zu completed=%zu "
                "useful=%zu depth=%zu top_score=%zu\n",
                policy_name, train_samples, train_hits, slots_created, candidates,
                chain_candidates, prefetch_completed, prefetch_useful,
                after_touch.policy_signature_chain_depth,
                after_touch.policy_signature_top_score);
        free(ptr);
        return fail("UFFD signature-like policy did not exercise signature predictor");
    }
    if (expect_hybrid_activity) {
        size_t sketch_updates =
            after_touch.policy_tinylfu_sketch_updates -
            before.policy_tinylfu_sketch_updates;
        size_t state_chunks =
            after_touch.policy_wtinylfu_window_chunks +
            after_touch.policy_wtinylfu_probation_chunks +
            after_touch.policy_wtinylfu_protected_chunks;
        size_t hybrid_candidates =
            (after_touch.policy_hybrid_signature_candidates -
             before.policy_hybrid_signature_candidates) +
            (after_touch.policy_hybrid_successor_candidates -
             before.policy_hybrid_successor_candidates) +
            (after_touch.policy_hybrid_stream_candidates -
             before.policy_hybrid_stream_candidates);
        size_t hybrid_signature_candidates =
            after_touch.policy_hybrid_signature_candidates -
            before.policy_hybrid_signature_candidates;
        size_t hybrid_rejected =
            after_touch.policy_hybrid_admission_rejected -
            before.policy_hybrid_admission_rejected;
        if (sketch_updates == 0 || state_chunks == 0 ||
            hybrid_candidates == 0 || hybrid_signature_candidates == 0) {
            fprintf(stderr,
                    "hybrid stats: sketch_updates=%zu state_chunks=%zu "
                    "hybrid_candidates=%zu signature_candidates=%zu "
                    "hybrid_rejected=%zu\n",
                    sketch_updates, state_chunks, hybrid_candidates,
                    hybrid_signature_candidates, hybrid_rejected);
            free(ptr);
            return fail("UFFD hybrid policy did not exercise integrated policy");
        }
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD signature-like policy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD signature-like policy allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_signature_policy(void) {
    return mode_uffd_pager_signature_like_policy("signature", 0);
}

static int mode_uffd_pager_hybrid_policy(void) {
    return mode_uffd_pager_signature_like_policy("hybrid", 1);
}

static int mode_uffd_pager_hybrid_stream_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t passes = 6;
    unsigned char expected[32] = {0};

    if (units > sizeof(expected)) {
        return fail("hybrid stream policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hybrid stream test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hybrid stream test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD hybrid stream allocation failed");
    }
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t index = 0; index < units; index += 2) {
            expected[index]++;
            ptr[index * unit] = expected[index];
            if (ptr[index * unit] != expected[index]) {
                free(ptr);
                return fail("UFFD hybrid stream lost write data");
            }
        }
    }
    for (size_t index = 0; index < units; index += 2) {
        if (ptr[index * unit] != expected[index]) {
            free(ptr);
            return fail("UFFD hybrid stream lost read data");
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD hybrid stream touches");
    }
    size_t stream_candidates =
        after_touch.policy_hybrid_stream_candidates -
        before.policy_hybrid_stream_candidates;
    size_t stream_admitted =
        after_touch.policy_hybrid_stream_admitted -
        before.policy_hybrid_stream_admitted;
    size_t stream_completed =
        after_touch.policy_hybrid_stream_completed -
        before.policy_hybrid_stream_completed;
    size_t stream_useful =
        after_touch.policy_hybrid_stream_useful -
        before.policy_hybrid_stream_useful;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD hybrid stream test did not exercise pager pressure");
    }
    if (stream_candidates == 0 || stream_admitted == 0 ||
        stream_completed == 0 || stream_useful == 0) {
        fprintf(stderr,
                "hybrid stream stats: candidates=%zu admitted=%zu "
                "completed=%zu useful=%zu\n",
                stream_candidates, stream_admitted, stream_completed,
                stream_useful);
        free(ptr);
        return fail("UFFD hybrid stream test did not exercise stream admission");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hybrid stream free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hybrid stream allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_hybrid_cohort_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t allocations = 3;
    const size_t size = 16 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t passes = 4;
    unsigned char* ptrs[3] = {0};
    unsigned char expected[3][8] = {{0}};

    if (allocations > 3 || units > 8) {
        return fail("hybrid cohort policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hybrid cohort test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hybrid cohort test");
    }

    for (size_t allocation = 0; allocation < allocations; allocation++) {
        ptrs[allocation] = malloc(size);
        if (!ptrs[allocation]) {
            for (size_t free_index = 0; free_index < allocation; free_index++) {
                free(ptrs[free_index]);
            }
            return fail("UFFD hybrid cohort allocation failed");
        }
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t index = 0; index < units; index++) {
            for (size_t allocation = 0; allocation < allocations; allocation++) {
                expected[allocation][index]++;
                ptrs[allocation][index * unit] = expected[allocation][index];
                if (ptrs[allocation][index * unit] !=
                    expected[allocation][index]) {
                    for (size_t free_index = 0; free_index < allocations;
                         free_index++) {
                        free(ptrs[free_index]);
                    }
                    return fail("UFFD hybrid cohort lost write data");
                }
            }
        }
    }
    for (size_t allocation = 0; allocation < allocations; allocation++) {
        for (size_t index = 0; index < units; index++) {
            if (ptrs[allocation][index * unit] !=
                expected[allocation][index]) {
                for (size_t free_index = 0; free_index < allocations;
                     free_index++) {
                    free(ptrs[free_index]);
                }
                return fail("UFFD hybrid cohort lost read data");
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("mai_get_stats failed after UFFD hybrid cohort touches");
    }
    size_t cohort_candidates =
        after_touch.policy_hybrid_cohort_candidates -
        before.policy_hybrid_cohort_candidates;
    size_t cohort_admitted =
        after_touch.policy_hybrid_cohort_admitted -
        before.policy_hybrid_cohort_admitted;
    size_t cohort_completed =
        after_touch.policy_hybrid_cohort_completed -
        before.policy_hybrid_cohort_completed;
    size_t cohort_useful =
        after_touch.policy_hybrid_cohort_useful -
        before.policy_hybrid_cohort_useful;
    if (!stats_show_managed_alloc(&before, &after_touch,
                                  allocations * size) ||
        after_touch.uffd_pager_allocations <
            before.uffd_pager_allocations + allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD hybrid cohort test did not exercise pager pressure");
    }
    if (cohort_candidates == 0 || cohort_admitted == 0 ||
        cohort_completed == 0 || cohort_useful == 0) {
        fprintf(stderr,
                "hybrid cohort stats: candidates=%zu admitted=%zu "
                "completed=%zu useful=%zu\n",
                cohort_candidates, cohort_admitted, cohort_completed,
                cohort_useful);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD hybrid cohort test did not exercise cohort prefetch");
    }

    for (size_t allocation = 0; allocation < allocations; allocation++) {
        free(ptrs[allocation]);
    }
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hybrid cohort free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hybrid cohort allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_phase_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t allocations = 3;
    const size_t size = 16 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t passes = 6;
    unsigned char* ptrs[3] = {0};
    unsigned char expected[3][8] = {{0}};

    if (allocations > 3 || units > 8) {
        return fail("phase policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD phase test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for phase test");
    }

    for (size_t allocation = 0; allocation < allocations; allocation++) {
        ptrs[allocation] = malloc(size);
        if (!ptrs[allocation]) {
            for (size_t free_index = 0; free_index < allocation; free_index++) {
                free(ptrs[free_index]);
            }
            return fail("UFFD phase allocation failed");
        }
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t index = 0; index < units; index++) {
            for (size_t allocation = 0; allocation < allocations; allocation++) {
                expected[allocation][index]++;
                ptrs[allocation][index * unit] = expected[allocation][index];
                if (ptrs[allocation][index * unit] !=
                    expected[allocation][index]) {
                    for (size_t free_index = 0; free_index < allocations;
                         free_index++) {
                        free(ptrs[free_index]);
                    }
                    return fail("UFFD phase lost write data");
                }
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("mai_get_stats failed after UFFD phase touches");
    }
    size_t phase_candidates =
        after_touch.policy_phase_candidates - before.policy_phase_candidates;
    size_t phase_admitted =
        after_touch.policy_phase_admitted - before.policy_phase_admitted;
    size_t phase_completed =
        after_touch.policy_phase_completed - before.policy_phase_completed;
    size_t phase_useful =
        after_touch.policy_phase_useful - before.policy_phase_useful;
    size_t phase_boundary =
        after_touch.policy_phase_boundary_prefetches -
        before.policy_phase_boundary_prefetches;
    size_t phase_hold =
        after_touch.policy_phase_hold_activations -
        before.policy_phase_hold_activations;
    size_t phase_shadow_candidates =
        after_touch.policy_phase_shadow_candidates -
        before.policy_phase_shadow_candidates;
    size_t phase_shadow_useful =
        after_touch.policy_phase_shadow_useful -
        before.policy_phase_shadow_useful;
    size_t phase_shadow_late =
        after_touch.policy_phase_shadow_late -
        before.policy_phase_shadow_late;
    size_t phase_shadow_expired =
        after_touch.policy_phase_shadow_expired -
        before.policy_phase_shadow_expired;
    size_t phase_shadow_overwritten =
        after_touch.policy_phase_shadow_overwritten -
        before.policy_phase_shadow_overwritten;
    size_t phase_shadow_probe_candidates =
        after_touch.policy_phase_shadow_probe_candidates -
        before.policy_phase_shadow_probe_candidates;
    size_t phase_shadow_edge_rejected =
        after_touch.policy_phase_shadow_edge_rejected -
        before.policy_phase_shadow_edge_rejected;
    size_t phase_shadow_edge_confirmed =
        after_touch.policy_phase_shadow_edge_confirmed -
        before.policy_phase_shadow_edge_confirmed;
    size_t phase_shadow_max_late = after_touch.policy_phase_shadow_max_late;
    const char* boundary_only =
        getenv("MAI_POLICY_PHASE_PREFETCH_BOUNDARY_ONLY");
    const char* shadow_probe_chunks_env =
        getenv("MAI_POLICY_PHASE_SHADOW_PROBE_CHUNKS");
    const char* shadow_probe_min_late_env =
        getenv("MAI_POLICY_PHASE_SHADOW_PROBE_MIN_LATE");
    const char* migration_policy_env = getenv("MAI_MIGRATION_POLICY");
    const char* phase_prefetch_env = getenv("MAI_POLICY_PHASE_PREFETCH");
    int boundary_only_enabled =
        boundary_only &&
        (strcmp(boundary_only, "1") == 0 ||
         strcmp(boundary_only, "true") == 0 ||
         strcmp(boundary_only, "yes") == 0 ||
         strcmp(boundary_only, "on") == 0);
    int shadow_probe_enabled =
        shadow_probe_chunks_env && shadow_probe_chunks_env[0] != '\0' &&
        strcmp(shadow_probe_chunks_env, "0") != 0;
    size_t shadow_probe_min_late = 0;
    if (shadow_probe_min_late_env) {
        shadow_probe_min_late = (size_t)strtoull(shadow_probe_min_late_env,
                                                 NULL, 10);
    }
    int markov_phase_hold_only =
        migration_policy_env &&
        (strcmp(migration_policy_env, "markov_phase") == 0 ||
         strcmp(migration_policy_env, "markov-phase") == 0 ||
         strcmp(migration_policy_env, "phase_hold_markov") == 0 ||
         strcmp(migration_policy_env, "phase-hold-markov") == 0) &&
        !phase_prefetch_env;
    if (!stats_show_managed_alloc(&before, &after_touch,
                                  allocations * size) ||
        after_touch.uffd_pager_allocations <
            before.uffd_pager_allocations + allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD phase test did not exercise pager pressure");
    }
    if (markov_phase_hold_only) {
        if (phase_candidates != 0 || phase_admitted != 0 ||
            phase_completed != 0 || phase_hold == 0) {
            fprintf(stderr,
                    "markov phase stats: candidates=%zu admitted=%zu "
                    "completed=%zu hold=%zu\n",
                    phase_candidates, phase_admitted, phase_completed,
                    phase_hold);
            for (size_t allocation = 0; allocation < allocations; allocation++) {
                free(ptrs[allocation]);
            }
            return fail("UFFD markov-phase default should hold without phase prefetch");
        }
    } else if (phase_candidates == 0 || phase_admitted == 0 ||
               phase_completed == 0 ||
               (!boundary_only_enabled && phase_useful == 0)) {
        fprintf(stderr,
                "phase stats: candidates=%zu admitted=%zu "
                "completed=%zu useful=%zu conflicts=%zu\n",
                phase_candidates, phase_admitted, phase_completed,
                phase_useful,
                after_touch.policy_phase_conflicts -
                    before.policy_phase_conflicts);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD phase policy did not produce useful prefetches");
    }
    if (boundary_only_enabled && !shadow_probe_enabled &&
        (phase_boundary == 0 || phase_boundary != phase_admitted)) {
        fprintf(stderr,
                "phase boundary stats: boundary=%zu admitted=%zu\n",
                phase_boundary, phase_admitted);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD boundary phase policy admitted non-boundary prefetches");
    }
    if (boundary_only_enabled && shadow_probe_enabled &&
        phase_boundary == 0) {
        fprintf(stderr,
                "phase probe stats: boundary=%zu admitted=%zu probe=%zu\n",
                phase_boundary, phase_admitted,
                phase_shadow_probe_candidates);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD phase probe test lost boundary admissions");
    }
    if (boundary_only_enabled &&
        (phase_shadow_candidates == 0 || phase_shadow_useful == 0 ||
         phase_shadow_late == 0 ||
         phase_shadow_useful + phase_shadow_expired >
             phase_shadow_candidates ||
         phase_shadow_overwritten > phase_shadow_candidates)) {
        fprintf(stderr,
                "phase shadow stats: candidates=%zu useful=%zu "
                "late=%zu expired=%zu\n",
                phase_shadow_candidates, phase_shadow_useful,
                phase_shadow_late, phase_shadow_expired);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD boundary phase policy shadow telemetry is incomplete");
    }
    if (boundary_only_enabled && shadow_probe_enabled &&
        shadow_probe_min_late != 0 &&
        (phase_shadow_edge_rejected == 0 ||
         phase_shadow_edge_confirmed == 0 ||
         phase_shadow_max_late < shadow_probe_min_late)) {
        fprintf(stderr,
                "phase edge probe stats: probe=%zu edge_rejected=%zu "
                "edge_confirmed=%zu max_late=%zu min_late=%zu\n",
                phase_shadow_probe_candidates, phase_shadow_edge_rejected,
                phase_shadow_edge_confirmed, phase_shadow_max_late,
                shadow_probe_min_late);
        for (size_t allocation = 0; allocation < allocations; allocation++) {
            free(ptrs[allocation]);
        }
        return fail("UFFD edge-confirmed phase probe telemetry is incomplete");
    }

    for (size_t allocation = 0; allocation < allocations; allocation++) {
        free(ptrs[allocation]);
    }
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD phase free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD phase allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_hinted_policy(void) {
    hint_range_fn hint_range =
        (hint_range_fn)dlsym(RTLD_DEFAULT, "mai_hint_range");
    if (!hint_range) {
        return fail("mai_hint_range symbol unavailable for UFFD hinted test");
    }

    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t resident_limit = 16 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t passes = 3;
    unsigned char expected[16] = {0};

    if (units > sizeof(expected)) {
        return fail("hinted policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hinted test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hinted test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD hinted allocation failed");
    }

    MaiHintOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.window_bytes = 8 * 1024 * 1024;
    if (hint_range(ptr, size, MAI_HINT_SEQUENTIAL, &opts) != 0) {
        free(ptr);
        return fail("mai_hint_range rejected managed UFFD hinted range");
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t index = 0; index < units; index++) {
            expected[index]++;
            ptr[index * unit] = expected[index];
            if (ptr[index * unit] != expected[index]) {
                free(ptr);
                return fail("UFFD hinted lost write data");
            }
        }
        for (size_t index = 0; index < units; index++) {
            if (ptr[index * unit] != expected[index]) {
                free(ptr);
                return fail("UFFD hinted lost read data");
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD hinted touches");
    }
    size_t hint_candidates =
        after_touch.policy_hint_candidates - before.policy_hint_candidates;
    size_t hint_admitted =
        after_touch.policy_hint_admitted - before.policy_hint_admitted;
    size_t hint_completed =
        after_touch.policy_hint_completed - before.policy_hint_completed;
    size_t hint_useful =
        after_touch.policy_hint_useful - before.policy_hint_useful;
    size_t hint_rejected =
        after_touch.policy_hint_rejected - before.policy_hint_rejected;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <
            before.uffd_pager_allocations + 1 ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD hinted test did not exercise pager pressure");
    }
    if (after_touch.uffd_resident_bytes > resident_limit) {
        fprintf(stderr,
                "hinted resident above limit: resident=%zu limit=%zu\n",
                after_touch.uffd_resident_bytes, resident_limit);
        free(ptr);
        return fail("UFFD hinted policy exceeded resident limit");
    }
    if (hint_candidates == 0 || hint_admitted == 0 ||
        hint_completed == 0 || hint_useful == 0) {
        fprintf(stderr,
                "hint stats: candidates=%zu admitted=%zu "
                "completed=%zu useful=%zu rejected=%zu\n",
                hint_candidates, hint_admitted, hint_completed, hint_useful,
                hint_rejected);
        free(ptr);
        return fail("UFFD hinted policy did not produce useful prefetches");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hinted free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hinted allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_hybrid_cross_record_cohort_policy_impl(
    int expect_async) {
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t delta = 8;
    const size_t train_indices[] = {0, 5, 2, 7, 1};
    const size_t train_len = sizeof(train_indices) / sizeof(train_indices[0]);
    const size_t trigger_index = 3;
    const size_t target_index = trigger_index + delta;
    MaiStats before;
    MaiStats before_trigger;
    MaiStats after_prefetch;
    MaiStats after_use;
    MaiStats after_free;
    unsigned char expected_a[16] = {0};
    unsigned char expected_b[16] = {0};

    if (units > sizeof(expected_a) || units > sizeof(expected_b) ||
        target_index >= units) {
        return fail("hybrid cross-record cohort expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hybrid cross-record cohort test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hybrid cross-record cohort test");
    }

    unsigned char* a = malloc(size);
    unsigned char* b = malloc(size);
    if (!a || !b) {
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort allocation failed");
    }

    for (size_t i = 0; i < train_len; i++) {
        size_t source = train_indices[i];
        size_t target = source + delta;
        expected_a[source]++;
        a[source * unit] = expected_a[source];
        if (a[source * unit] != expected_a[source]) {
            free(a);
            free(b);
            return fail("UFFD hybrid cross-record cohort lost A training data");
        }
        expected_b[target]++;
        b[target * unit] = expected_b[target];
        if (b[target * unit] != expected_b[target]) {
            free(a);
            free(b);
            return fail("UFFD hybrid cross-record cohort lost B training data");
        }
    }

    if (load_stats(&before_trigger) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed before UFFD hybrid cross-record trigger");
    }

    expected_a[trigger_index]++;
    a[trigger_index * unit] = expected_a[trigger_index];
    if (a[trigger_index * unit] != expected_a[trigger_index]) {
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort lost A trigger data");
    }
    for (size_t wait = 0; wait < 200; wait++) {
        if (load_stats(&after_prefetch) != 0) {
            free(a);
            free(b);
            return fail("mai_get_stats failed after UFFD hybrid cross-record trigger");
        }
        size_t completed =
            after_prefetch.policy_hybrid_cohort_completed -
            before_trigger.policy_hybrid_cohort_completed;
        size_t async_completed =
            after_prefetch.policy_async_prefetch_completed -
            before_trigger.policy_async_prefetch_completed;
        if (completed >= 1 && (!expect_async || async_completed >= 1)) {
            break;
        }
        usleep(1000);
    }

    size_t cohort_candidates =
        after_prefetch.policy_hybrid_cohort_candidates -
        before_trigger.policy_hybrid_cohort_candidates;
    size_t cohort_admitted =
        after_prefetch.policy_hybrid_cohort_admitted -
        before_trigger.policy_hybrid_cohort_admitted;
    size_t cohort_completed =
        after_prefetch.policy_hybrid_cohort_completed -
        before_trigger.policy_hybrid_cohort_completed;
    size_t prefetch_requests =
        after_prefetch.policy_prefetch_requests -
        before_trigger.policy_prefetch_requests;
    size_t prefetch_admitted =
        after_prefetch.policy_prefetch_admitted -
        before_trigger.policy_prefetch_admitted;
    size_t prefetch_completed =
        after_prefetch.policy_prefetch_completed -
        before_trigger.policy_prefetch_completed;
    size_t async_enqueued =
        after_prefetch.policy_async_prefetch_enqueued -
        before_trigger.policy_async_prefetch_enqueued;
    size_t async_completed =
        after_prefetch.policy_async_prefetch_completed -
        before_trigger.policy_async_prefetch_completed;
    if (cohort_candidates != 1 || cohort_admitted != 1 ||
        cohort_completed != 1 || prefetch_requests < 1 ||
        prefetch_admitted != 1 || prefetch_completed != 1) {
        fprintf(stderr,
                "hybrid cross-record cohort prefetch stats: "
                "cohort candidates=%zu admitted=%zu completed=%zu "
                "prefetch requests=%zu admitted=%zu completed=%zu\n",
                cohort_candidates, cohort_admitted, cohort_completed,
                prefetch_requests, prefetch_admitted, prefetch_completed);
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort did not prefetch target chunk");
    }
    if (expect_async && (async_enqueued == 0 || async_completed == 0)) {
        fprintf(stderr,
                "hybrid cross-record async stats: enqueued=%zu completed=%zu\n",
                async_enqueued, async_completed);
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort did not run asynchronously");
    }

    expected_b[target_index]++;
    b[target_index * unit] = expected_b[target_index];
    if (b[target_index * unit] != expected_b[target_index]) {
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort lost prefetched B data");
    }
    if (load_stats(&after_use) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed after UFFD hybrid cross-record use");
    }
    size_t cohort_useful =
        after_use.policy_hybrid_cohort_useful -
        after_prefetch.policy_hybrid_cohort_useful;
    size_t prefetch_useful =
        after_use.policy_prefetch_useful -
        after_prefetch.policy_prefetch_useful;
    size_t useful_bytes =
        after_use.policy_prefetch_useful_bytes -
        after_prefetch.policy_prefetch_useful_bytes;
    if (cohort_useful != 1 || prefetch_useful != 1 ||
        useful_bytes < unit) {
        fprintf(stderr,
                "hybrid cross-record cohort useful stats: "
                "cohort=%zu prefetch=%zu useful_bytes=%zu\n",
                cohort_useful, prefetch_useful, useful_bytes);
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort prefetch was not useful");
    }
    if (!stats_show_managed_alloc(&before, &after_use, size * 2) ||
        after_use.uffd_pager_allocations <
            before.uffd_pager_allocations + 2 ||
        after_use.uffd_faults <= before.uffd_faults) {
        free(a);
        free(b);
        return fail("UFFD hybrid cross-record cohort test did not exercise pager");
    }

    free(a);
    free(b);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hybrid cross-record cohort free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hybrid cross-record cohort allocation leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_hybrid_cross_record_cohort_policy(void) {
    return mode_uffd_pager_hybrid_cross_record_cohort_policy_impl(0);
}

static int mode_uffd_pager_hybrid_cross_record_cohort_async_policy(void) {
    return mode_uffd_pager_hybrid_cross_record_cohort_policy_impl(1);
}

static int mode_uffd_pager_markov_cohort_pressure_cold_start_policy(void) {
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t delta = 8;
    const size_t resident_low = 10 * 1024 * 1024;
    const size_t train_indices[] = {0, 5, 2};
    const size_t train_len = sizeof(train_indices) / sizeof(train_indices[0]);
    const size_t trigger_index = 3;
    const size_t target_index = trigger_index + delta;
    MaiStats before;
    MaiStats before_trigger;
    MaiStats after_prefetch;
    MaiStats after_use;
    MaiStats after_free;
    unsigned char expected_a[16] = {0};
    unsigned char expected_b[16] = {0};

    if (units > sizeof(expected_a) || units > sizeof(expected_b) ||
        target_index >= units) {
        return fail("markov-cohort cold-start expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before markov-cohort cold-start test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for markov-cohort cold-start test");
    }

    unsigned char* a = malloc(size);
    unsigned char* b = malloc(size);
    if (!a || !b) {
        free(a);
        free(b);
        return fail("markov-cohort cold-start allocation failed");
    }

    for (size_t i = 0; i < train_len; i++) {
        size_t source = train_indices[i];
        size_t target = source + delta;
        expected_a[source]++;
        a[source * unit] = expected_a[source];
        if (a[source * unit] != expected_a[source]) {
            free(a);
            free(b);
            return fail("markov-cohort cold-start lost A training data");
        }
        expected_b[target]++;
        b[target * unit] = expected_b[target];
        if (b[target * unit] != expected_b[target]) {
            free(a);
            free(b);
            return fail("markov-cohort cold-start lost B training data");
        }
    }

    if (load_stats(&before_trigger) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed before markov-cohort cold-start trigger");
    }
    size_t prior_candidates =
        before_trigger.policy_hybrid_cohort_candidates -
        before.policy_hybrid_cohort_candidates;
    size_t prior_admitted =
        before_trigger.policy_hybrid_cohort_admitted -
        before.policy_hybrid_cohort_admitted;
    size_t prior_completed =
        before_trigger.policy_hybrid_cohort_completed -
        before.policy_hybrid_cohort_completed;
    size_t prior_useful =
        before_trigger.policy_hybrid_cohort_useful -
        before.policy_hybrid_cohort_useful;
    if (prior_candidates != 0 || prior_admitted != 0 ||
        prior_completed != 0 || prior_useful != 0) {
        fprintf(stderr,
                "markov-cohort cold-start prior stats: candidates=%zu "
                "admitted=%zu completed=%zu useful=%zu\n",
                prior_candidates, prior_admitted, prior_completed,
                prior_useful);
        free(a);
        free(b);
        return fail("markov-cohort cold-start fired before the trigger");
    }
    if (before_trigger.uffd_resident_bytes < resident_low) {
        fprintf(stderr,
                "markov-cohort cold-start resident bytes=%zu low=%zu\n",
                before_trigger.uffd_resident_bytes, resident_low);
        free(a);
        free(b);
        return fail("markov-cohort cold-start did not reach low pressure");
    }

    expected_a[trigger_index]++;
    a[trigger_index * unit] = expected_a[trigger_index];
    if (a[trigger_index * unit] != expected_a[trigger_index]) {
        free(a);
        free(b);
        return fail("markov-cohort cold-start lost A trigger data");
    }
    for (size_t wait = 0; wait < 200; wait++) {
        if (load_stats(&after_prefetch) != 0) {
            free(a);
            free(b);
            return fail("mai_get_stats failed after markov-cohort cold-start trigger");
        }
        size_t completed =
            after_prefetch.policy_hybrid_cohort_completed -
            before_trigger.policy_hybrid_cohort_completed;
        if (completed >= 1) {
            break;
        }
        usleep(1000);
    }

    size_t cohort_candidates =
        after_prefetch.policy_hybrid_cohort_candidates -
        before_trigger.policy_hybrid_cohort_candidates;
    size_t cohort_admitted =
        after_prefetch.policy_hybrid_cohort_admitted -
        before_trigger.policy_hybrid_cohort_admitted;
    size_t cohort_completed =
        after_prefetch.policy_hybrid_cohort_completed -
        before_trigger.policy_hybrid_cohort_completed;
    if (cohort_candidates != 1 || cohort_admitted != 1 ||
        cohort_completed != 1) {
        fprintf(stderr,
                "markov-cohort cold-start stats: candidates=%zu "
                "admitted=%zu completed=%zu\n",
                cohort_candidates, cohort_admitted, cohort_completed);
        free(a);
        free(b);
        return fail("markov-cohort cold-start did not admit first pressured seed");
    }

    expected_b[target_index]++;
    b[target_index * unit] = expected_b[target_index];
    if (b[target_index * unit] != expected_b[target_index]) {
        free(a);
        free(b);
        return fail("markov-cohort cold-start lost prefetched B data");
    }
    if (load_stats(&after_use) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed after markov-cohort cold-start use");
    }
    size_t cohort_useful =
        after_use.policy_hybrid_cohort_useful -
        after_prefetch.policy_hybrid_cohort_useful;
    size_t prefetch_useful =
        after_use.policy_prefetch_useful -
        after_prefetch.policy_prefetch_useful;
    if (cohort_useful != 1 || prefetch_useful != 1) {
        fprintf(stderr,
                "markov-cohort cold-start useful stats: cohort=%zu "
                "prefetch=%zu\n",
                cohort_useful, prefetch_useful);
        free(a);
        free(b);
        return fail("markov-cohort cold-start prefetch was not useful");
    }
    if (!stats_show_managed_alloc(&before, &after_use, size * 2) ||
        after_use.uffd_pager_allocations <
            before.uffd_pager_allocations + 2 ||
        after_use.uffd_faults <= before.uffd_faults) {
        free(a);
        free(b);
        return fail("markov-cohort cold-start did not exercise pager");
    }

    free(a);
    free(b);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after markov-cohort cold-start free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("markov-cohort cold-start leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_markov_cohort_free_releases_lease(void) {
    const size_t size = 32 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t units = size / unit;
    const size_t delta = 8;
    const size_t train_first[] = {0, 5, 2};
    const size_t train_second[] = {0, 5, 2, 1};
    const size_t first_len = sizeof(train_first) / sizeof(train_first[0]);
    const size_t second_len = sizeof(train_second) / sizeof(train_second[0]);
    const size_t trigger_index = 3;
    MaiStats before;
    MaiStats before_first_trigger;
    MaiStats after_first_prefetch;
    MaiStats after_release;
    MaiStats after_second_prefetch;
    MaiStats after_free;
    unsigned char expected_a[16] = {0};
    unsigned char expected_b[16] = {0};
    unsigned char expected_c[16] = {0};
    unsigned char expected_d[16] = {0};

    if (units > sizeof(expected_a) || units > sizeof(expected_b) ||
        units > sizeof(expected_c) || units > sizeof(expected_d) ||
        trigger_index + delta >= units) {
        return fail("markov-cohort free-release expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before markov-cohort free-release test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for markov-cohort free-release test");
    }

    unsigned char* a = malloc(size);
    unsigned char* b = malloc(size);
    if (!a || !b) {
        free(a);
        free(b);
        return fail("markov-cohort free-release first allocation failed");
    }
    for (size_t i = 0; i < first_len; i++) {
        size_t source = train_first[i];
        size_t target = source + delta;
        expected_a[source]++;
        a[source * unit] = expected_a[source];
        if (a[source * unit] != expected_a[source]) {
            free(a);
            free(b);
            return fail("markov-cohort free-release lost A training data");
        }
        expected_b[target]++;
        b[target * unit] = expected_b[target];
        if (b[target * unit] != expected_b[target]) {
            free(a);
            free(b);
            return fail("markov-cohort free-release lost B training data");
        }
    }
    if (load_stats(&before_first_trigger) != 0) {
        free(a);
        free(b);
        return fail("mai_get_stats failed before markov-cohort first trigger");
    }
    expected_a[trigger_index]++;
    a[trigger_index * unit] = expected_a[trigger_index];
    if (a[trigger_index * unit] != expected_a[trigger_index]) {
        free(a);
        free(b);
        return fail("markov-cohort free-release lost A trigger data");
    }
    for (size_t wait = 0; wait < 200; wait++) {
        if (load_stats(&after_first_prefetch) != 0) {
            free(a);
            free(b);
            return fail("mai_get_stats failed after markov-cohort first trigger");
        }
        size_t completed =
            after_first_prefetch.policy_hybrid_cohort_completed -
            before_first_trigger.policy_hybrid_cohort_completed;
        if (completed >= 1) {
            break;
        }
        usleep(1000);
    }
    size_t first_completed =
        after_first_prefetch.policy_hybrid_cohort_completed -
        before_first_trigger.policy_hybrid_cohort_completed;
    if (first_completed == 0) {
        free(a);
        free(b);
        return fail("markov-cohort free-release did not create first lease");
    }

    free(b);
    free(a);
    if (load_stats(&after_release) != 0) {
        return fail("mai_get_stats failed after markov-cohort first free");
    }

    unsigned char* c = malloc(size);
    unsigned char* d = malloc(size);
    if (!c || !d) {
        free(c);
        free(d);
        return fail("markov-cohort free-release second allocation failed");
    }
    for (size_t i = 0; i < second_len; i++) {
        size_t source = train_second[i];
        size_t target = source + delta;
        expected_c[source]++;
        c[source * unit] = expected_c[source];
        if (c[source * unit] != expected_c[source]) {
            free(c);
            free(d);
            return fail("markov-cohort free-release lost C training data");
        }
        expected_d[target]++;
        d[target * unit] = expected_d[target];
        if (d[target * unit] != expected_d[target]) {
            free(c);
            free(d);
            return fail("markov-cohort free-release lost D training data");
        }
    }
    expected_c[trigger_index]++;
    c[trigger_index * unit] = expected_c[trigger_index];
    if (c[trigger_index * unit] != expected_c[trigger_index]) {
        free(c);
        free(d);
        return fail("markov-cohort free-release lost C trigger data");
    }
    for (size_t wait = 0; wait < 200; wait++) {
        if (load_stats(&after_second_prefetch) != 0) {
            free(c);
            free(d);
            return fail("mai_get_stats failed after markov-cohort second trigger");
        }
        size_t completed =
            after_second_prefetch.policy_hybrid_cohort_completed -
            after_release.policy_hybrid_cohort_completed;
        if (completed >= 1) {
            break;
        }
        usleep(1000);
    }
    size_t second_candidates =
        after_second_prefetch.policy_hybrid_cohort_candidates -
        after_release.policy_hybrid_cohort_candidates;
    size_t second_admitted =
        after_second_prefetch.policy_hybrid_cohort_admitted -
        after_release.policy_hybrid_cohort_admitted;
    size_t second_completed =
        after_second_prefetch.policy_hybrid_cohort_completed -
        after_release.policy_hybrid_cohort_completed;
    if (second_candidates == 0 || second_admitted == 0 ||
        second_completed == 0) {
        fprintf(stderr,
                "markov-cohort free-release second stats: "
                "candidates=%zu admitted=%zu completed=%zu\n",
                second_candidates, second_admitted, second_completed);
        free(c);
        free(d);
        return fail("markov-cohort free-before-use lease suppressed later prefetch");
    }

    free(c);
    free(d);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after markov-cohort free-release free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("markov-cohort free-release leaked managed or resident bytes");
    }
    return 0;
}

static int mode_uffd_pager_hybrid_default_low_window(void) {
    MaiStats before;
    MaiStats before_trigger;
    MaiStats after_trigger;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    unsigned char expected[32] = {0};

    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD hybrid default-low test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for hybrid default-low test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD hybrid default-low allocation failed");
    }
    for (size_t index = 0; index < 3; index++) {
        size_t unit_index = index * 2;
        expected[unit_index]++;
        runtime_store_byte(ptr, unit_index * unit, expected[unit_index]);
        if (runtime_load_byte(ptr, unit_index * unit) != expected[unit_index]) {
            free(ptr);
            return fail("UFFD hybrid default-low lost warmup data");
        }
    }
    if (load_stats(&before_trigger) != 0) {
        free(ptr);
        return fail("mai_get_stats failed before hybrid default-low trigger");
    }

    size_t trigger_unit = 6;
    expected[trigger_unit]++;
    runtime_store_byte(ptr, trigger_unit * unit, expected[trigger_unit]);
    if (runtime_load_byte(ptr, trigger_unit * unit) != expected[trigger_unit]) {
        free(ptr);
        return fail("UFFD hybrid default-low lost trigger data");
    }
    if (load_stats(&after_trigger) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after hybrid default-low trigger");
    }

    size_t stream_admitted =
        after_trigger.policy_hybrid_stream_admitted -
        before_trigger.policy_hybrid_stream_admitted;
    size_t stream_completed =
        after_trigger.policy_hybrid_stream_completed -
        before_trigger.policy_hybrid_stream_completed;
    size_t total_admitted =
        after_trigger.policy_prefetch_admitted -
        before_trigger.policy_prefetch_admitted;
    size_t total_completed =
        after_trigger.policy_prefetch_completed -
        before_trigger.policy_prefetch_completed;
    if (total_admitted < 2 || total_completed < 2) {
        fprintf(stderr,
                "hybrid default-low window stats: total_admitted=%zu "
                "total_completed=%zu stream_admitted=%zu "
                "stream_completed=%zu resident=%zu\n",
                total_admitted, total_completed,
                stream_admitted, stream_completed,
                after_trigger.uffd_resident_bytes);
        free(ptr);
        return fail("UFFD hybrid default-low test did not emit multi-candidate window");
    }
    if (after_trigger.uffd_resident_bytes >= after_trigger.max_rss) {
        free(ptr);
        return fail("UFFD hybrid default-low trigger unexpectedly reached RSS cap");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD hybrid default-low free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD hybrid default-low allocation leaked managed or resident bytes");
    }
    return 0;
}

static size_t runtime_spatial_offset(size_t position, size_t pass,
                                     size_t region, int mixed_masks) {
    static const size_t offsets_a[] = {0, 3, 5};
    static const size_t offsets_b[] = {1, 4, 7};
    const size_t* offsets = offsets_a;
    size_t count = sizeof(offsets_a) / sizeof(offsets_a[0]);
    if (mixed_masks && (region & 1u) != 0) {
        offsets = offsets_b;
    }
    size_t rotated = (position + pass + region) % count;
    if (((pass + region) & 1u) != 0) {
        rotated = count - 1 - rotated;
    }
    return offsets[rotated];
}

static int mode_uffd_pager_spatial_mask_policy(void) {
    MaiStats before;
    MaiStats after_touch;
    MaiStats after_free;
    const size_t size = 64 * 1024 * 1024;
    const size_t unit = 2 * 1024 * 1024;
    const size_t region_units = 8;
    const size_t mask_units = 3;
    const size_t units = size / unit;
    const size_t regions = units / region_units;
    const size_t passes = 4;
    const size_t logical_touches = passes * regions * mask_units * 2;
    unsigned char expected[32] = {0};

    if (units > sizeof(expected) || units % region_units != 0) {
        return fail("spatial policy expected array is too small");
    }
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats failed before UFFD spatial policy test");
    }
    if (before.config_error != 0 && getenv("MAI_UFFD_ALLOW_SKIP")) {
        return skip("UFFD pager required mode is unavailable on this host");
    }
    if (before.config_error != 0 || before.uffd_pager_available == 0) {
        return fail("UFFD pager is unavailable for spatial policy test");
    }

    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return fail("UFFD spatial policy allocation failed");
    }
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t position = 0; position < mask_units; position++) {
            for (size_t region = 0; region < regions; region++) {
                size_t region_base = region * region_units;
                size_t index = region_base +
                    runtime_spatial_offset(position, pass, region, 1);
                expected[index]++;
                ptr[index * unit] = expected[index];
                if (ptr[index * unit] != expected[index]) {
                    free(ptr);
                    return fail("UFFD spatial policy lost write data");
                }
            }
        }
        for (size_t position = 0; position < mask_units; position++) {
            for (size_t region = 0; region < regions; region++) {
                size_t region_base = region * region_units;
                size_t index = region_base +
                    runtime_spatial_offset(position, pass + 1, region, 1);
                if (ptr[index * unit] != expected[index]) {
                    free(ptr);
                    return fail("UFFD spatial policy lost read data");
                }
            }
        }
    }

    if (load_stats(&after_touch) != 0) {
        free(ptr);
        return fail("mai_get_stats failed after UFFD spatial policy touches");
    }
    size_t prefetch_completed =
        after_touch.policy_prefetch_completed - before.policy_prefetch_completed;
    size_t prefetch_useful =
        after_touch.policy_prefetch_useful - before.policy_prefetch_useful;
    size_t demand_faults =
        after_touch.policy_demand_faults - before.policy_demand_faults;
    if (!stats_show_managed_alloc(&before, &after_touch, size) ||
        after_touch.uffd_pager_allocations <= before.uffd_pager_allocations ||
        after_touch.uffd_faults <= before.uffd_faults ||
        after_touch.uffd_evictions <= before.uffd_evictions) {
        free(ptr);
        return fail("UFFD spatial policy did not exercise pager pressure");
    }
    if (prefetch_completed == 0) {
        fprintf(stderr,
                "spatial policy prefetch stats: completed=%zu useful=%zu\n",
                prefetch_completed, prefetch_useful);
        free(ptr);
        return fail("UFFD spatial policy did not prefetch learned regions");
    }
    if (demand_faults >= logical_touches) {
        fprintf(stderr,
                "spatial policy demand faults: faults=%zu touches=%zu\n",
                demand_faults, logical_touches);
        free(ptr);
        return fail("UFFD spatial policy did not reduce demand faults");
    }

    free(ptr);
    if (load_stats(&after_free) != 0) {
        return fail("mai_get_stats failed after UFFD spatial policy free");
    }
    if (after_free.live_managed_bytes != before.live_managed_bytes ||
        after_free.uffd_resident_bytes > before.uffd_resident_bytes) {
        return fail("UFFD spatial policy allocation leaked managed or resident bytes");
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
    if (strcmp(argv[1], "uffd_pager_memory_cap_reclaim") == 0) {
        return mode_uffd_pager_memory_cap_reclaim();
    }
    if (strcmp(argv[1], "uffd_pager_fault_headroom") == 0) {
        return mode_uffd_pager_fault_headroom();
    }
    if (strcmp(argv[1], "uffd_pager_aligned_required") == 0) {
        return mode_uffd_pager_aligned_required();
    }
    if (strcmp(argv[1], "uffd_pager_spatial_prefetch") == 0) {
        return mode_uffd_pager_spatial_prefetch();
    }
    if (strcmp(argv[1], "uffd_pager_async_prefetch") == 0) {
        return mode_uffd_pager_async_prefetch();
    }
    if (strcmp(argv[1], "uffd_pager_async_queue_saturation_no_sync_prefetch") == 0) {
        return mode_uffd_pager_async_queue_saturation_no_sync_prefetch();
    }
    if (strcmp(argv[1], "uffd_pager_record_protect_policy") == 0) {
        return mode_uffd_pager_record_protect_policy();
    }
    if (strcmp(argv[1], "uffd_pager_active_record_policy") == 0) {
        return mode_uffd_pager_active_record_policy();
    }
    if (strcmp(argv[1], "uffd_pager_active_record_prefetch_guard") == 0) {
        return mode_uffd_pager_active_record_prefetch_guard();
    }
    if (strcmp(argv[1], "uffd_pager_adaptive_policy_throttle") == 0) {
        return mode_uffd_pager_adaptive_policy_throttle();
    }
    if (strcmp(argv[1], "uffd_pager_adaptive_legacy_noop") == 0) {
        return mode_uffd_pager_adaptive_legacy_noop();
    }
    if (strcmp(argv[1], "uffd_pager_clean_shadow_skip") == 0) {
        return mode_uffd_pager_clean_shadow_skip();
    }
    if (strcmp(argv[1], "uffd_pager_clean_shadow_dirty") == 0) {
        return mode_uffd_pager_clean_shadow_dirty();
    }
    if (strcmp(argv[1], "uffd_pager_clean_shadow_fallback") == 0) {
        return mode_uffd_pager_clean_shadow_fallback();
    }
    if (strcmp(argv[1], "uffd_pager_stride_policy") == 0) {
        return mode_uffd_pager_stride_policy();
    }
    if (strcmp(argv[1], "uffd_pager_lfu_hotset_scan") == 0) {
        return mode_uffd_pager_lfu_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_lruk_hotset_scan") == 0) {
        return mode_uffd_pager_lruk_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_car_hotset_scan") == 0) {
        return mode_uffd_pager_car_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_irr_hotset_scan") == 0) {
        return mode_uffd_pager_irr_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_arc_pivot_policy") == 0) {
        return mode_uffd_pager_arc_pivot_policy();
    }
    if (strcmp(argv[1], "uffd_pager_tinylfu_hotset_scan") == 0) {
        return mode_uffd_pager_tinylfu_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_wtinylfu_hotset_scan") == 0) {
        return mode_uffd_pager_wtinylfu_hotset_scan();
    }
    if (strcmp(argv[1], "uffd_pager_bestoffset_policy") == 0) {
        return mode_uffd_pager_bestoffset_policy();
    }
    if (strcmp(argv[1], "uffd_pager_successor_policy") == 0) {
        return mode_uffd_pager_successor_policy();
    }
    if (strcmp(argv[1], "uffd_pager_signature_policy") == 0) {
        return mode_uffd_pager_signature_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_policy") == 0) {
        return mode_uffd_pager_hybrid_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_stream_policy") == 0) {
        return mode_uffd_pager_hybrid_stream_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_cohort_policy") == 0) {
        return mode_uffd_pager_hybrid_cohort_policy();
    }
    if (strcmp(argv[1], "uffd_pager_phase_policy") == 0) {
        return mode_uffd_pager_phase_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hinted_policy") == 0) {
        return mode_uffd_pager_hinted_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_cross_record_cohort_policy") == 0) {
        return mode_uffd_pager_hybrid_cross_record_cohort_policy();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_cross_record_cohort_async_policy") == 0) {
        return mode_uffd_pager_hybrid_cross_record_cohort_async_policy();
    }
    if (strcmp(argv[1], "uffd_pager_markov_cohort_pressure_cold_start_policy") == 0) {
        return mode_uffd_pager_markov_cohort_pressure_cold_start_policy();
    }
    if (strcmp(argv[1], "uffd_pager_markov_cohort_free_releases_lease") == 0) {
        return mode_uffd_pager_markov_cohort_free_releases_lease();
    }
    if (strcmp(argv[1], "uffd_pager_hybrid_default_low_window") == 0) {
        return mode_uffd_pager_hybrid_default_low_window();
    }
    if (strcmp(argv[1], "uffd_pager_spatial_mask_policy") == 0) {
        return mode_uffd_pager_spatial_mask_policy();
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
