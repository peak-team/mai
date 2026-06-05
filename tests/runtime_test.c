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

static int fail(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 1;
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
    if (strcmp(argv[1], "large") == 0) return mode_large();
    if (strcmp(argv[1], "calloc") == 0) return mode_calloc();
    if (strcmp(argv[1], "realloc") == 0) return mode_realloc();
    if (strcmp(argv[1], "alignment") == 0) return mode_alignment();
    if (strcmp(argv[1], "many") == 0) return mode_many();
    if (strcmp(argv[1], "thread") == 0) return mode_thread();
    if (strcmp(argv[1], "reclaim") == 0) return mode_reclaim();
    if (strcmp(argv[1], "target_rss") == 0) return mode_target_rss();
    if (strcmp(argv[1], "profile") == 0) return mode_profile();
    if (strcmp(argv[1], "hotness") == 0) return mode_hotness();
    if (strcmp(argv[1], "hotness_live_exit") == 0) return mode_hotness_live_exit();
    if (strcmp(argv[1], "diagnostics") == 0) return mode_diagnostics();
    if (strcmp(argv[1], "dlopen") == 0) return mode_dlopen();
    if (strcmp(argv[1], "dlopen_local_allocator") == 0) return mode_dlopen_local_allocator();
    if (strcmp(argv[1], "backing_failure") == 0) return mode_backing_failure();
    if (strcmp(argv[1], "unprivileged") == 0) return mode_unprivileged();

    return fail("unknown mode");
}
