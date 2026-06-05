#ifndef __MALLOC_INTERCEPTOR_H
#define __MALLOC_INTERCEPTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>

/**
 * @file malloc_interceptor.h
 * @brief Public API for MAI lifecycle, stats, and reclaim controls.
 */

/**
 * @brief Attach memory allocation function interception
 *
 * This function attaches interception to supported allocation functions using
 * the Gum library.
 *
 * @return 0 if interception was successful or MAI is disabled, -1 on configuration or hook failure.
 */
typedef struct {
    int enabled;
    int configured;
    int config_error;
    size_t threshold;
    size_t arena_size;
    size_t target_rss;
    size_t current_rss_bytes;
    size_t high_water_rss_bytes;
    size_t arena_segments;
    size_t arena_bytes;
    size_t managed_bytes_total;
    size_t pass_through_bytes_total;
    size_t live_managed_bytes;
    size_t high_water_managed_bytes;
    size_t managed_allocations;
    size_t pass_through_allocations;
    size_t managed_frees;
    size_t reclaim_calls;
    size_t policy_reclaim_calls;
    size_t reclaimed_bytes;
    size_t mmap_calls;
    size_t munmap_calls;
    size_t mremap_calls;
    size_t brk_calls;
    size_t sbrk_calls;
    size_t profile_sites;
    size_t hotness_samples;
    size_t hotness_sampled_pages;
    size_t hotness_resident_pages;
    size_t allocator_hook_mode;
    size_t allocator_libc_patches;
    size_t allocator_preload_calls;
    size_t allocator_frida_calls;
} MaiStats;

#ifdef __cplusplus
extern "C" {
#endif

int malloc_interceptor_attach(void);

/**
 * @brief Detach memory allocation function interception
 *
 * This function detaches the previously attached memory allocation function interception and releases any resources used by the Gum library.
 *
 * @return void
 */
void malloc_interceptor_detach(void);

void malloc_interceptor_dettach(void);

__attribute__((visibility("default")))
int mai_get_stats(MaiStats* stats);

__attribute__((visibility("default")))
int mai_reclaim_all(void);

__attribute__((visibility("default")))
int mai_sample_hotness(void);

#ifdef __cplusplus
}
#endif

#endif /* __MALLOC_INTERCEPTOR_H */
