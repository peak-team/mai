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

#if defined(__GNUC__) || defined(__clang__)
#define MAI_DEPRECATED(message) __attribute__((deprecated(message)))
#else
#define MAI_DEPRECATED(message)
#endif

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
    size_t excluded_ranges;
    size_t excluded_bytes;
    size_t exclusion_events;
    size_t exclusion_release_events;
    size_t reclaim_skipped_excluded;
    size_t reclaim_skipped_excluded_bytes;
    size_t safety_hook_patches;
    size_t max_rss;
    size_t memory_cap_reclaim_calls;
    size_t memory_cap_failures;
    size_t anon_allocations;
    size_t file_allocations;
    size_t migrated_to_file_bytes;
    size_t promoted_to_anon_bytes;
    size_t uffd_pager_available;
    size_t uffd_pager_allocations;
    size_t uffd_faults;
    size_t uffd_evictions;
    size_t uffd_resident_bytes;
    size_t uffd_fallbacks;
} MaiStats;

/**
 * Experimental, advisory range hint kinds for future predictive migration
 * strategies. These hints do not infer or guarantee access order, placement,
 * prefetch, or reclaim behavior. MAI may ignore any hint at any time.
 */
typedef enum {
    MAI_HINT_UNKNOWN = 0,
    MAI_HINT_NONE = 1,
    MAI_HINT_SEQUENTIAL = 2,
    MAI_HINT_SPARSE = 3,
    MAI_HINT_RANDOM_HOTSET = 4,
    MAI_HINT_COLD_RECLAIM = 5
} MaiHintKind;

/**
 * Versioned options for mai_hint_range().
 *
 * Set size to sizeof(MaiHintOptions). All fields are advisory and best-effort:
 * flags are currently recorded but not interpreted, hotset_bytes can describe
 * the expected protected working set for MAI_HINT_RANDOM_HOTSET, and
 * window_bytes can describe an expected sequential or sparse access window.
 * Reserved fields must not be used for correctness.
 */
typedef struct {
    size_t size;
    uint32_t flags;
    size_t hotset_bytes;
    size_t window_bytes;
    uint64_t reserved[4];
} MaiHintOptions;

/**
 * Versioned options for intrusive sampled access tracing.
 *
 * This is an experimental performance-tuning mechanism. MAI protects a bounded
 * set of full pages inside the requested managed range, records sampled first
 * touches through SIGSEGV, and restores normal read/write access for each
 * touched page. max_pages caps the sample count. chunk_bytes changes sampling
 * from evenly spaced pages to the first full page of each chunk, which is the
 * preferred mode when a whole allocation call or large chunk is expected to be
 * accessed together. It is intentionally intrusive and should be used only when
 * the application accepts signal-handler and page-protection overhead.
 */
typedef struct {
    size_t size;
    size_t max_pages;
    size_t chunk_bytes;
    uint32_t flags;
    uint64_t reserved[4];
} MaiAccessTraceOptions;

/**
 * Snapshot returned by mai_get_access_trace().
 *
 * touched_bitmap uses bit N for sampled page N. Up to 64 sampled pages are
 * tracked per process in the current implementation.
 */
typedef struct {
    size_t size;
    size_t page_size;
    size_t total_pages;
    size_t armed_pages;
    size_t touched_pages;
    uint64_t touched_bitmap;
    uint64_t first_touch_sequence;
    uint64_t last_touch_sequence;
    uint64_t reserved[4];
} MaiAccessTraceSnapshot;

/**
 * Versioned options for one adaptive heartbeat tick.
 *
 * The heartbeat observes sampled first touches from the previous epoch, reduces
 * observation and skips migration while access is busy, and uses quiet epochs
 * to demote cold sampled chunks. chunk_bytes controls the observation and
 * migration granularity; by default MAI uses a conservative large chunk.
 */
typedef struct {
    size_t size;
    size_t observe_pages;
    size_t chunk_bytes;
    size_t migrate_bytes;
    uint32_t flags;
    uint64_t reserved[4];
} MaiHeartbeatOptions;

/**
 * Snapshot returned by mai_heartbeat().
 */
typedef struct {
    size_t size;
    size_t epoch;
    size_t observed_allocations;
    size_t armed_pages;
    size_t touched_pages;
    size_t reclaimed_bytes;
    size_t busy_score;
    int busy;
    uint64_t reserved[4];
} MaiHeartbeatSnapshot;

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

MAI_DEPRECATED("use malloc_interceptor_detach")
void malloc_interceptor_dettach(void);

__attribute__((visibility("default")))
int mai_get_stats(MaiStats* stats);

/**
 * Versioned stats snapshot API.
 *
 * mai_get_stats() preserves the original prefix-sized ABI. Call this function
 * with sizeof(MaiStats) to receive fields added after the original stats
 * layout, such as UFFD pager counters.
 */
__attribute__((visibility("default")))
int mai_get_stats_sized(MaiStats* stats, size_t stats_size);

__attribute__((visibility("default")))
int mai_reclaim_all(void);

__attribute__((visibility("default")))
int mai_sample_hotness(void);

/**
 * Record an experimental advisory hint for a live MAI-managed range.
 *
 * The hint is metadata only: it is best-effort, may be ignored, never bypasses
 * safety exclusions, and provides no ordering, residency, reclaim, prefetch, or
 * performance guarantee. Unmanaged ranges are accepted as no-op success.
 *
 * Returns 0 when accepted or ignored as a no-op, or -1 with errno set for
 * invalid arguments.
 */
__attribute__((visibility("default")))
int mai_hint_range(void* ptr, size_t len, uint32_t kind,
                   const MaiHintOptions* opts);

/**
 * Explicitly reclaim a subrange of a live MAI-managed allocation using the
 * configured reclaim policy. This is advisory and best-effort; excluded ranges
 * are skipped and unmanaged ranges are no-op success. Anonymous-first managed
 * chunks are first demoted to storage-backed mappings so data is preserved.
 *
 * Returns 0 when accepted or ignored as a no-op, or -1 with errno set for
 * invalid arguments or syscall failures.
 */
__attribute__((visibility("default")))
int mai_reclaim_range(void* ptr, size_t len);

/**
 * Promote storage-backed cold chunks in a live MAI-managed subrange back to
 * anonymous memory, then ask the kernel to prefetch with MADV_WILLNEED when
 * available. This is a weak, best-effort hint and may be ignored by the kernel
 * or by MAI. Unmanaged ranges are no-op success.
 *
 * Returns 0 when accepted or ignored as a no-op, or -1 with errno set for
 * invalid arguments or syscall failures.
 */
__attribute__((visibility("default")))
int mai_prefetch(void* ptr, size_t len);

/**
 * Prepare storage-backed cold chunks in a live MAI-managed subrange for a
 * full overwrite by replacing them with anonymous memory without reading old
 * storage contents. This is appropriate only when the application will write
 * the entire prepared range before reading it. Unmanaged ranges are no-op
 * success.
 *
 * Returns 0 when accepted or ignored as a no-op, or -1 with errno set for
 * invalid arguments or syscall failures.
 */
__attribute__((visibility("default")))
int mai_prepare_write(void* ptr, size_t len);

/**
 * Intrusively sample first-touch access over full pages inside a live
 * MAI-managed range. Unmanaged ranges are accepted as no-op success. Only one
 * trace may be active per allocation; starting a new trace replaces the
 * previous trace for that allocation.
 *
 * Returns 0 when armed or ignored as a no-op, or -1 with errno set for invalid
 * arguments, unavailable sample slots, signal-handler installation failure, or
 * mprotect failure.
 */
__attribute__((visibility("default")))
int mai_trace_access(void* ptr, size_t len, const MaiAccessTraceOptions* opts);

/**
 * Read the current sampled access snapshot for a live MAI-managed allocation.
 * Unmanaged ranges return an empty successful snapshot.
 */
__attribute__((visibility("default")))
int mai_get_access_trace(void* ptr, MaiAccessTraceSnapshot* snapshot);

/**
 * Stop sampled access tracing for a live MAI-managed allocation and restore any
 * still-protected sampled pages. Unmanaged ranges are no-op success.
 */
__attribute__((visibility("default")))
int mai_stop_access_trace(void* ptr);

/**
 * Run one adaptive observation/migration heartbeat. This is deterministic and
 * can be called by an application, runtime integration, or future background
 * controller. It re-arms sampled pages for the next epoch.
 */
__attribute__((visibility("default")))
int mai_heartbeat(const MaiHeartbeatOptions* opts, MaiHeartbeatSnapshot* snapshot);

#ifdef __cplusplus
}
#endif

#endif /* __MALLOC_INTERCEPTOR_H */
