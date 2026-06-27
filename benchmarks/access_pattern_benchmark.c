#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

typedef int (*get_stats_fn)(MaiStats*);
typedef int (*get_stats_sized_fn)(MaiStats*, size_t);
typedef int (*reclaim_all_fn)(void);
typedef int (*trace_access_fn)(void*, size_t, const MaiAccessTraceOptions*);
typedef int (*get_access_trace_fn)(void*, MaiAccessTraceSnapshot*);
typedef int (*stop_access_trace_fn)(void*);
typedef int (*heartbeat_fn)(const MaiHeartbeatOptions*, MaiHeartbeatSnapshot*);
typedef int (*range_op_fn)(void*, size_t);
typedef int (*hint_range_fn)(void*, size_t, uint32_t, const MaiHintOptions*);

static size_t page_size_bytes = 4096;
static get_stats_fn get_stats = NULL;
static get_stats_sized_fn get_stats_sized = NULL;
static reclaim_all_fn reclaim_all = NULL;
static trace_access_fn trace_access = NULL;
static get_access_trace_fn get_access_trace = NULL;
static stop_access_trace_fn stop_access_trace = NULL;
static heartbeat_fn heartbeat = NULL;
static range_op_fn prefetch_range = NULL;
static range_op_fn prepare_write_range = NULL;
static range_op_fn reclaim_range = NULL;
static hint_range_fn hint_range = NULL;
static size_t heartbeat_calls = 0;
static size_t heartbeat_busy_ticks = 0;
static size_t heartbeat_migrate_bytes = 0;
static size_t heartbeat_reclaimed_bytes = 0;
static size_t trace_setup_calls = 0;
static size_t trace_stop_calls = 0;
static size_t trace_faulted_pages = 0;
static size_t latency_ops = 0;
static size_t logical_bytes = 0;
static double measured_access_seconds = 0.0;
static const char* mprotect_mechanism_label = "none";
static size_t mprotect_chunk_bytes = 0;
static size_t mprotect_sample_pages = 0;
static uint64_t mprotect_setup_ns = 0;
static uint64_t mprotect_warmup_ns = 0;
static uint64_t mprotect_first_touch_total_ns = 0;
static uint64_t mprotect_first_touch_min_ns = 0;
static uint64_t mprotect_first_touch_p50_ns = 0;
static uint64_t mprotect_first_touch_p90_ns = 0;
static uint64_t mprotect_first_touch_p99_ns = 0;
static uint64_t mprotect_first_touch_max_ns = 0;
static uint64_t mprotect_finish_ns = 0;
static uint64_t mprotect_sweep_ns = 0;
static long mprotect_minor_faults_delta = 0;
static long mprotect_major_faults_delta = 0;
static long mprotect_voluntary_ctxt_delta = 0;
static long mprotect_involuntary_ctxt_delta = 0;
static long mprotect_user_cpu_us_delta = 0;
static long mprotect_sys_cpu_us_delta = 0;
static long run_minor_faults_delta = 0;
static long run_major_faults_delta = 0;
static long run_inblock_delta = 0;
static long run_oublock_delta = 0;
static long run_voluntary_ctxt_delta = 0;
static long run_involuntary_ctxt_delta = 0;
static long run_user_cpu_us_delta = 0;
static long run_sys_cpu_us_delta = 0;
static long run_maxrss_kib = 0;
static size_t cgroup_memory_max_bytes = 0;
static int cgroup_memory_max_available = 0;
static int cgroup_memory_max_unbounded = 0;
static int cgroup_memory_max_is_max_token = 0;
static size_t cgroup_memory_current_before = 0;
static size_t cgroup_memory_current_after = 0;
static size_t cgroup_memory_events_high_delta = 0;
static size_t cgroup_memory_events_max_delta = 0;
static size_t cgroup_memory_events_oom_delta = 0;
static size_t cgroup_swap_max_bytes = 0;
static int cgroup_swap_max_available = 0;
static int cgroup_swap_max_unbounded = 0;
static int cgroup_swap_max_is_max_token = 0;
static size_t cgroup_swap_current_before = 0;
static size_t cgroup_swap_current_after = 0;
static uint64_t heartbeat_total_ns = 0;
static const char* chunk_touch_position_label = "none";
static double stream_copy_mib_per_sec = 0.0;
static double stream_scale_mib_per_sec = 0.0;
static double stream_add_mib_per_sec = 0.0;
static double stream_triad_mib_per_sec = 0.0;
static double stream_total_mib_per_sec = 0.0;
static double stream_first_pass_mib_per_sec = 0.0;
static double stream_median_pass_mib_per_sec = 0.0;
static double stream_last_pass_mib_per_sec = 0.0;
static double stream_min_pass_mib_per_sec = 0.0;
static double stream_max_pass_mib_per_sec = 0.0;
static uint64_t stream_copy_ns = 0;
static uint64_t stream_scale_ns = 0;
static uint64_t stream_add_ns = 0;
static uint64_t stream_triad_ns = 0;
static uint64_t stream_prefetch_ns = 0;
static uint64_t stream_prepare_write_ns = 0;
static uint64_t stream_reclaim_ns = 0;
static uint64_t stream_init_ns = 0;
static size_t stream_tile_bytes_recorded = 0;
static size_t stream_tiles_recorded = 0;
static size_t stream_resident_arrays_recorded = 0;
static size_t stream_pipeline_kernels_recorded = 0;
static size_t stream_pipeline_cycles_recorded = 0;
static size_t stream_pipeline_group_visits_recorded = 0;
static size_t stream_pipeline_groups_recorded = 0;
static size_t stream_pipeline_group_iterations_recorded = 0;
static size_t stream_pipeline_matrix_bytes_recorded = 0;
static size_t stream_pipeline_group_bytes_recorded = 0;
static size_t stream_pipeline_total_matrix_bytes_recorded = 0;
static double stream_pipeline_scalar_recorded = 0.0;
static size_t stream_pipeline_seed_recorded = 0;
static const char* stream_pipeline_order_recorded = "sequential";
static const char* stream_pipeline_prediction_recorded = "entry";
static size_t stream_pipeline_reclaim_lag_recorded = 0;
static size_t stream_pipeline_reclaim_horizon_recorded = 0;
static size_t stream_pipeline_unique_cold_visits_recorded = 0;
static size_t stream_pipeline_max_cycle_policy_demand_faults = 0;
static size_t stream_pipeline_max_cycle_policy_read_bytes = 0;
static size_t stream_pipeline_max_cycle_policy_write_bytes = 0;
static size_t stream_pipeline_max_cycle_policy_stall_ns = 0;
static size_t stream_pipeline_max_cycle_policy_demotions = 0;
static size_t stream_pipeline_max_cycle_policy_hot_evicted_bytes = 0;
static size_t stream_pipeline_cycle_policy_demand_faults_p50 = 0;
static size_t stream_pipeline_cycle_policy_demand_faults_p90 = 0;
static size_t stream_pipeline_cycle_policy_demand_faults_p99 = 0;
static size_t stream_pipeline_cycle_policy_read_bytes_p50 = 0;
static size_t stream_pipeline_cycle_policy_read_bytes_p90 = 0;
static size_t stream_pipeline_cycle_policy_read_bytes_p99 = 0;
static size_t stream_pipeline_cycle_policy_write_bytes_p50 = 0;
static size_t stream_pipeline_cycle_policy_write_bytes_p90 = 0;
static size_t stream_pipeline_cycle_policy_write_bytes_p99 = 0;
static size_t stream_pipeline_cycle_policy_stall_ns_p50 = 0;
static size_t stream_pipeline_cycle_policy_stall_ns_p90 = 0;
static size_t stream_pipeline_cycle_policy_stall_ns_p99 = 0;
static size_t stream_pipeline_cycle_policy_unused_prefetch_evictions_p50 = 0;
static size_t stream_pipeline_cycle_policy_unused_prefetch_evictions_p90 = 0;
static size_t stream_pipeline_cycle_policy_unused_prefetch_evictions_p99 = 0;
static size_t stream_pipeline_group_visit_0_recorded = 0;
static size_t stream_pipeline_group_visit_1_recorded = 0;
static size_t stream_pipeline_group_visit_2_recorded = 0;
static size_t stream_pipeline_transition_00_recorded = 0;
static size_t stream_pipeline_transition_01_recorded = 0;
static size_t stream_pipeline_transition_02_recorded = 0;
static size_t stream_pipeline_transition_10_recorded = 0;
static size_t stream_pipeline_transition_11_recorded = 0;
static size_t stream_pipeline_transition_12_recorded = 0;
static size_t stream_pipeline_transition_20_recorded = 0;
static size_t stream_pipeline_transition_21_recorded = 0;
static size_t stream_pipeline_transition_22_recorded = 0;
static size_t stream_pipeline_unique_transitions_recorded = 0;
static size_t stream_pipeline_worst_cycle_index_recorded = 0;
static size_t stream_pipeline_worst_cycle_group_recorded = 0;
static size_t stream_pipeline_worst_cycle_prev_group_recorded = 0;
static char stream_pipeline_order_sequence_recorded[128] = "none";
static size_t stream_pipeline_phase_chunks_recorded = 0;
static size_t stream_pipeline_phase_return_cycles_recorded = 0;
static size_t stream_pipeline_phase_return_policy_demand_faults = 0;
static size_t stream_pipeline_phase_return_policy_read_bytes = 0;
static size_t stream_pipeline_phase_return_policy_write_bytes = 0;
static size_t stream_pipeline_phase_return_policy_stall_ns = 0;
static size_t stream_pipeline_phase_return_policy_hot_evicted_bytes = 0;
static size_t stream_pipeline_phase_return_policy_unused_prefetch_evictions = 0;
static size_t stream_pipeline_phase_return_estimated_hits = 0;
static double stream_pipeline_phase_return_estimated_hit_ratio = 0.0;
static size_t stream_pipeline_phase_warm_return_cycles_recorded = 0;
static size_t stream_pipeline_phase_warm_return_policy_demand_faults = 0;
static size_t stream_pipeline_phase_warm_return_policy_read_bytes = 0;
static size_t stream_pipeline_phase_warm_return_policy_write_bytes = 0;
static size_t stream_pipeline_phase_warm_return_policy_stall_ns = 0;
static size_t stream_pipeline_phase_warm_return_policy_hot_evicted_bytes = 0;
static size_t stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions = 0;
static size_t stream_pipeline_phase_warm_return_estimated_hits = 0;
static double stream_pipeline_phase_warm_return_estimated_hit_ratio = 0.0;
static size_t stream_pipeline_phase_decoy_cycles_recorded = 0;
static size_t stream_pipeline_phase_decoy_policy_demand_faults = 0;
static size_t stream_pipeline_phase_decoy_policy_read_bytes = 0;
static size_t stream_pipeline_phase_decoy_policy_write_bytes = 0;
static size_t stream_pipeline_phase_decoy_policy_stall_ns = 0;
static size_t stream_pipeline_phase_decoy_policy_hot_evicted_bytes = 0;
static size_t stream_pipeline_phase_decoy_policy_unused_prefetch_evictions = 0;
static size_t policy_pivot_return_faults_recorded = 0;
static size_t policy_pivot_return_touches_recorded = 0;
static size_t policy_pivot_return_hits_recorded = 0;
static double policy_pivot_hot_return_hit_ratio_recorded = 0.0;
static size_t policy_pivot_adaptation_lag_touches_recorded = 0;
static size_t policy_irr_hot_return_faults_recorded = 0;
static size_t policy_irr_hot_return_touches_recorded = 0;
static size_t policy_irr_hot_return_hits_recorded = 0;
static double policy_irr_hot_return_hit_ratio_recorded = 0.0;
static size_t policy_irr_decoy_return_faults_recorded = 0;
static size_t policy_irr_decoy_return_touches_recorded = 0;
static size_t policy_irr_decoy_return_hits_recorded = 0;
static double policy_irr_decoy_return_hit_ratio_recorded = 0.0;
static double policy_irr_discrimination_score_recorded = 0.0;
static size_t policy_irr_adaptation_lag_touches_recorded = 0;
static size_t policy_irr_scan_faults_recorded = 0;
static size_t policy_irr_scan_read_bytes_recorded = 0;
static size_t policy_irr_scan_write_bytes_recorded = 0;
static size_t policy_irr_scan_hot_evicted_bytes_recorded = 0;
static size_t policy_irr_scan_unused_prefetch_evictions_recorded = 0;
static size_t policy_irr_scan_stall_ns_recorded = 0;
static const char* stream_mapping_kind_recorded = "malloc";
static char stream_backing_path_recorded[PATH_MAX] = "none";
static unsigned long long stream_backing_fs_type = 0;
static int stream_backing_is_tmpfs = 0;
static size_t stream_passes_recorded = 0;

typedef enum {
    MPROTECT_MECHANISM_NONE = 0,
    MPROTECT_MECHANISM_TRACE,
    MPROTECT_MECHANISM_HEARTBEAT,
    MPROTECT_MECHANISM_RAW
} MprotectMechanism;

typedef struct {
    uintptr_t page;
    volatile sig_atomic_t armed;
} RawMprotectPage;

static RawMprotectPage raw_mprotect_pages[64];
static volatile sig_atomic_t raw_mprotect_page_count = 0;
static volatile sig_atomic_t raw_mprotect_faults = 0;
static struct sigaction previous_raw_sigsegv_action;
static int raw_sigsegv_installed = 0;

static int fail(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static uint64_t timespec_delta_ns(const struct timespec* start,
                                  const struct timespec* end) {
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    }
    return (uint64_t)sec * 1000000000ULL + (uint64_t)nsec;
}

static long timeval_delta_us(const struct timeval* start,
                             const struct timeval* end) {
    long sec = (long)(end->tv_sec - start->tv_sec);
    long usec = (long)(end->tv_usec - start->tv_usec);
    if (usec < 0) {
        sec -= 1;
        usec += 1000000L;
    }
    return sec * 1000000L + usec;
}

static int compare_u64(const void* left, const void* right) {
    uint64_t a = *(const uint64_t*)left;
    uint64_t b = *(const uint64_t*)right;
    return (a > b) - (a < b);
}

static uint64_t percentile_u64(uint64_t* values, size_t count,
                               size_t percentile) {
    if (!values || count == 0) {
        return 0;
    }
    qsort(values, count, sizeof(*values), compare_u64);
    size_t index = ((count - 1) * percentile + 50) / 100;
    if (index >= count) {
        index = count - 1;
    }
    return values[index];
}

static int compare_double(const void* left, const void* right) {
    double a = *(const double*)left;
    double b = *(const double*)right;
    return (a > b) - (a < b);
}

static size_t size_delta(size_t after, size_t before) {
    return after >= before ? after - before : 0;
}

static double seconds_since(const struct timespec* start, const struct timespec* end) {
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    }
    return (double)sec + (double)nsec / 1000000000.0;
}

static void benchmark_compiler_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#else
    atomic_signal_fence(memory_order_seq_cst);
#endif
}

static int mul_size(size_t a, size_t b, size_t* out) {
    if (a != 0 && b > SIZE_MAX / a) {
        return -1;
    }
    *out = a * b;
    return 0;
}

static size_t gcd_size(size_t a, size_t b) {
    while (b != 0) {
        size_t rem = a % b;
        a = b;
        b = rem;
    }
    return a;
}

static size_t coprime_stride(size_t units, size_t salt) {
    if (units <= 1) {
        return 1;
    }

    size_t stride = salt % units;
    if (stride == 0) {
        stride = 1;
    }
    if ((stride & 1U) == 0) {
        stride++;
    }
    if (stride >= units) {
        stride = 1;
    }

    while (gcd_size(stride, units) != 1) {
        stride += 2;
        if (stride >= units) {
            stride = 1;
        }
    }
    return stride;
}

static void shuffle_size_order(size_t* order, size_t count, uint64_t seed) {
    for (size_t i = 0; i < count; i++) {
        order[i] = i;
    }
    uint64_t state = seed == 0 ? 0x9e3779b97f4a7c15ULL : seed;
    for (size_t i = count; i > 1; i--) {
        state = state * 2862933555777941757ULL + 3037000493ULL;
        size_t j = (size_t)(state % i);
        size_t tmp = order[i - 1];
        order[i - 1] = order[j];
        order[j] = tmp;
    }
}

static int parse_size_value(const char* value, size_t* out) {
    char* end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || parsed > (unsigned long long)SIZE_MAX) {
        return -1;
    }

    while (*end && isspace((unsigned char)*end)) {
        end++;
    }

    size_t multiplier = 1;
    if (*end) {
        char suffix = (char)toupper((unsigned char)*end++);
        if (suffix == 'K') {
            multiplier = 1024ULL;
        } else if (suffix == 'M') {
            multiplier = 1024ULL * 1024ULL;
        } else if (suffix == 'G') {
            multiplier = 1024ULL * 1024ULL * 1024ULL;
        } else if (suffix == 'T') {
            multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        } else {
            return -1;
        }
    }

    while (*end && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0') {
        return -1;
    }

    return mul_size((size_t)parsed, multiplier, out);
}

static int parse_count_value(const char* value, size_t* out) {
    char* end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed > (unsigned long long)SIZE_MAX) {
        return -1;
    }
    *out = (size_t)parsed;
    return 0;
}

static size_t env_size(const char* name, size_t fallback) {
    const char* value = getenv(name);
    size_t parsed = 0;
    if (!value || value[0] == '\0' || parse_size_value(value, &parsed) != 0) {
        return fallback;
    }
    return parsed;
}

static size_t env_count(const char* name, size_t fallback) {
    const char* value = getenv(name);
    size_t parsed = 0;
    if (!value || value[0] == '\0' || parse_count_value(value, &parsed) != 0) {
        return fallback;
    }
    return parsed;
}

static int env_flag(const char* name, int fallback) {
    const char* value = getenv(name);
    if (!value || value[0] == '\0') {
        return fallback;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "off") == 0 || strcmp(value, "no") == 0) {
        return 0;
    }
    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
        strcmp(value, "on") == 0 || strcmp(value, "yes") == 0) {
        return 1;
    }
    return fallback;
}

static int pure_workload_mode(void) {
    return env_flag("MAI_BENCH_PURE_WORKLOAD",
                    env_flag("MAI_BENCH_DISABLE_MAI_STATS_API", 0));
}

static const char* env_value_compat(const char* primary, const char* legacy) {
    const char* value = getenv(primary);
    if (value && value[0] != '\0') {
        return value;
    }
    return legacy ? getenv(legacy) : NULL;
}

static size_t env_size_compat(const char* primary, const char* legacy,
                              size_t fallback) {
    const char* value = env_value_compat(primary, legacy);
    size_t parsed = 0;
    if (!value || value[0] == '\0' || parse_size_value(value, &parsed) != 0) {
        return fallback;
    }
    return parsed;
}

static size_t env_count_compat(const char* primary, const char* legacy,
                               size_t fallback) {
    const char* value = env_value_compat(primary, legacy);
    size_t parsed = 0;
    if (!value || value[0] == '\0' || parse_count_value(value, &parsed) != 0) {
        return fallback;
    }
    return parsed;
}

static double env_double_compat(const char* primary, const char* legacy,
                                double fallback) {
    const char* value = env_value_compat(primary, legacy);
    char* end = NULL;
    if (!value || value[0] == '\0') {
        return fallback;
    }
    errno = 0;
    double parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0' || parsed < 0.0) {
        return fallback;
    }
    return parsed;
}

static double env_double(const char* name, double fallback) {
    const char* value = getenv(name);
    char* end = NULL;
    if (!value || value[0] == '\0') {
        return fallback;
    }
    errno = 0;
    double parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0' || parsed < 0.0) {
        return fallback;
    }
    return parsed;
}

static int read_text_file(const char* path, char* buffer, size_t buffer_size) {
    if (!path || !buffer || buffer_size == 0) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t bytes = read(fd, buffer, buffer_size - 1);
    close(fd);
    if (bytes <= 0) {
        return -1;
    }
    buffer[bytes] = '\0';
    return 0;
}

typedef struct {
    size_t bytes;
    int available;
    int max_token;
} CgroupSizeSample;

static int cgroup_token_is_max(const char* cursor) {
    return cursor && strncmp(cursor, "max", 3) == 0 &&
           (cursor[3] == '\0' || isspace((unsigned char)cursor[3]));
}

static int parse_cgroup_size_text(const char* text, CgroupSizeSample* out) {
    if (!text || !out) {
        return -1;
    }
    char* end = NULL;
    while (*text && isspace((unsigned char)*text)) {
        text++;
    }
    if (cgroup_token_is_max(text)) {
        out->bytes = 0;
        out->available = 1;
        out->max_token = 1;
        return 0;
    }
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || parsed > (unsigned long long)SIZE_MAX) {
        return -1;
    }
    out->bytes = (size_t)parsed;
    out->available = 1;
    out->max_token = 0;
    return 0;
}

static int read_size_file_token(const char* path, CgroupSizeSample* out) {
    char buffer[128];
    if (!out || read_text_file(path, buffer, sizeof(buffer)) != 0) {
        return -1;
    }
    return parse_cgroup_size_text(buffer, out);
}

static int cgroup_controller_list_has_memory(const char* controllers) {
    const char* cursor = controllers;
    while (cursor && *cursor) {
        const char* comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (length == strlen("memory") &&
            strncmp(cursor, "memory", length) == 0) {
            return 1;
        }
        if (!comma) {
            break;
        }
        cursor = comma + 1;
    }
    return 0;
}

static int build_cgroup_metric_path(char* buffer, size_t buffer_size,
                                    const char* mount_root,
                                    const char* relative_path,
                                    const char* file_name) {
    if (!buffer || buffer_size == 0 || !mount_root ||
        !relative_path || !file_name) {
        return -1;
    }
    while (*relative_path == '/') {
        relative_path++;
    }
    if (strstr(relative_path, "..")) {
        return -1;
    }
    int written = *relative_path ?
        snprintf(buffer, buffer_size, "%s/%s/%s", mount_root,
                 relative_path, file_name) :
        snprintf(buffer, buffer_size, "%s/%s", mount_root, file_name);
    return written >= 0 && (size_t)written < buffer_size ? 0 : -1;
}

static int read_process_cgroup_text(const char* v2_file,
                                    const char* v1_file,
                                    char* out,
                                    size_t out_size) {
    char buffer[4096];
    if (!v2_file || !v1_file || !out || out_size == 0 ||
        read_text_file("/proc/self/cgroup", buffer, sizeof(buffer)) != 0) {
        return -1;
    }

    for (char* line = buffer; line && *line;) {
        char* next = strchr(line, '\n');
        if (next) {
            *next = '\0';
            next++;
        }
        char* first_colon = strchr(line, ':');
        char* second_colon = first_colon ? strchr(first_colon + 1, ':') : NULL;
        if (!first_colon || !second_colon) {
            line = next;
            continue;
        }
        *first_colon = '\0';
        *second_colon = '\0';
        const char* hierarchy = line;
        const char* controllers = first_colon + 1;
        const char* relative_path = second_colon + 1;
        char path[PATH_MAX];

        if (strcmp(hierarchy, "0") == 0 && controllers[0] == '\0') {
            if (build_cgroup_metric_path(path, sizeof(path), "/sys/fs/cgroup",
                                         relative_path, v2_file) == 0 &&
                read_text_file(path, out, out_size) == 0) {
                return 0;
            }
        } else if (cgroup_controller_list_has_memory(controllers)) {
            if (build_cgroup_metric_path(path, sizeof(path),
                                         "/sys/fs/cgroup/memory",
                                         relative_path, v1_file) == 0 &&
                read_text_file(path, out, out_size) == 0) {
                return 0;
            }
        }
        line = next;
    }
    return -1;
}

static int read_process_cgroup_size(const char* v2_file,
                                    const char* v1_file,
                                    CgroupSizeSample* out) {
    char buffer[128];
    if (!out ||
        read_process_cgroup_text(v2_file, v1_file, buffer,
                                 sizeof(buffer)) != 0) {
        return -1;
    }
    return parse_cgroup_size_text(buffer, out);
}

static CgroupSizeSample sample_cgroup_size(const char* v2_file,
                                           const char* v1_file,
                                           const char* fallback_v2,
                                           const char* fallback_v1) {
    CgroupSizeSample sample = {0};
    if (read_process_cgroup_size(v2_file, v1_file, &sample) == 0 ||
        read_size_file_token(fallback_v2, &sample) == 0 ||
        read_size_file_token(fallback_v1, &sample) == 0) {
        return sample;
    }
    return sample;
}

typedef struct {
    size_t high;
    size_t max;
    size_t oom;
} CgroupMemoryEvents;

static void parse_cgroup_memory_events(const char* text,
                                       CgroupMemoryEvents* out) {
    if (!text || !out) {
        return;
    }
    for (const char* line = text; *line;) {
        while (*line == '\n') {
            line++;
        }
        const char* end_line = strchr(line, '\n');
        size_t length = end_line ? (size_t)(end_line - line) : strlen(line);
        if (length == 0) {
            break;
        }
        char key[32];
        unsigned long long value = 0;
        if (sscanf(line, "%31s %llu", key, &value) == 2 &&
            value <= (unsigned long long)SIZE_MAX) {
            if (strcmp(key, "high") == 0) {
                out->high = (size_t)value;
            } else if (strcmp(key, "max") == 0) {
                out->max = (size_t)value;
            } else if (strcmp(key, "oom") == 0) {
                out->oom = (size_t)value;
            }
        } else if (sscanf(line, "%llu", &value) == 1 &&
                   value <= (unsigned long long)SIZE_MAX) {
            out->max = (size_t)value;
        }
        if (!end_line) {
            break;
        }
        line = end_line + 1;
    }
}

static CgroupMemoryEvents sample_cgroup_memory_events(void) {
    CgroupMemoryEvents events = {0};
    char buffer[512];
    if (read_process_cgroup_text("memory.events", "memory.failcnt",
                                 buffer, sizeof(buffer)) == 0 ||
        read_text_file("/sys/fs/cgroup/memory.events", buffer,
                       sizeof(buffer)) == 0) {
        parse_cgroup_memory_events(buffer, &events);
    }
    return events;
}

static size_t delta_size_t(size_t before, size_t after) {
    return after >= before ? after - before : 0;
}

static int cgroup_limit_is_unbounded(CgroupSizeSample sample) {
    if (!sample.available) {
        return 0;
    }
    if (sample.max_token) {
        return 1;
    }
#if SIZE_MAX > 0xffffffffu
    if (sample.bytes >= ((size_t)1 << 60)) {
        return 1;
    }
#endif
    return 0;
}

static int mode_uses_stream_kernel(const char* mode) {
    return strcmp(mode, "stream_bandwidth") == 0 ||
           strcmp(mode, "stream_tiled_bandwidth") == 0 ||
           strcmp(mode, "stream_anon_mmap") == 0 ||
           strcmp(mode, "stream_shared_file") == 0 ||
           strcmp(mode, "stream_private_file") == 0;
}

static int mode_uses_stream_pipeline(const char* mode) {
    return strcmp(mode, "policy_stream_pipeline") == 0 ||
           strcmp(mode, "policy_stream_pipeline_phase_decoy") == 0 ||
           strcmp(mode, "stream_kernel_pipeline") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_anon_mmap") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_shared_file") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_private_file") == 0;
}

static int mode_allocates_internally(const char* mode) {
    return strcmp(mode, "multi_alloc_matrix_pipeline") == 0;
}

static int build_stream_file_template(char* buffer, size_t buffer_size) {
    const char* dir = env_value_compat("MAI_BENCH_STREAM_BACKING_PATH",
                                       "MAI_STREAM_BACKING_PATH");
    if (!dir || dir[0] == '\0') {
        dir = getenv("TMPDIR");
    }
    if (!dir || dir[0] == '\0') {
        dir = "/tmp";
    }

    size_t len = strlen(dir);
    const char* slash = len > 0 && dir[len - 1] == '/' ? "" : "/";
    int written = snprintf(buffer, buffer_size, "%s%smai-stream-XXXXXX",
                           dir, slash);
    return written >= 0 && (size_t)written < buffer_size ? 0 : -1;
}

static int allocate_file_mapping(size_t size, int shared, unsigned char** out) {
    char filename[PATH_MAX];
    if (build_stream_file_template(filename, sizeof(filename)) != 0) {
        return -1;
    }

    int fd = mkstemp(filename);
    if (fd < 0) {
        return -1;
    }
    stream_mapping_kind_recorded = shared ? "shared_file" : "private_file";
    snprintf(stream_backing_path_recorded, sizeof(stream_backing_path_recorded),
             "%s", filename);
    struct statfs fs_info;
    if (fstatfs(fd, &fs_info) == 0) {
        stream_backing_fs_type = (unsigned long long)fs_info.f_type;
        stream_backing_is_tmpfs = fs_info.f_type == TMPFS_MAGIC ? 1 : 0;
    } else {
        stream_backing_fs_type = 0;
        stream_backing_is_tmpfs = 0;
    }
    int saved_errno = 0;
    if (unlink(filename) != 0 || ftruncate(fd, (off_t)size) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    int flags = shared ? MAP_SHARED : MAP_PRIVATE;
    void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);
    saved_errno = errno;
    close(fd);
    if (ptr == MAP_FAILED) {
        errno = saved_errno;
        return -1;
    }

    *out = (unsigned char*)ptr;
    return 0;
}

static int allocate_benchmark_buffer(const char* mode, size_t size,
                                     unsigned char** buffer,
                                     int* free_with_munmap) {
    *buffer = NULL;
    *free_with_munmap = 0;

    if (strcmp(mode, "mprotect_overhead") == 0) {
        if (posix_memalign((void**)buffer, page_size_bytes, size) != 0) {
            *buffer = NULL;
            return -1;
        }
        return 0;
    }

    if (strcmp(mode, "stream_anon_mmap") == 0 ||
        strcmp(mode, "stream_kernel_pipeline_anon_mmap") == 0) {
        stream_mapping_kind_recorded = "anon_mmap";
        snprintf(stream_backing_path_recorded, sizeof(stream_backing_path_recorded),
                 "%s", "none");
        stream_backing_fs_type = 0;
        stream_backing_is_tmpfs = 0;
        void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            return -1;
        }
        *buffer = (unsigned char*)ptr;
        *free_with_munmap = 1;
        return 0;
    }

    if (strcmp(mode, "stream_shared_file") == 0 ||
        strcmp(mode, "stream_private_file") == 0 ||
        strcmp(mode, "stream_kernel_pipeline_shared_file") == 0 ||
        strcmp(mode, "stream_kernel_pipeline_private_file") == 0) {
        int shared = strcmp(mode, "stream_shared_file") == 0 ||
            strcmp(mode, "stream_kernel_pipeline_shared_file") == 0;
        if (allocate_file_mapping(size, shared, buffer) != 0) {
            return -1;
        }
        *free_with_munmap = 1;
        return 0;
    }

    stream_mapping_kind_recorded = "malloc";
    snprintf(stream_backing_path_recorded, sizeof(stream_backing_path_recorded),
             "%s", "none");
    stream_backing_fs_type = 0;
    stream_backing_is_tmpfs = 0;
    *buffer = malloc(size);
    return *buffer ? 0 : -1;
}

static void free_benchmark_buffer(unsigned char* buffer, size_t size,
                                  int free_with_munmap) {
    if (!buffer) {
        return;
    }
    if (free_with_munmap) {
        munmap(buffer, size);
    } else {
        free(buffer);
    }
}

static int load_stats_optional(MaiStats* stats, int* available) {
    memset(stats, 0, sizeof(*stats));
    *available = 0;

    if (pure_workload_mode()) {
        return 0;
    }

    if (!get_stats_sized) {
        get_stats_sized =
            (get_stats_sized_fn)dlsym(RTLD_DEFAULT, "mai_get_stats_sized");
    }
    if (get_stats_sized) {
        *available = 1;
        return get_stats_sized(stats, sizeof(*stats));
    }

    if (!get_stats) {
        get_stats = (get_stats_fn)dlsym(RTLD_DEFAULT, "mai_get_stats");
    }
    if (!get_stats) {
        return 0;
    }

    *available = 1;
    return get_stats(stats);
}

static int reclaim_now(void) {
    if (pure_workload_mode()) {
        return 0;
    }

    if (!reclaim_all) {
        reclaim_all = (reclaim_all_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_all");
    }
    if (!reclaim_all) {
        return -1;
    }
    return reclaim_all();
}

static void load_range_ops_optional(void) {
    if (pure_workload_mode()) {
        prefetch_range = NULL;
        prepare_write_range = NULL;
        reclaim_range = NULL;
        hint_range = NULL;
        return;
    }

    if (!prefetch_range) {
        prefetch_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_prefetch");
    }
    if (!prepare_write_range) {
        prepare_write_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_prepare_write");
    }
    if (!reclaim_range) {
        reclaim_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_range");
    }
    if (!hint_range) {
        hint_range = (hint_range_fn)dlsym(RTLD_DEFAULT, "mai_hint_range");
    }
}

static int timed_range_op(range_op_fn op, void* ptr, size_t len,
                          uint64_t* elapsed_ns) {
    if (!op || len == 0) {
        return 0;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = op(ptr, len);
    clock_gettime(CLOCK_MONOTONIC, &end);
    *elapsed_ns += timespec_delta_ns(&start, &end);
    return rc;
}

static int stream_active_bytes_for_residency(size_t array_bytes, size_t tile_bytes,
                                             size_t resident_arrays,
                                             size_t* out) {
    size_t resident_bytes = 0;
    size_t tiled_bytes = 0;
    if (resident_arrays > 3) {
        return -1;
    }
    if (mul_size(array_bytes, resident_arrays, &resident_bytes) != 0 ||
        mul_size(tile_bytes, 3 - resident_arrays, &tiled_bytes) != 0 ||
        resident_bytes > SIZE_MAX - tiled_bytes) {
        return -1;
    }
    *out = resident_bytes + tiled_bytes;
    return 0;
}

static size_t choose_stream_resident_arrays(size_t array_bytes, size_t tile_bytes) {
    const char* value = env_value_compat("MAI_BENCH_STREAM_RESIDENT_ARRAYS",
                                         "MAI_STREAM_RESIDENT_ARRAYS");
    if (value && value[0] != '\0' && strcmp(value, "auto") != 0) {
        size_t parsed = 0;
        if (parse_count_value(value, &parsed) == 0) {
            return parsed > 3 ? 3 : parsed;
        }
    }

    MaiStats stats;
    int stats_available = 0;
    if (load_stats_optional(&stats, &stats_available) != 0 ||
        !stats_available || stats.max_rss == 0) {
        return 3;
    }

    size_t safe_cap = (stats.max_rss / 100) * 85 +
        ((stats.max_rss % 100) * 85) / 100;
    for (size_t resident = 3; resident > 0; resident--) {
        size_t active_bytes = 0;
        if (stream_active_bytes_for_residency(array_bytes, tile_bytes, resident,
                                              &active_bytes) == 0 &&
            active_bytes <= safe_cap) {
            return resident;
        }
    }
    return 0;
}

static int load_trace_symbols(void) {
    if (!trace_access) {
        trace_access = (trace_access_fn)dlsym(RTLD_DEFAULT, "mai_trace_access");
    }
    if (!get_access_trace) {
        get_access_trace =
            (get_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_get_access_trace");
    }
    if (!stop_access_trace) {
        stop_access_trace =
            (stop_access_trace_fn)dlsym(RTLD_DEFAULT, "mai_stop_access_trace");
    }

    return trace_access && get_access_trace && stop_access_trace ? 0 : -1;
}

static int load_heartbeat_symbol(void) {
    if (!heartbeat) {
        heartbeat = (heartbeat_fn)dlsym(RTLD_DEFAULT, "mai_heartbeat");
    }

    return heartbeat ? 0 : -1;
}

static int heartbeat_with_snapshot(const MaiHeartbeatOptions* opts,
                                   MaiHeartbeatSnapshot* snapshot) {
    if (heartbeat(opts, snapshot) != 0) {
        return -1;
    }

    heartbeat_calls++;
    heartbeat_busy_ticks += snapshot->busy ? 1 : 0;
    heartbeat_reclaimed_bytes += snapshot->reclaimed_bytes;
    return 0;
}

static int heartbeat_now(const MaiHeartbeatOptions* opts) {
    MaiHeartbeatSnapshot snapshot;
    return heartbeat_with_snapshot(opts, &snapshot);
}

static int align_size_to_page(size_t* value) {
    size_t rem = *value % page_size_bytes;
    if (rem == 0) {
        return 0;
    }
    if (*value > SIZE_MAX - (page_size_bytes - rem)) {
        return -1;
    }
    *value += page_size_bytes - rem;
    return 0;
}

static unsigned char expected_byte(size_t page_index, size_t pass) {
    return (unsigned char)((page_index * 1315423911ULL + pass * 2654435761ULL) & 0xff);
}

static void dispatch_previous_raw_sigsegv(int signo, siginfo_t* info,
                                          void* context) {
    if ((previous_raw_sigsegv_action.sa_flags & SA_SIGINFO) &&
        previous_raw_sigsegv_action.sa_sigaction) {
        previous_raw_sigsegv_action.sa_sigaction(signo, info, context);
        return;
    }

    if (previous_raw_sigsegv_action.sa_handler == SIG_IGN) {
        return;
    }
    if (previous_raw_sigsegv_action.sa_handler &&
        previous_raw_sigsegv_action.sa_handler != SIG_DFL) {
        previous_raw_sigsegv_action.sa_handler(signo);
        return;
    }

    (void)sigaction(SIGSEGV, &previous_raw_sigsegv_action, NULL);
    (void)raise(SIGSEGV);
}

static void raw_mprotect_sigsegv_handler(int signo, siginfo_t* info,
                                         void* context) {
    uintptr_t fault = (uintptr_t)info->si_addr;
    uintptr_t page = fault & ~((uintptr_t)page_size_bytes - 1);
    sig_atomic_t page_count = raw_mprotect_page_count;

    for (sig_atomic_t i = 0; i < page_count; i++) {
        if (!raw_mprotect_pages[i].armed ||
            raw_mprotect_pages[i].page != page) {
            continue;
        }

        if (syscall(SYS_mprotect, (void*)page, page_size_bytes,
                    PROT_READ | PROT_WRITE) == 0) {
            raw_mprotect_pages[i].armed = 0;
            raw_mprotect_faults++;
            return;
        }
        break;
    }

    dispatch_previous_raw_sigsegv(signo, info, context);
}

static int install_raw_sigsegv_handler(void) {
    if (raw_sigsegv_installed) {
        return 0;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = raw_mprotect_sigsegv_handler;
    action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &action, &previous_raw_sigsegv_action) != 0) {
        return -1;
    }

    raw_sigsegv_installed = 1;
    return 0;
}

static void restore_raw_sigsegv_handler(void) {
    if (!raw_sigsegv_installed) {
        return;
    }

    struct sigaction current;
    memset(&current, 0, sizeof(current));
    if (sigaction(SIGSEGV, NULL, &current) == 0 &&
        (current.sa_flags & SA_SIGINFO) &&
        current.sa_sigaction == raw_mprotect_sigsegv_handler) {
        (void)sigaction(SIGSEGV, &previous_raw_sigsegv_action, NULL);
    }
    memset(&previous_raw_sigsegv_action, 0, sizeof(previous_raw_sigsegv_action));
    raw_sigsegv_installed = 0;
}

static int mprotect_mechanism_from_env(MprotectMechanism* mechanism) {
    const char* value = getenv("MAI_MPROTECT_MECHANISM");
    if (!value || value[0] == '\0' || strcmp(value, "trace") == 0) {
        *mechanism = MPROTECT_MECHANISM_TRACE;
        return 0;
    }
    if (strcmp(value, "none") == 0) {
        *mechanism = MPROTECT_MECHANISM_NONE;
        return 0;
    }
    if (strcmp(value, "heartbeat") == 0) {
        *mechanism = MPROTECT_MECHANISM_HEARTBEAT;
        return 0;
    }
    if (strcmp(value, "raw") == 0) {
        *mechanism = MPROTECT_MECHANISM_RAW;
        return 0;
    }

    return -1;
}

static const char* mprotect_mechanism_name(MprotectMechanism mechanism) {
    switch (mechanism) {
    case MPROTECT_MECHANISM_NONE:
        return "none";
    case MPROTECT_MECHANISM_TRACE:
        return "trace";
    case MPROTECT_MECHANISM_HEARTBEAT:
        return "heartbeat";
    case MPROTECT_MECHANISM_RAW:
        return "raw";
    }

    return "unknown";
}

static size_t mprotect_sample_count(size_t size, size_t chunk, size_t max_pages) {
    size_t chunk_count = size / chunk + (size % chunk != 0);
    if (max_pages == 0 || max_pages > 64) {
        max_pages = 64;
    }
    return max_pages < chunk_count ? max_pages : chunk_count;
}

static int mprotect_common_options(size_t size, size_t* chunk_out,
                                   size_t* max_pages_out,
                                   size_t* passes_out,
                                   MprotectMechanism* mechanism_out) {
    size_t chunk = env_size("MAI_MPROTECT_CHUNK", 4ULL * 1024ULL * 1024ULL);
    size_t max_pages = env_count("MAI_MPROTECT_TRACE_PAGES", 64);
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    MprotectMechanism mechanism;

    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0 || chunk > size) {
        return -1;
    }
    if (max_pages == 0 || max_pages > 64) {
        max_pages = 64;
    }
    if (passes == 0) {
        passes = 1;
    }
    if (mprotect_mechanism_from_env(&mechanism) != 0) {
        return -1;
    }

    *chunk_out = chunk;
    *max_pages_out = max_pages;
    *passes_out = passes;
    *mechanism_out = mechanism;
    return 0;
}

static int start_observation(unsigned char* buffer, size_t size,
                             MprotectMechanism mechanism, size_t chunk,
                             size_t max_pages,
                             MaiHeartbeatOptions* heartbeat_opts) {
    size_t sample_count = mprotect_sample_count(size, chunk, max_pages);

    if (mechanism == MPROTECT_MECHANISM_NONE) {
        return 0;
    }
    if (mechanism == MPROTECT_MECHANISM_TRACE) {
        if (load_trace_symbols() != 0) {
            return -1;
        }
        MaiAccessTraceOptions opts;
        memset(&opts, 0, sizeof(opts));
        opts.size = sizeof(opts);
        opts.max_pages = max_pages;
        opts.chunk_bytes = chunk;
        if (trace_access(buffer, size, &opts) != 0) {
            return -1;
        }
        trace_setup_calls++;
        return 0;
    }
    if (mechanism == MPROTECT_MECHANISM_RAW) {
        if (install_raw_sigsegv_handler() != 0 || sample_count > 64) {
            return -1;
        }
        raw_mprotect_faults = 0;
        raw_mprotect_page_count = 0;
        for (size_t i = 0; i < sample_count; i++) {
            uintptr_t page = (uintptr_t)buffer + i * chunk;
            raw_mprotect_pages[i].page = page;
            raw_mprotect_pages[i].armed = 1;
            if (mprotect((void*)page, page_size_bytes, PROT_NONE) != 0) {
                for (size_t j = 0; j <= i; j++) {
                    (void)mprotect((void*)raw_mprotect_pages[j].page,
                                   page_size_bytes, PROT_READ | PROT_WRITE);
                    raw_mprotect_pages[j].armed = 0;
                }
                restore_raw_sigsegv_handler();
                return -1;
            }
            raw_mprotect_page_count = (sig_atomic_t)(i + 1);
        }
        trace_setup_calls++;
        return 0;
    }

    if (load_heartbeat_symbol() != 0) {
        return -1;
    }
    memset(heartbeat_opts, 0, sizeof(*heartbeat_opts));
    heartbeat_opts->size = sizeof(*heartbeat_opts);
    heartbeat_opts->observe_pages = max_pages;
    heartbeat_opts->chunk_bytes = chunk;
    heartbeat_opts->migrate_bytes = 0;
    return heartbeat_now(heartbeat_opts);
}

static int finish_observation(unsigned char* buffer, MprotectMechanism mechanism,
                              const MaiHeartbeatOptions* heartbeat_opts,
                              size_t expected_touched) {
    if (mechanism == MPROTECT_MECHANISM_NONE) {
        return 0;
    }
    if (mechanism == MPROTECT_MECHANISM_TRACE) {
        MaiAccessTraceSnapshot snapshot;
        if (get_access_trace(buffer, &snapshot) != 0) {
            (void)stop_access_trace(buffer);
            return -1;
        }
        if (snapshot.touched_pages != expected_touched) {
            (void)stop_access_trace(buffer);
            return -1;
        }
        trace_faulted_pages += snapshot.touched_pages;
        if (stop_access_trace(buffer) != 0) {
            return -1;
        }
        trace_stop_calls++;
        return 0;
    }
    if (mechanism == MPROTECT_MECHANISM_RAW) {
        for (sig_atomic_t i = 0; i < raw_mprotect_page_count; i++) {
            (void)mprotect((void*)raw_mprotect_pages[i].page, page_size_bytes,
                           PROT_READ | PROT_WRITE);
            raw_mprotect_pages[i].armed = 0;
        }
        if ((size_t)raw_mprotect_faults != expected_touched) {
            restore_raw_sigsegv_handler();
            return -1;
        }
        trace_faulted_pages += (size_t)raw_mprotect_faults;
        trace_stop_calls++;
        raw_mprotect_page_count = 0;
        restore_raw_sigsegv_handler();
        return 0;
    }

    MaiHeartbeatSnapshot snapshot;
    if (heartbeat_with_snapshot(heartbeat_opts, &snapshot) != 0) {
        return -1;
    }
    if (!snapshot.busy || snapshot.touched_pages != expected_touched ||
        snapshot.reclaimed_bytes != 0) {
        return -1;
    }
    trace_faulted_pages += snapshot.touched_pages;
    return 0;
}

static int visit_window(unsigned char* buffer, size_t start, size_t end,
                        size_t pass, size_t page_stride, int permute,
                        uint64_t* checksum, size_t* touches) {
    size_t pages = (end - start) / page_size_bytes;
    if (pages == 0) {
        return 0;
    }
    if (page_stride == 0) {
        page_stride = 1;
    }

    for (size_t i = 0; i < pages; i++) {
        size_t page = permute ? (i * page_stride) % pages : i;
        size_t offset = start + page * page_size_bytes;
        unsigned char value = expected_byte(offset / page_size_bytes, pass);
        buffer[offset] = value;
        *checksum += value;
        (*touches)++;
    }

    if (reclaim_now() != 0) {
        return -1;
    }

    for (size_t i = 0; i < pages; i++) {
        size_t page = permute ? (i * page_stride) % pages : i;
        size_t offset = start + page * page_size_bytes;
        unsigned char expected = expected_byte(offset / page_size_bytes, pass);
        if (buffer[offset] != expected) {
            return -1;
        }
        *checksum += buffer[offset];
        (*touches)++;
    }

    return reclaim_now();
}

static int visit_window_plain(unsigned char* buffer, size_t start, size_t end,
                              size_t pass, size_t page_stride, int permute,
                              uint64_t* checksum, size_t* touches) {
    size_t pages = (end - start) / page_size_bytes;
    if (pages == 0) {
        return 0;
    }
    if (page_stride == 0) {
        page_stride = 1;
    }

    for (size_t i = 0; i < pages; i++) {
        size_t page = permute ? (i * page_stride) % pages : i;
        size_t offset = start + page * page_size_bytes;
        unsigned char value = expected_byte(offset / page_size_bytes, pass);
        buffer[offset] = value;
        *checksum += value;
        (*touches)++;
    }

    for (size_t i = 0; i < pages; i++) {
        size_t page = permute ? (i * page_stride) % pages : i;
        size_t offset = start + page * page_size_bytes;
        unsigned char expected = expected_byte(offset / page_size_bytes, pass);
        if (buffer[offset] != expected) {
            return -1;
        }
        *checksum += buffer[offset];
        (*touches)++;
    }

    return 0;
}

static int run_windowed(unsigned char* buffer, size_t size, int permute,
                        uint64_t* checksum, size_t* touches) {
    size_t window = env_size("MAI_ACCESS_WINDOW", 4ULL * 1024ULL * 1024ULL);
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    size_t page_stride = env_count("MAI_ACCESS_STRIDE_PAGES", 17);

    if (window < page_size_bytes) {
        window = page_size_bytes;
    }
    window -= window % page_size_bytes;
    if (window == 0) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t start = 0; start < size; start += window) {
            size_t end = start + window;
            if (end > size || end < start) {
                end = size;
            }
            end -= (end - start) % page_size_bytes;
            if (end <= start) {
                continue;
            }
            if (visit_window(buffer, start, end, pass, page_stride, permute,
                             checksum, touches) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int run_windowed_plain(unsigned char* buffer, size_t size, int permute,
                              uint64_t* checksum, size_t* touches) {
    size_t window = env_size("MAI_ACCESS_WINDOW", 4ULL * 1024ULL * 1024ULL);
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    size_t page_stride = env_count("MAI_ACCESS_STRIDE_PAGES", 17);

    if (window < page_size_bytes) {
        window = page_size_bytes;
    }
    window -= window % page_size_bytes;
    if (window == 0) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t start = 0; start < size; start += window) {
            size_t end = start + window;
            if (end > size || end < start) {
                end = size;
            }
            end -= (end - start) % page_size_bytes;
            if (end <= start) {
                continue;
            }
            if (visit_window_plain(buffer, start, end, pass, page_stride, permute,
                                   checksum, touches) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int run_sparse(unsigned char* buffer, size_t size,
                      uint64_t* checksum, size_t* touches) {
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    size_t page_stride = env_count("MAI_ACCESS_STRIDE_PAGES", 16);
    size_t pages = size / page_size_bytes;
    if (page_stride == 0) {
        page_stride = 1;
    }
    if (passes == 0) {
        passes = 1;
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t page = 0; page < pages; page += page_stride) {
            size_t offset = page * page_size_bytes;
            unsigned char value = expected_byte(page, pass);
            buffer[offset] = value;
            *checksum += value;
            (*touches)++;
        }
        if (reclaim_now() != 0) {
            return -1;
        }
        for (size_t page = 0; page < pages; page += page_stride) {
            size_t offset = page * page_size_bytes;
            unsigned char expected = expected_byte(page, pass);
            if (buffer[offset] != expected) {
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    return reclaim_now();
}

static int run_sparse_plain(unsigned char* buffer, size_t size,
                            uint64_t* checksum, size_t* touches) {
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    size_t page_stride = env_count("MAI_ACCESS_STRIDE_PAGES", 16);
    size_t pages = size / page_size_bytes;
    if (page_stride == 0) {
        page_stride = 1;
    }
    if (passes == 0) {
        passes = 1;
    }

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t page = 0; page < pages; page += page_stride) {
            size_t offset = page * page_size_bytes;
            unsigned char value = expected_byte(page, pass);
            buffer[offset] = value;
            *checksum += value;
            (*touches)++;
        }
        for (size_t page = 0; page < pages; page += page_stride) {
            size_t offset = page * page_size_bytes;
            unsigned char expected = expected_byte(page, pass);
            if (buffer[offset] != expected) {
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    return 0;
}

static int run_random_hotset(unsigned char* buffer, size_t size,
                             uint64_t* checksum, size_t* touches) {
    size_t hotset = env_size("MAI_ACCESS_HOTSET", 16ULL * 1024ULL * 1024ULL);
    size_t ops = env_count("MAI_ACCESS_RANDOM_OPS", 200000);
    if (hotset > size) {
        hotset = size;
    }
    hotset -= hotset % page_size_bytes;
    if (hotset == 0 || ops == 0) {
        return -1;
    }

    size_t pages = hotset / page_size_bytes;
    uint32_t* expected = calloc(pages, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    uint64_t state = 0x9e3779b97f4a7c15ULL;
    for (size_t op = 0; op < ops; op++) {
        state = state * 2862933555777941757ULL + 3037000493ULL;
        size_t page = (size_t)((state >> 16) % pages);
        size_t offset = page * page_size_bytes;
        expected[page]++;
        buffer[offset] = (unsigned char)expected[page];
        *checksum += buffer[offset];
        (*touches)++;
    }

    for (size_t page = 0; page < pages; page++) {
        size_t offset = page * page_size_bytes;
        if (buffer[offset] != (unsigned char)expected[page]) {
            free(expected);
            return -1;
        }
        *checksum += buffer[offset];
        (*touches)++;
    }

    free(expected);
    return 0;
}

static int run_policy_hotset_scan(unsigned char* buffer, size_t size,
                                  uint64_t* checksum, size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_HOTSET_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t hotset_bytes =
        env_size("MAI_BENCH_POLICY_HOTSET", 8ULL * 1024ULL * 1024ULL);
    size_t hot_rounds = env_count("MAI_BENCH_POLICY_HOT_ROUNDS", 4);
    size_t scan_passes = env_count("MAI_BENCH_POLICY_SCAN_PASSES", 3);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    size_t units = size / unit_bytes;
    if (units < 2) {
        return -1;
    }
    hotset_bytes -= hotset_bytes % unit_bytes;
    size_t hot_units = hotset_bytes / unit_bytes;
    if (hot_units == 0) {
        hot_units = 1;
    }
    if (hot_units >= units) {
        hot_units = units / 2;
    }
    if (hot_units == 0 || hot_units >= units) {
        return -1;
    }
    if (hot_rounds == 0) {
        hot_rounds = 1;
    }
    if (scan_passes == 0) {
        scan_passes = 1;
    }

    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t round = 0; round < hot_rounds; round++) {
            for (size_t unit = 0; unit < hot_units; unit++) {
                size_t offset = unit * unit_bytes;
                expected[unit]++;
                buffer[offset] = expected[unit];
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
        for (size_t unit = hot_units; unit < units; unit++) {
            size_t offset = unit * unit_bytes;
            expected[unit]++;
            buffer[offset] = expected[unit];
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t offset = unit * unit_bytes;
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "hotset_scan";
    stream_pipeline_prediction_recorded = "admission_lfu";
    stream_pipeline_groups_recorded = hot_units;
    stream_pipeline_group_visits_recorded = units - hot_units;
    stream_pipeline_group_iterations_recorded = scan_passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;

    free(expected);
    return 0;
}

static int run_policy_phase_shift_hotset(unsigned char* buffer, size_t size,
                                         uint64_t* checksum,
                                         size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_PHASE_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t hotset_bytes =
        env_size("MAI_BENCH_POLICY_PHASE_HOTSET", 8ULL * 1024ULL * 1024ULL);
    size_t warm_rounds = env_count("MAI_BENCH_POLICY_PHASE_WARM_ROUNDS", 8);
    size_t active_rounds =
        env_count("MAI_BENCH_POLICY_PHASE_ACTIVE_ROUNDS", 4);
    size_t scan_passes = env_count("MAI_BENCH_POLICY_PHASE_SCAN_PASSES", 3);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    hotset_bytes -= hotset_bytes % unit_bytes;
    size_t hot_units = hotset_bytes / unit_bytes;
    if (hot_units == 0) {
        hot_units = 1;
    }
    size_t units = size / unit_bytes;
    if (units < hot_units * 2 + 1) {
        return -1;
    }
    if (warm_rounds == 0) {
        warm_rounds = 1;
    }
    if (active_rounds == 0) {
        active_rounds = 1;
    }
    if (scan_passes == 0) {
        scan_passes = 1;
    }

    size_t phase_a = 0;
    size_t phase_b = hot_units;
    size_t scan_start = hot_units * 2;
    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t round = 0; round < warm_rounds; round++) {
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = phase_a + unit;
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t round = 0; round < active_rounds; round++) {
            for (size_t unit = 0; unit < hot_units; unit++) {
                size_t index = phase_b + unit;
                size_t offset = index * unit_bytes;
                expected[index]++;
                buffer[offset] = expected[index];
                if (buffer[offset] != expected[index]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
        for (size_t index = scan_start; index < units; index++) {
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = phase_b + unit;
            size_t offset = index * unit_bytes;
            if (buffer[offset] != expected[index]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "phase_shift_hotset";
    stream_pipeline_prediction_recorded = "reuse_distance";
    stream_pipeline_groups_recorded = hot_units;
    stream_pipeline_group_visits_recorded = units - scan_start;
    stream_pipeline_group_iterations_recorded = scan_passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_lag_recorded = warm_rounds;
    stream_pipeline_reclaim_horizon_recorded = active_rounds;

    free(expected);
    return 0;
}

static int run_policy_irr_scan_return(unsigned char* buffer, size_t size,
                                      uint64_t* checksum,
                                      size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_IRR_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t hotset_bytes =
        env_size("MAI_BENCH_POLICY_IRR_HOTSET", 8ULL * 1024ULL * 1024ULL);
    size_t decoy_bytes =
        env_size("MAI_BENCH_POLICY_IRR_DECOY", 8ULL * 1024ULL * 1024ULL);
    size_t epochs = env_count("MAI_BENCH_POLICY_IRR_EPOCHS", 6);
    size_t hot_rounds = env_count("MAI_BENCH_POLICY_IRR_HOT_ROUNDS", 4);
    size_t decoy_rounds = env_count("MAI_BENCH_POLICY_IRR_DECOY_ROUNDS", 2);
    size_t decoy_bands = env_count("MAI_BENCH_POLICY_IRR_DECOY_BANDS", 3);
    size_t seed = env_count("MAI_BENCH_POLICY_IRR_SEED", 23);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    hotset_bytes -= hotset_bytes % unit_bytes;
    decoy_bytes -= decoy_bytes % unit_bytes;
    size_t hot_units = hotset_bytes / unit_bytes;
    size_t decoy_units = decoy_bytes / unit_bytes;
    if (hot_units == 0) {
        hot_units = 1;
    }
    if (decoy_units == 0) {
        decoy_units = 1;
    }
    if (epochs < 2) {
        epochs = 2;
    }
    if (hot_rounds == 0) {
        hot_rounds = 1;
    }
    if (decoy_rounds == 0) {
        decoy_rounds = 1;
    }
    if (decoy_bands == 0) {
        decoy_bands = 1;
    }

    size_t units = size / unit_bytes;
    if (units < hot_units * 2 + decoy_units + 1) {
        return -1;
    }
    while (decoy_bands > 1 &&
           hot_units * 2 + decoy_bands * decoy_units >= units) {
        decoy_bands--;
    }
    size_t phase_a = 0;
    size_t phase_b = hot_units;
    size_t decoy_start = hot_units * 2;
    size_t cold_start = decoy_start + decoy_bands * decoy_units;
    if (cold_start >= units) {
        return -1;
    }
    size_t cold_units = units - cold_start;

    unsigned char* expected = calloc(units, sizeof(*expected));
    size_t* cold_order = malloc(cold_units * sizeof(*cold_order));
    if (!expected || !cold_order) {
        free(expected);
        free(cold_order);
        return -1;
    }

    int adapted_to_phase_b = 0;
    size_t switch_epoch = epochs / 2;
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t epoch = 0; epoch < epochs; epoch++) {
        size_t hot_base = epoch < switch_epoch ? phase_a : phase_b;
        size_t decoy_base =
            decoy_start + (epoch % decoy_bands) * decoy_units;

        for (size_t round = 0; round < hot_rounds; round++) {
            for (size_t unit = 0; unit < hot_units; unit++) {
                size_t index = hot_base + unit;
                size_t offset = index * unit_bytes;
                expected[index]++;
                buffer[offset] = expected[index];
                if (buffer[offset] != expected[index]) {
                    free(expected);
                    free(cold_order);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }

        for (size_t round = 0; round < decoy_rounds; round++) {
            for (size_t unit = 0; unit < decoy_units; unit++) {
                size_t index = decoy_base + unit;
                size_t offset = index * unit_bytes;
                expected[index]++;
                buffer[offset] = expected[index];
                if (buffer[offset] != expected[index]) {
                    free(expected);
                    free(cold_order);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }

        shuffle_size_order(cold_order, cold_units,
                           seed + epoch * 11400714819323198485ULL);
        MaiStats scan_before;
        int scan_before_available = 0;
        if (load_stats_optional(&scan_before, &scan_before_available) != 0) {
            free(expected);
            free(cold_order);
            return -1;
        }
        for (size_t pos = 0; pos < cold_units; pos++) {
            size_t index = cold_start + cold_order[pos];
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(expected);
                free(cold_order);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        if (scan_before_available) {
            MaiStats scan_after;
            int scan_after_available = 0;
            if (load_stats_optional(&scan_after, &scan_after_available) != 0) {
                free(expected);
                free(cold_order);
                return -1;
            }
            if (scan_after_available) {
                policy_irr_scan_faults_recorded +=
                    scan_after.policy_demand_faults -
                    scan_before.policy_demand_faults;
                policy_irr_scan_read_bytes_recorded +=
                    scan_after.policy_migration_read_bytes -
                    scan_before.policy_migration_read_bytes;
                policy_irr_scan_write_bytes_recorded +=
                    scan_after.policy_migration_write_bytes -
                    scan_before.policy_migration_write_bytes;
                policy_irr_scan_hot_evicted_bytes_recorded +=
                    scan_after.policy_evicted_hot_bytes -
                    scan_before.policy_evicted_hot_bytes;
                policy_irr_scan_unused_prefetch_evictions_recorded +=
                    scan_after.policy_prefetch_unused_evictions -
                    scan_before.policy_prefetch_unused_evictions;
                policy_irr_scan_stall_ns_recorded +=
                    scan_after.policy_demand_fault_stall_ns -
                    scan_before.policy_demand_fault_stall_ns;
            }
        }

        for (size_t unit = 0; unit < hot_units; unit++) {
            MaiStats return_before;
            int return_before_available = 0;
            if (load_stats_optional(&return_before,
                                    &return_before_available) != 0) {
                free(expected);
                free(cold_order);
                return -1;
            }
            size_t index = hot_base + unit;
            size_t offset = index * unit_bytes;
            if (buffer[offset] != expected[index]) {
                free(expected);
                free(cold_order);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
            policy_irr_hot_return_touches_recorded++;
            if (return_before_available) {
                MaiStats return_after;
                int return_after_available = 0;
                if (load_stats_optional(&return_after,
                                        &return_after_available) != 0) {
                    free(expected);
                    free(cold_order);
                    return -1;
                }
                if (return_after_available) {
                    size_t faults =
                        return_after.policy_demand_faults -
                        return_before.policy_demand_faults;
                    if (faults == 0) {
                        policy_irr_hot_return_hits_recorded++;
                        if (epoch >= switch_epoch && !adapted_to_phase_b) {
                            policy_irr_adaptation_lag_touches_recorded++;
                            adapted_to_phase_b = 1;
                        }
                    } else {
                        policy_irr_hot_return_faults_recorded += faults;
                        if (epoch >= switch_epoch && !adapted_to_phase_b) {
                            policy_irr_adaptation_lag_touches_recorded++;
                        }
                    }
                }
            }
        }

        for (size_t unit = 0; unit < decoy_units; unit++) {
            MaiStats return_before;
            int return_before_available = 0;
            if (load_stats_optional(&return_before,
                                    &return_before_available) != 0) {
                free(expected);
                free(cold_order);
                return -1;
            }
            size_t index = decoy_base + unit;
            size_t offset = index * unit_bytes;
            if (buffer[offset] != expected[index]) {
                free(expected);
                free(cold_order);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
            policy_irr_decoy_return_touches_recorded++;
            if (return_before_available) {
                MaiStats return_after;
                int return_after_available = 0;
                if (load_stats_optional(&return_after,
                                        &return_after_available) != 0) {
                    free(expected);
                    free(cold_order);
                    return -1;
                }
                if (return_after_available) {
                    size_t faults =
                        return_after.policy_demand_faults -
                        return_before.policy_demand_faults;
                    if (faults == 0) {
                        policy_irr_decoy_return_hits_recorded++;
                    } else {
                        policy_irr_decoy_return_faults_recorded += faults;
                    }
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        free(cold_order);
        return -1;
    }
    if (policy_irr_hot_return_touches_recorded != 0) {
        policy_irr_hot_return_hit_ratio_recorded =
            (double)policy_irr_hot_return_hits_recorded /
            (double)policy_irr_hot_return_touches_recorded;
    }
    if (policy_irr_decoy_return_touches_recorded != 0) {
        policy_irr_decoy_return_hit_ratio_recorded =
            (double)policy_irr_decoy_return_hits_recorded /
            (double)policy_irr_decoy_return_touches_recorded;
    }
    policy_irr_discrimination_score_recorded =
        policy_irr_hot_return_hit_ratio_recorded -
        policy_irr_decoy_return_hit_ratio_recorded;
    if (!adapted_to_phase_b && policy_irr_adaptation_lag_touches_recorded == 0) {
        policy_irr_adaptation_lag_touches_recorded =
            policy_irr_hot_return_touches_recorded;
    }
    stream_pipeline_order_recorded = "irr_scan_return";
    stream_pipeline_prediction_recorded = "irr_discrimination";
    stream_pipeline_groups_recorded = 2 + decoy_bands;
    stream_pipeline_group_visits_recorded = epochs;
    stream_pipeline_group_iterations_recorded = hot_rounds;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_group_bytes_recorded = hot_units * unit_bytes;
    stream_pipeline_reclaim_lag_recorded = decoy_rounds;
    stream_pipeline_reclaim_horizon_recorded = cold_units;
    stream_pipeline_unique_cold_visits_recorded = cold_units;
    stream_pipeline_seed_recorded = seed;

    free(expected);
    free(cold_order);
    return 0;
}

static int run_policy_recency_frequency_pivot(unsigned char* buffer,
                                              size_t size,
                                              uint64_t* checksum,
                                              size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_PIVOT_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t hotset_bytes =
        env_size("MAI_BENCH_POLICY_PIVOT_HOTSET", 8ULL * 1024ULL * 1024ULL);
    size_t warm_rounds =
        env_count("MAI_BENCH_POLICY_PIVOT_WARM_ROUNDS", 8);
    size_t burst_groups =
        env_count("MAI_BENCH_POLICY_PIVOT_BURST_GROUPS", 3);
    size_t burst_rounds =
        env_count("MAI_BENCH_POLICY_PIVOT_BURST_ROUNDS", 3);
    size_t return_rounds =
        env_count("MAI_BENCH_POLICY_PIVOT_RETURN_ROUNDS", 4);
    size_t scan_passes =
        env_count("MAI_BENCH_POLICY_PIVOT_SCAN_PASSES", 2);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    hotset_bytes -= hotset_bytes % unit_bytes;
    size_t hot_units = hotset_bytes / unit_bytes;
    if (hot_units == 0) {
        hot_units = 1;
    }
    if (burst_groups == 0) {
        burst_groups = 1;
    }
    if (warm_rounds == 0) {
        warm_rounds = 1;
    }
    if (burst_rounds == 0) {
        burst_rounds = 1;
    }
    if (return_rounds == 0) {
        return_rounds = 1;
    }
    if (scan_passes == 0) {
        scan_passes = 1;
    }

    size_t units = size / unit_bytes;
    size_t active_groups = burst_groups + 1;
    if (active_groups > SIZE_MAX / hot_units) {
        return -1;
    }
    size_t scan_start = active_groups * hot_units;
    if (units <= scan_start) {
        return -1;
    }
    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t round = 0; round < warm_rounds; round++) {
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t offset = unit * unit_bytes;
            expected[unit]++;
            buffer[offset] = expected[unit];
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    for (size_t pass = 0; pass < scan_passes; pass++) {
        for (size_t group = 0; group < burst_groups; group++) {
            size_t base = (group + 1) * hot_units;
            for (size_t round = 0; round < burst_rounds; round++) {
                for (size_t unit = 0; unit < hot_units; unit++) {
                    size_t index = base + unit;
                    size_t offset = index * unit_bytes;
                    expected[index]++;
                    buffer[offset] = expected[index];
                    if (buffer[offset] != expected[index]) {
                        free(expected);
                        return -1;
                    }
                    *checksum += buffer[offset];
                    (*touches)++;
                }
            }
            for (size_t index = scan_start; index < units; index++) {
                size_t offset = index * unit_bytes;
                expected[index]++;
                buffer[offset] = expected[index];
                if (buffer[offset] != expected[index]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
            for (size_t unit = 0; unit < hot_units; unit++) {
                size_t index = base + unit;
                size_t offset = index * unit_bytes;
                if (buffer[offset] != expected[index]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }

        for (size_t round = 0; round < return_rounds; round++) {
            for (size_t unit = 0; unit < hot_units; unit++) {
                MaiStats return_before;
                int return_before_available = 0;
                if (load_stats_optional(&return_before,
                                        &return_before_available) != 0) {
                    free(expected);
                    return -1;
                }
                size_t offset = unit * unit_bytes;
                expected[unit]++;
                buffer[offset] = expected[unit];
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
                policy_pivot_return_touches_recorded++;
                if (return_before_available) {
                    MaiStats return_after;
                    int return_after_available = 0;
                    if (load_stats_optional(&return_after,
                                            &return_after_available) != 0) {
                        free(expected);
                        return -1;
                    }
                    if (return_after_available) {
                        size_t faults =
                            return_after.policy_demand_faults -
                            return_before.policy_demand_faults;
                        if (faults == 0) {
                            policy_pivot_return_hits_recorded++;
                        } else {
                            policy_pivot_return_faults_recorded += faults;
                            if (policy_pivot_adaptation_lag_touches_recorded ==
                                0) {
                                policy_pivot_adaptation_lag_touches_recorded =
                                    policy_pivot_return_touches_recorded;
                            }
                        }
                    }
                }
            }
        }
        for (size_t index = scan_start; index < units; index++) {
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t offset = unit * unit_bytes;
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "recency_frequency_pivot";
    stream_pipeline_prediction_recorded = "car_adaptive";
    stream_pipeline_groups_recorded = active_groups;
    stream_pipeline_group_visits_recorded = active_groups * scan_passes;
    stream_pipeline_group_iterations_recorded = burst_rounds;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_lag_recorded = warm_rounds;
    stream_pipeline_reclaim_horizon_recorded = return_rounds;
    if (policy_pivot_return_touches_recorded != 0) {
        policy_pivot_hot_return_hit_ratio_recorded =
            (double)policy_pivot_return_hits_recorded /
            (double)policy_pivot_return_touches_recorded;
    }

    free(expected);
    return 0;
}

static int run_policy_long_tail_admission(unsigned char* buffer, size_t size,
                                          uint64_t* checksum,
                                          size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_LONGTAIL_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t hotset_bytes =
        env_size("MAI_BENCH_POLICY_LONGTAIL_HOTSET", 8ULL * 1024ULL * 1024ULL);
    size_t medium_bytes =
        env_size("MAI_BENCH_POLICY_LONGTAIL_MEDIUM", 8ULL * 1024ULL * 1024ULL);
    size_t warm_rounds =
        env_count("MAI_BENCH_POLICY_LONGTAIL_WARM_ROUNDS", 8);
    size_t medium_rounds =
        env_count("MAI_BENCH_POLICY_LONGTAIL_MEDIUM_ROUNDS", 2);
    size_t cold_passes =
        env_count("MAI_BENCH_POLICY_LONGTAIL_COLD_PASSES", 3);
    size_t phase_rounds =
        env_count("MAI_BENCH_POLICY_LONGTAIL_PHASE_ROUNDS", 3);
    size_t seed = env_count("MAI_BENCH_POLICY_LONGTAIL_SEED", 17);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    hotset_bytes -= hotset_bytes % unit_bytes;
    medium_bytes -= medium_bytes % unit_bytes;
    size_t hot_units = hotset_bytes / unit_bytes;
    size_t medium_units = medium_bytes / unit_bytes;
    if (hot_units == 0) {
        hot_units = 1;
    }
    if (medium_units == 0) {
        medium_units = 1;
    }
    size_t units = size / unit_bytes;
    if (units < hot_units * 2 + medium_units + 1) {
        return -1;
    }
    if (warm_rounds == 0) {
        warm_rounds = 1;
    }
    if (medium_rounds == 0) {
        medium_rounds = 1;
    }
    if (cold_passes == 0) {
        cold_passes = 1;
    }
    if (phase_rounds == 0) {
        phase_rounds = 1;
    }

    size_t hot_a = 0;
    size_t hot_b = hot_units;
    size_t medium_start = hot_units * 2;
    size_t cold_start = medium_start + medium_units;
    size_t cold_units = units - cold_start;
    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }
    unsigned char* visited = calloc(cold_units, sizeof(*visited));
    if (!visited) {
        free(expected);
        return -1;
    }
    size_t unique_cold_visits = 0;

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t round = 0; round < warm_rounds; round++) {
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = hot_a + unit;
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    for (size_t pass = 0; pass < cold_passes; pass++) {
        for (size_t round = 0; round < medium_rounds; round++) {
            for (size_t unit = 0; unit < medium_units; unit++) {
                size_t index = medium_start + unit;
                size_t offset = index * unit_bytes;
                expected[index]++;
                buffer[offset] = expected[index];
                if (buffer[offset] != expected[index]) {
                    free(visited);
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
        size_t salt = seed + pass * 2654435761ULL;
        size_t start_unit = salt % cold_units;
        size_t stride = coprime_stride(cold_units, salt ^ 1103515245ULL);
        memset(visited, 0, cold_units * sizeof(*visited));
        size_t pass_unique = 0;
        for (size_t step = 0; step < cold_units; step++) {
            size_t cold_unit = (start_unit + step * stride) % cold_units;
            if (visited[cold_unit]) {
                free(visited);
                free(expected);
                return -1;
            }
            visited[cold_unit] = 1;
            pass_unique++;
            size_t index = cold_start + cold_unit;
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        if (pass_unique != cold_units) {
            free(visited);
            free(expected);
            return -1;
        }
        unique_cold_visits += pass_unique;
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = hot_a + unit;
            size_t offset = index * unit_bytes;
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    for (size_t round = 0; round < phase_rounds; round++) {
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = hot_b + unit;
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        size_t salt = seed + round * 1013904223ULL;
        size_t start_unit = salt % cold_units;
        size_t stride = coprime_stride(cold_units, salt ^ 1664525ULL);
        memset(visited, 0, cold_units * sizeof(*visited));
        size_t pass_unique = 0;
        for (size_t step = 0; step < cold_units; step++) {
            size_t cold_unit = (start_unit + step * stride) % cold_units;
            if (visited[cold_unit]) {
                free(visited);
                free(expected);
                return -1;
            }
            visited[cold_unit] = 1;
            pass_unique++;
            size_t index = cold_start + cold_unit;
            size_t offset = index * unit_bytes;
            expected[index]++;
            buffer[offset] = expected[index];
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
        if (pass_unique != cold_units) {
            free(visited);
            free(expected);
            return -1;
        }
        unique_cold_visits += pass_unique;
        for (size_t unit = 0; unit < hot_units; unit++) {
            size_t index = hot_b + unit;
            size_t offset = index * unit_bytes;
            if (buffer[offset] != expected[index]) {
                free(visited);
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(visited);
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "long_tail_admission";
    stream_pipeline_prediction_recorded = "tinylfu_admission";
    stream_pipeline_groups_recorded = 3;
    stream_pipeline_group_visits_recorded = cold_units;
    stream_pipeline_group_iterations_recorded = cold_passes + phase_rounds;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_lag_recorded = warm_rounds;
    stream_pipeline_reclaim_horizon_recorded = phase_rounds;
    stream_pipeline_unique_cold_visits_recorded = unique_cold_visits;
    stream_pipeline_seed_recorded = seed;

    free(visited);
    free(expected);
    return 0;
}

static int run_policy_best_offset_lag(unsigned char* buffer, size_t size,
                                      uint64_t* checksum, size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_OFFSET_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t offset_chunks =
        env_count("MAI_BENCH_POLICY_OFFSET_CHUNKS", 8);
    size_t lookahead =
        env_count("MAI_BENCH_POLICY_OFFSET_LOOKAHEAD", 4);
    size_t passes = env_count("MAI_BENCH_POLICY_OFFSET_PASSES", 3);
    size_t seed = env_count("MAI_BENCH_POLICY_OFFSET_SEED", 11);
    size_t noise = env_count("MAI_BENCH_POLICY_OFFSET_NOISE", 0);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    size_t units = size / unit_bytes;
    if (units < 4) {
        return -1;
    }
    if (offset_chunks == 0) {
        offset_chunks = 2;
    }
    if (offset_chunks == 1 && units > 3) {
        offset_chunks = 2;
    }
    if (offset_chunks >= units) {
        offset_chunks = units / 2;
    }
    if (offset_chunks == 0 || offset_chunks >= units) {
        return -1;
    }
    if (lookahead == 0) {
        lookahead = 1;
    }
    if (passes == 0) {
        passes = 1;
    }

    size_t pair_count = offset_chunks;
    if (pair_count > units - offset_chunks) {
        pair_count = units - offset_chunks;
    }
    if (pair_count == 0) {
        return -1;
    }
    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }
    size_t* order = malloc(pair_count * sizeof(*order));
    if (!order) {
        free(expected);
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t pass = 0; pass < passes; pass++) {
        size_t salt = seed + pass * 2654435761ULL;
        shuffle_size_order(order, pair_count, salt ^ 1103515245ULL);
        size_t steps = pair_count + lookahead;
        for (size_t step = 0; step < steps; step++) {
            if (step < pair_count) {
                size_t anchor = order[step];
                size_t offset = anchor * unit_bytes;
                expected[anchor]++;
                buffer[offset] = expected[anchor];
                if (buffer[offset] != expected[anchor]) {
                    free(order);
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
            if (noise != 0 && step < pair_count) {
                size_t noise_index =
                    (salt + step * 1664525ULL + 1013904223ULL) % units;
                size_t offset = noise_index * unit_bytes;
                expected[noise_index]++;
                buffer[offset] = expected[noise_index];
                if (buffer[offset] != expected[noise_index]) {
                    free(order);
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
            if (step >= lookahead &&
                step - lookahead < pair_count) {
                size_t delayed = step - lookahead;
                size_t anchor = order[delayed];
                size_t target = anchor + offset_chunks;
                size_t offset = target * unit_bytes;
                expected[target]++;
                buffer[offset] = expected[target];
                if (buffer[offset] != expected[target]) {
                    free(order);
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(order);
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "best_offset_lag";
    stream_pipeline_prediction_recorded = "best_offset";
    stream_pipeline_groups_recorded = pair_count;
    stream_pipeline_group_visits_recorded = pair_count;
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_lag_recorded = lookahead;
    stream_pipeline_reclaim_horizon_recorded = offset_chunks;
    stream_pipeline_seed_recorded = seed;

    free(order);
    free(expected);
    return 0;
}

static int run_policy_successor_cycle(unsigned char* buffer, size_t size,
                                      uint64_t* checksum,
                                      size_t* touches) {
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_SUCCESSOR_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t passes = env_count_compat("MAI_BENCH_POLICY_PASSES",
                                     "MAI_BENCH_STREAM_PASSES", 3);
    size_t multiplier = env_count("MAI_BENCH_POLICY_SUCCESSOR_MULTIPLIER", 5);
    size_t addend = env_count("MAI_BENCH_POLICY_SUCCESSOR_ADDEND", 3);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    size_t units = size / unit_bytes;
    if (units < 4) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }
    if (multiplier == 0) {
        multiplier = 5;
    }
    if (addend == 0) {
        addend = 3;
    }
    if ((multiplier % units) == 0) {
        multiplier++;
    }
    if ((addend % units) == 0) {
        addend++;
    }

    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }
    unsigned char* visited = calloc(units, sizeof(*visited));
    if (!visited) {
        free(expected);
        return -1;
    }
    size_t cycle_index = 0;
    for (size_t step = 0; step < units; step++) {
        if (visited[cycle_index]) {
            free(visited);
            free(expected);
            return -1;
        }
        visited[cycle_index] = 1;
        cycle_index = (multiplier * cycle_index + addend) % units;
    }
    if (cycle_index != 0) {
        free(visited);
        free(expected);
        return -1;
    }
    free(visited);

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < passes; pass++) {
        size_t unit = 0;
        for (size_t step = 0; step < units; step++) {
            size_t offset = unit * unit_bytes;
            expected[unit]++;
            buffer[offset] = expected[unit];
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
            unit = (multiplier * unit + addend) % units;
        }
        unit = 0;
        for (size_t step = 0; step < units; step++) {
            size_t offset = unit * unit_bytes;
            if (buffer[offset] != expected[unit]) {
                free(expected);
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
            unit = (multiplier * unit + addend) % units;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "successor_cycle";
    stream_pipeline_prediction_recorded = "successor";
    stream_pipeline_groups_recorded = units;
    stream_pipeline_group_visits_recorded = passes;
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_scalar_recorded = (double)multiplier;
    stream_pipeline_reclaim_horizon_recorded = addend;

    free(expected);
    return 0;
}

static int run_policy_hinted_sequential(unsigned char* buffer, size_t size,
                                        uint64_t* checksum,
                                        size_t* touches) {
    load_range_ops_optional();

    MaiHintOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.window_bytes =
        env_size("MAI_BENCH_HINT_WINDOW", 8ULL * 1024ULL * 1024ULL);
    opts.hotset_bytes = env_size("MAI_BENCH_HINT_HOTSET", 0);
    if (env_flag("MAI_BENCH_HINT_ENABLE", 1) && hint_range &&
        hint_range(buffer, size, MAI_HINT_SEQUENTIAL, &opts) != 0) {
        return -1;
    }

    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    if (passes == 0) {
        passes = 1;
    }
    size_t pages = size / page_size_bytes;

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t page = 0; page < pages; page++) {
            size_t offset = page * page_size_bytes;
            unsigned char value = expected_byte(page, pass);
            buffer[offset] = value;
            *checksum += value;
            (*touches)++;
        }
        for (size_t page = 0; page < pages; page++) {
            size_t offset = page * page_size_bytes;
            unsigned char expected = expected_byte(page, pass);
            if (buffer[offset] != expected) {
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, page_size_bytes, &logical_bytes) != 0) {
        return -1;
    }
    stream_pipeline_order_recorded = "hinted_sequential";
    stream_pipeline_prediction_recorded = "application_hint";
    stream_pipeline_matrix_bytes_recorded = size;
    stream_pipeline_total_matrix_bytes_recorded = size;
    stream_pipeline_group_iterations_recorded = passes;
    return 0;
}

static int run_policy_signature_context_cycle(unsigned char* buffer,
                                              size_t size,
                                              uint64_t* checksum,
                                              size_t* touches) {
    static const size_t context_a[] = {0, 2, 3, 5, 7};
    static const size_t context_b[] = {1, 4, 3, 6, 4};
    const size_t context_len = sizeof(context_a) / sizeof(context_a[0]);
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_SIGNATURE_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t region_units =
        env_count("MAI_BENCH_POLICY_SIGNATURE_REGION_UNITS", 8);
    size_t passes =
        env_count("MAI_BENCH_POLICY_SIGNATURE_PASSES", 4);
    size_t seed = env_count("MAI_BENCH_POLICY_SIGNATURE_SEED", 7);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    if (region_units < 8) {
        region_units = 8;
    }
    size_t units = size / unit_bytes;
    if (units < region_units || units % region_units != 0) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }
    size_t regions = units / region_units;
    unsigned char* expected = calloc(units, sizeof(*expected));
    size_t* order = calloc(regions, sizeof(*order));
    if (!expected || !order) {
        free(order);
        free(expected);
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < passes; pass++) {
        shuffle_size_order(order, regions, (uint64_t)seed +
                           pass * 2654435761ULL);
        for (size_t order_index = 0; order_index < regions; order_index++) {
            size_t region = order[order_index];
            size_t region_base = region * region_units;
            for (size_t context = 0; context < 2; context++) {
                const size_t* pattern =
                    ((pass + order_index + context) & 1u) == 0 ?
                    context_a : context_b;
                for (size_t pos = 0; pos < context_len; pos++) {
                    size_t unit = region_base + pattern[pos];
                    size_t offset = unit * unit_bytes;
                    expected[unit]++;
                    buffer[offset] = expected[unit];
                    if (buffer[offset] != expected[unit]) {
                        free(order);
                        free(expected);
                        return -1;
                    }
                    *checksum += buffer[offset];
                    (*touches)++;
                }
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(order);
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "signature_context_cycle";
    stream_pipeline_prediction_recorded = "signature_history";
    stream_pipeline_groups_recorded = regions;
    stream_pipeline_group_visits_recorded = regions * passes;
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_horizon_recorded = region_units;
    stream_pipeline_seed_recorded = seed;

    free(order);
    free(expected);
    return 0;
}

static size_t spatial_region_units_env(void) {
    return env_count("MAI_BENCH_POLICY_SPATIAL_REGION_UNITS", 8);
}

static size_t spatial_mask_units(size_t region_units) {
    return region_units < 3 ? region_units : 3;
}

static size_t spatial_pattern_offset(size_t position, size_t pass,
                                     size_t region, size_t region_units,
                                     int mixed_masks) {
    static const size_t offsets_a[] = {0, 3, 5};
    static const size_t offsets_b[] = {1, 4, 7};
    const size_t* offsets = offsets_a;
    size_t count = sizeof(offsets_a) / sizeof(offsets_a[0]);
    if (region_units >= 8 && mixed_masks && (region & 1u) != 0) {
        offsets = offsets_b;
    }
    if (region_units < 8) {
        count = spatial_mask_units(region_units);
    }
    size_t rotated = count == 0 ? 0 : (position + pass + region) % count;
    if (((pass + region) & 1u) != 0) {
        rotated = count - 1 - rotated;
    }
    if (region_units >= 8) {
        return offsets[rotated];
    }
    if (mixed_masks && (region & 1u) != 0 && region_units > count) {
        return (rotated + 1) % region_units;
    }
    return rotated;
}

static int run_policy_spatial_region_mask(unsigned char* buffer, size_t size,
                                          uint64_t* checksum,
                                          size_t* touches) {
    const size_t region_units = spatial_region_units_env();
    const size_t mask_units = spatial_mask_units(region_units);
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_SPATIAL_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t passes = env_count_compat("MAI_BENCH_POLICY_PASSES",
                                     "MAI_BENCH_STREAM_PASSES", 3);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    size_t units = size / unit_bytes;
    if (region_units < 2 || mask_units == 0 || units < region_units ||
        units % region_units != 0) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }
    size_t regions = units / region_units;

    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t region = 0; region < regions; region++) {
            size_t region_base = region * region_units;
            for (size_t position = 0; position < mask_units; position++) {
                size_t unit = region_base +
                    spatial_pattern_offset(position, pass, region,
                                           region_units, 0);
                size_t offset = unit * unit_bytes;
                expected[unit]++;
                buffer[offset] = expected[unit];
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
        for (size_t region = 0; region < regions; region++) {
            size_t region_base = region * region_units;
            for (size_t position = 0; position < mask_units; position++) {
                size_t unit = region_base +
                    spatial_pattern_offset(position, pass + 1, region,
                                           region_units, 0);
                size_t offset = unit * unit_bytes;
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "spatial_region_mask";
    stream_pipeline_prediction_recorded = "spatial";
    stream_pipeline_groups_recorded = regions;
    stream_pipeline_group_visits_recorded = mask_units;
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_horizon_recorded = region_units;

    free(expected);
    return 0;
}

static int run_policy_spatial_interleaved_mask(unsigned char* buffer,
                                               size_t size,
                                               uint64_t* checksum,
                                               size_t* touches) {
    const size_t region_units = spatial_region_units_env();
    const size_t mask_units = spatial_mask_units(region_units);
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_SPATIAL_UNIT", 2ULL * 1024ULL * 1024ULL);
    size_t passes = env_count_compat("MAI_BENCH_POLICY_PASSES",
                                     "MAI_BENCH_STREAM_PASSES", 3);

    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }
    size_t units = size / unit_bytes;
    if (region_units < 2 || mask_units == 0 || units < region_units ||
        units % region_units != 0) {
        return -1;
    }
    if (passes == 0) {
        passes = 1;
    }
    size_t regions = units / region_units;

    unsigned char* expected = calloc(units, sizeof(*expected));
    if (!expected) {
        return -1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t position = 0; position < mask_units; position++) {
            for (size_t region = 0; region < regions; region++) {
                size_t region_base = region * region_units;
                size_t unit = region_base +
                    spatial_pattern_offset(position, pass, region,
                                           region_units, 1);
                size_t offset = unit * unit_bytes;
                expected[unit]++;
                buffer[offset] = expected[unit];
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
        for (size_t position = 0; position < mask_units; position++) {
            for (size_t region = 0; region < regions; region++) {
                size_t region_base = region * region_units;
                size_t unit = region_base +
                    spatial_pattern_offset(position, pass + 1, region,
                                           region_units, 1);
                size_t offset = unit * unit_bytes;
                if (buffer[offset] != expected[unit]) {
                    free(expected);
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        free(expected);
        return -1;
    }
    stream_pipeline_order_recorded = "spatial_interleaved_mask";
    stream_pipeline_prediction_recorded = "spatial";
    stream_pipeline_groups_recorded = regions;
    stream_pipeline_group_visits_recorded = mask_units;
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_reclaim_horizon_recorded = region_units;

    free(expected);
    return 0;
}

static int run_trace_chunks(unsigned char* buffer, size_t size,
                            uint64_t* checksum, size_t* touches) {
    if (load_trace_symbols() != 0) {
        return -1;
    }

    size_t chunk = env_size("MAI_ACCESS_TRACE_CHUNK", 4ULL * 1024ULL * 1024ULL);
    size_t max_pages = env_count("MAI_ACCESS_TRACE_PAGES", 64);
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0) {
        return -1;
    }
    if (max_pages == 0 || max_pages > 64) {
        max_pages = 64;
    }
    if (passes == 0) {
        passes = 1;
    }

    size_t chunk_count = size / chunk + (size % chunk != 0);
    size_t sampled_chunks = max_pages < chunk_count ? max_pages : chunk_count;
    if (sampled_chunks == 0) {
        return -1;
    }

    MaiAccessTraceOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.max_pages = max_pages;
    opts.chunk_bytes = chunk;

    for (size_t pass = 0; pass < passes; pass++) {
        if (trace_access(buffer, size, &opts) != 0) {
            return -1;
        }

        for (size_t sample = 0; sample < sampled_chunks; sample++) {
            size_t offset = sample * chunk;
            if (offset >= size) {
                break;
            }
            unsigned char value = expected_byte(offset / page_size_bytes, pass);
            buffer[offset] = value;
            *checksum += value;
            (*touches)++;
        }

        MaiAccessTraceSnapshot snapshot;
        if (get_access_trace(buffer, &snapshot) != 0 ||
            snapshot.touched_pages != sampled_chunks) {
            (void)stop_access_trace(buffer);
            return -1;
        }

        if (stop_access_trace(buffer) != 0) {
            return -1;
        }

        for (size_t sample = 0; sample < sampled_chunks; sample++) {
            size_t offset = sample * chunk;
            unsigned char expected = expected_byte(offset / page_size_bytes, pass);
            if (buffer[offset] != expected) {
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    return 0;
}

static int run_heartbeat_busy(unsigned char* buffer, size_t size,
                              uint64_t* checksum, size_t* touches) {
    if (load_heartbeat_symbol() != 0) {
        return -1;
    }

    size_t chunk = env_size("MAI_HEARTBEAT_CHUNK", 4ULL * 1024ULL * 1024ULL);
    size_t observe_pages = env_count("MAI_HEARTBEAT_OBSERVE_PAGES", 16);
    size_t migrate_bytes = env_size("MAI_HEARTBEAT_MIGRATE_BYTES", 0);
    size_t passes = env_count("MAI_ACCESS_PASSES", 1);
    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0) {
        return -1;
    }
    if (observe_pages == 0 || observe_pages > 64) {
        observe_pages = 64;
    }
    if (passes == 0) {
        passes = 1;
    }
    if (migrate_bytes == 0) {
        if (chunk > SIZE_MAX / observe_pages) {
            migrate_bytes = SIZE_MAX;
        } else {
            migrate_bytes = chunk * observe_pages;
        }
    }
    heartbeat_migrate_bytes = migrate_bytes;

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = observe_pages;
    opts.chunk_bytes = chunk;
    opts.migrate_bytes = migrate_bytes;

    for (size_t pass = 0; pass < passes; pass++) {
        if (heartbeat_now(&opts) != 0) {
            return -1;
        }

        for (size_t offset = 0; offset < size; offset += page_size_bytes) {
            unsigned char value = expected_byte(offset / page_size_bytes, pass);
            buffer[offset] = value;
            *checksum += value;
            (*touches)++;
        }

        if (heartbeat_now(&opts) != 0) {
            return -1;
        }

        for (size_t offset = 0; offset < size; offset += page_size_bytes) {
            unsigned char expected = expected_byte(offset / page_size_bytes, pass);
            if (buffer[offset] != expected) {
                return -1;
            }
            *checksum += buffer[offset];
            (*touches)++;
        }
    }

    return heartbeat_reclaimed_bytes == 0 && heartbeat_busy_ticks != 0 ? 0 : -1;
}

static void fill_sample_order(size_t* order, size_t sample_count) {
    const char* order_env = getenv("MAI_MPROTECT_ORDER");
    for (size_t i = 0; i < sample_count; i++) {
        order[i] = i;
    }
    if (!order_env || strcmp(order_env, "sequential") == 0) {
        return;
    }
    if (strcmp(order_env, "reverse") == 0) {
        for (size_t i = 0; i < sample_count / 2; i++) {
            size_t tmp = order[i];
            order[i] = order[sample_count - 1 - i];
            order[sample_count - 1 - i] = tmp;
        }
        return;
    }
    if (strcmp(order_env, "random") == 0) {
        uint64_t state = 0x9e3779b97f4a7c15ULL;
        for (size_t i = sample_count; i > 1; i--) {
            state = state * 2862933555777941757ULL + 3037000493ULL;
            size_t j = (size_t)(state % i);
            size_t tmp = order[i - 1];
            order[i - 1] = order[j];
            order[j] = tmp;
        }
    }
}

static void summarize_latencies(uint64_t* latencies, size_t count) {
    if (count == 0) {
        return;
    }

    qsort(latencies, count, sizeof(*latencies), compare_u64);
    mprotect_first_touch_min_ns = latencies[0];
    mprotect_first_touch_p50_ns = latencies[count / 2];
    mprotect_first_touch_p90_ns = latencies[(count * 90) / 100 >= count ?
        count - 1 : (count * 90) / 100];
    mprotect_first_touch_p99_ns = latencies[(count * 99) / 100 >= count ?
        count - 1 : (count * 99) / 100];
    mprotect_first_touch_max_ns = latencies[count - 1];
}

static int run_full_sweep(unsigned char* buffer, size_t size,
                          uint64_t* checksum) {
    struct timespec start;
    struct timespec end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(buffer[i] + 1);
    }
    for (size_t i = 0; i < size; i++) {
        *checksum += buffer[i];
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    mprotect_sweep_ns += timespec_delta_ns(&start, &end);
    logical_bytes += size * 2;
    return 0;
}

static void warm_buffer_pages(unsigned char* buffer, size_t size,
                              uint64_t* checksum) {
    struct timespec start;
    struct timespec end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t offset = 0; offset < size; offset += page_size_bytes) {
        buffer[offset] = expected_byte(offset / page_size_bytes, 0);
    }
    for (size_t offset = 0; offset < size; offset += page_size_bytes) {
        *checksum += buffer[offset];
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    mprotect_warmup_ns += timespec_delta_ns(&start, &end);
}

static int run_mprotect_overhead(unsigned char* buffer, size_t size,
                                 uint64_t* checksum, size_t* touches) {
    size_t chunk = 0;
    size_t max_pages = 0;
    size_t passes = 0;
    MprotectMechanism mechanism = MPROTECT_MECHANISM_TRACE;
    if (mprotect_common_options(size, &chunk, &max_pages, &passes,
                                &mechanism) != 0) {
        return -1;
    }

    size_t sample_count = mprotect_sample_count(size, chunk, max_pages);
    if (sample_count == 0 || sample_count > 64) {
        return -1;
    }
    if (passes > SIZE_MAX / sample_count) {
        return -1;
    }
    size_t latency_count = passes * sample_count;
    uint64_t* latencies = calloc(latency_count, sizeof(*latencies));
    if (!latencies) {
        return -1;
    }

    size_t order[64];
    fill_sample_order(order, sample_count);
    warm_buffer_pages(buffer, size, checksum);

    struct rusage usage_before;
    struct rusage usage_after;
    if (getrusage(RUSAGE_SELF, &usage_before) != 0) {
        free(latencies);
        return -1;
    }

    mprotect_mechanism_label = mprotect_mechanism_name(mechanism);
    mprotect_chunk_bytes = chunk;
    mprotect_sample_pages = sample_count;

    size_t latency_index = 0;
    for (size_t pass = 0; pass < passes; pass++) {
        MaiHeartbeatOptions heartbeat_opts;
        struct timespec setup_start;
        struct timespec setup_end;
        clock_gettime(CLOCK_MONOTONIC, &setup_start);
        if (start_observation(buffer, size, mechanism, chunk, max_pages,
                              &heartbeat_opts) != 0) {
            free(latencies);
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &setup_end);
        mprotect_setup_ns += timespec_delta_ns(&setup_start, &setup_end);

        for (size_t i = 0; i < sample_count; i++) {
            size_t sample = order[i];
            size_t offset = sample * chunk;
            struct timespec touch_start;
            struct timespec touch_end;
            clock_gettime(CLOCK_MONOTONIC, &touch_start);
            buffer[offset] = expected_byte(offset / page_size_bytes, pass);
            *checksum += buffer[offset];
            clock_gettime(CLOCK_MONOTONIC, &touch_end);

            uint64_t touch_ns = timespec_delta_ns(&touch_start, &touch_end);
            latencies[latency_index++] = touch_ns;
            mprotect_first_touch_total_ns += touch_ns;
            (*touches)++;
        }

        struct timespec finish_start;
        struct timespec finish_end;
        clock_gettime(CLOCK_MONOTONIC, &finish_start);
        if (finish_observation(buffer, mechanism, &heartbeat_opts,
                               sample_count) != 0) {
            free(latencies);
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &finish_end);
        mprotect_finish_ns += timespec_delta_ns(&finish_start, &finish_end);
    }

    summarize_latencies(latencies, latency_count);
    latency_ops = latency_count;
    free(latencies);

    if (run_full_sweep(buffer, size, checksum) != 0) {
        return -1;
    }

    if (getrusage(RUSAGE_SELF, &usage_after) != 0) {
        return -1;
    }
    mprotect_minor_faults_delta = usage_after.ru_minflt - usage_before.ru_minflt;
    mprotect_major_faults_delta = usage_after.ru_majflt - usage_before.ru_majflt;
    mprotect_voluntary_ctxt_delta =
        usage_after.ru_nvcsw - usage_before.ru_nvcsw;
    mprotect_involuntary_ctxt_delta =
        usage_after.ru_nivcsw - usage_before.ru_nivcsw;
    mprotect_user_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_utime, &usage_after.ru_utime);
    mprotect_sys_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_stime, &usage_after.ru_stime);
    measured_access_seconds = (double)(mprotect_first_touch_total_ns +
        mprotect_sweep_ns) / 1000000000.0;

    return 0;
}

static int run_heartbeat_idle(unsigned char* buffer, size_t size,
                              uint64_t* checksum, size_t* touches) {
    if (load_heartbeat_symbol() != 0) {
        return -1;
    }

    size_t chunk = env_size("MAI_HEARTBEAT_CHUNK", 4ULL * 1024ULL * 1024ULL);
    size_t observe_pages = env_count("MAI_HEARTBEAT_OBSERVE_PAGES", 16);
    size_t epochs = env_count("MAI_HEARTBEAT_EPOCHS", 100);
    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0 || epochs == 0) {
        return -1;
    }
    if (observe_pages == 0 || observe_pages > 64) {
        observe_pages = 64;
    }

    warm_buffer_pages(buffer, size, checksum);

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = observe_pages;
    opts.chunk_bytes = chunk;
    opts.migrate_bytes = 0;

    struct rusage usage_before;
    struct rusage usage_after;
    if (getrusage(RUSAGE_SELF, &usage_before) != 0) {
        return -1;
    }

    for (size_t epoch = 0; epoch < epochs; epoch++) {
        struct timespec start;
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (heartbeat_now(&opts) != 0) {
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        heartbeat_total_ns += timespec_delta_ns(&start, &end);
    }

    if (getrusage(RUSAGE_SELF, &usage_after) != 0) {
        return -1;
    }
    mprotect_minor_faults_delta = usage_after.ru_minflt - usage_before.ru_minflt;
    mprotect_major_faults_delta = usage_after.ru_majflt - usage_before.ru_majflt;
    mprotect_voluntary_ctxt_delta =
        usage_after.ru_nvcsw - usage_before.ru_nvcsw;
    mprotect_involuntary_ctxt_delta =
        usage_after.ru_nivcsw - usage_before.ru_nivcsw;
    mprotect_user_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_utime, &usage_after.ru_utime);
    mprotect_sys_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_stime, &usage_after.ru_stime);
    mprotect_chunk_bytes = chunk;
    mprotect_sample_pages = observe_pages;
    latency_ops = epochs;
    *touches += epochs;
    return 0;
}

static int chunk_touch_offset(size_t chunk, const char** label, size_t* offset) {
    const char* value = getenv("MAI_CHUNK_TOUCH_POSITION");
    if (!value || value[0] == '\0' || strcmp(value, "first") == 0) {
        *label = "first";
        *offset = 0;
        return 0;
    }
    if (strcmp(value, "middle") == 0) {
        *label = "middle";
        *offset = chunk / 2;
        *offset -= *offset % page_size_bytes;
        return 0;
    }
    if (strcmp(value, "last") == 0) {
        *label = "last";
        *offset = chunk > page_size_bytes ? chunk - page_size_bytes : 0;
        return 0;
    }

    return -1;
}

static int run_chunk_position(unsigned char* buffer, size_t size,
                              uint64_t* checksum, size_t* touches) {
    if (load_heartbeat_symbol() != 0) {
        return -1;
    }

    size_t chunk = env_size("MAI_HEARTBEAT_CHUNK", 1ULL * 1024ULL * 1024ULL);
    size_t observe_pages = env_count("MAI_HEARTBEAT_OBSERVE_PAGES", 16);
    size_t epochs = env_count("MAI_CHUNK_POSITION_EPOCHS", 5);
    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0 || chunk > size || epochs == 0) {
        return -1;
    }
    size_t chunk_count = size / chunk;
    if (chunk_count == 0) {
        return -1;
    }
    if (observe_pages == 0 || observe_pages > 64) {
        observe_pages = 64;
    }
    if (observe_pages > chunk_count) {
        observe_pages = chunk_count;
    }

    size_t touch_offset = 0;
    if (chunk_touch_offset(chunk, &chunk_touch_position_label,
                           &touch_offset) != 0) {
        return -1;
    }
    warm_buffer_pages(buffer, size, checksum);

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = observe_pages;
    opts.chunk_bytes = chunk;
    opts.migrate_bytes = observe_pages * chunk;

    MaiHeartbeatSnapshot arm_snapshot;
    struct timespec heartbeat_start;
    struct timespec heartbeat_end;
    clock_gettime(CLOCK_MONOTONIC, &heartbeat_start);
    if (heartbeat_with_snapshot(&opts, &arm_snapshot) != 0 ||
        arm_snapshot.armed_pages == 0) {
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &heartbeat_end);
    heartbeat_total_ns += timespec_delta_ns(&heartbeat_start, &heartbeat_end);

    size_t observed_touched_pages = 0;
    for (size_t epoch = 0; epoch < epochs; epoch++) {
        for (size_t sample = 0; sample < observe_pages; sample++) {
            size_t offset = sample * chunk + touch_offset;
            buffer[offset] = (unsigned char)(buffer[offset] + 1);
            *checksum += buffer[offset];
            (*touches)++;
        }

        MaiHeartbeatSnapshot observe_snapshot;
        clock_gettime(CLOCK_MONOTONIC, &heartbeat_start);
        if (heartbeat_with_snapshot(&opts, &observe_snapshot) != 0) {
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &heartbeat_end);
        heartbeat_total_ns += timespec_delta_ns(&heartbeat_start, &heartbeat_end);
        observed_touched_pages += observe_snapshot.touched_pages;
    }

    for (size_t sample = 0; sample < observe_pages; sample++) {
        size_t offset = sample * chunk + touch_offset;
        *checksum += buffer[offset];
        (*touches)++;
    }

    mprotect_chunk_bytes = chunk;
    mprotect_sample_pages = observe_pages;
    trace_faulted_pages = observed_touched_pages;
    latency_ops = epochs;
    return 0;
}

typedef struct {
    unsigned char* buffer;
    size_t size;
    size_t thread_index;
    size_t thread_count;
    atomic_int* stop;
    atomic_size_t* touch_counter;
} ConcurrentTouchArgs;

static void* concurrent_touch_worker(void* arg) {
    ConcurrentTouchArgs* worker = (ConcurrentTouchArgs*)arg;
    size_t pass = 0;

    while (!atomic_load_explicit(worker->stop, memory_order_acquire)) {
        for (size_t offset = worker->thread_index * page_size_bytes;
             offset < worker->size;
             offset += worker->thread_count * page_size_bytes) {
            worker->buffer[offset] =
                (unsigned char)(worker->buffer[offset] + (unsigned char)(pass + 1));
            atomic_fetch_add_explicit(worker->touch_counter, 1,
                                      memory_order_relaxed);
        }
        pass++;
    }

    return NULL;
}

static int run_heartbeat_concurrent(unsigned char* buffer, size_t size,
                                    uint64_t* checksum, size_t* touches) {
    if (load_heartbeat_symbol() != 0) {
        return -1;
    }

    size_t chunk = env_size("MAI_HEARTBEAT_CHUNK", 1ULL * 1024ULL * 1024ULL);
    size_t observe_pages = env_count("MAI_HEARTBEAT_OBSERVE_PAGES", 16);
    size_t epochs = env_count("MAI_HEARTBEAT_EPOCHS", 50);
    size_t thread_count = env_count("MAI_HEARTBEAT_THREADS", 4);
    if (chunk < page_size_bytes) {
        chunk = page_size_bytes;
    }
    if (align_size_to_page(&chunk) != 0 || epochs == 0 || thread_count == 0) {
        return -1;
    }
    if (observe_pages == 0 || observe_pages > 64) {
        observe_pages = 64;
    }
    if (thread_count > 64) {
        thread_count = 64;
    }

    warm_buffer_pages(buffer, size, checksum);

    pthread_t* threads = calloc(thread_count, sizeof(*threads));
    ConcurrentTouchArgs* args = calloc(thread_count, sizeof(*args));
    if (!threads || !args) {
        free(threads);
        free(args);
        return -1;
    }

    atomic_int stop;
    atomic_size_t touch_counter;
    atomic_init(&stop, 0);
    atomic_init(&touch_counter, 0);

    for (size_t i = 0; i < thread_count; i++) {
        args[i].buffer = buffer;
        args[i].size = size;
        args[i].thread_index = i;
        args[i].thread_count = thread_count;
        args[i].stop = &stop;
        args[i].touch_counter = &touch_counter;
        if (pthread_create(&threads[i], NULL, concurrent_touch_worker,
                           &args[i]) != 0) {
            atomic_store_explicit(&stop, 1, memory_order_release);
            for (size_t j = 0; j < i; j++) {
                pthread_join(threads[j], NULL);
            }
            free(threads);
            free(args);
            return -1;
        }
    }

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = observe_pages;
    opts.chunk_bytes = chunk;
    opts.migrate_bytes = 0;

    struct rusage usage_before;
    struct rusage usage_after;
    if (getrusage(RUSAGE_SELF, &usage_before) != 0) {
        atomic_store_explicit(&stop, 1, memory_order_release);
        for (size_t i = 0; i < thread_count; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
        free(args);
        return -1;
    }

    for (size_t epoch = 0; epoch < epochs; epoch++) {
        struct timespec start;
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (heartbeat_now(&opts) != 0) {
            atomic_store_explicit(&stop, 1, memory_order_release);
            for (size_t i = 0; i < thread_count; i++) {
                pthread_join(threads[i], NULL);
            }
            free(threads);
            free(args);
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        heartbeat_total_ns += timespec_delta_ns(&start, &end);
    }

    atomic_store_explicit(&stop, 1, memory_order_release);
    for (size_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    if (getrusage(RUSAGE_SELF, &usage_after) != 0) {
        free(threads);
        free(args);
        return -1;
    }

    for (size_t offset = 0; offset < size; offset += page_size_bytes) {
        *checksum += buffer[offset];
    }
    size_t worker_touches =
        atomic_load_explicit(&touch_counter, memory_order_relaxed);
    *touches += worker_touches;
    latency_ops = epochs;
    mprotect_chunk_bytes = chunk;
    mprotect_sample_pages = observe_pages;
    logical_bytes = worker_touches * page_size_bytes;
    measured_access_seconds = heartbeat_total_ns > 0 ?
        (double)heartbeat_total_ns / 1000000000.0 : 0.0;
    mprotect_minor_faults_delta = usage_after.ru_minflt - usage_before.ru_minflt;
    mprotect_major_faults_delta = usage_after.ru_majflt - usage_before.ru_majflt;
    mprotect_voluntary_ctxt_delta =
        usage_after.ru_nvcsw - usage_before.ru_nvcsw;
    mprotect_involuntary_ctxt_delta =
        usage_after.ru_nivcsw - usage_before.ru_nivcsw;
    mprotect_user_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_utime, &usage_after.ru_utime);
    mprotect_sys_cpu_us_delta =
        timeval_delta_us(&usage_before.ru_stime, &usage_after.ru_stime);

    free(threads);
    free(args);
    return worker_touches != 0 ? 0 : -1;
}

static int run_stream_bandwidth(const char* mode, unsigned char* buffer, size_t size,
                                uint64_t* checksum, size_t* touches) {
    size_t passes = env_count_compat("MAI_BENCH_STREAM_PASSES",
                                     "MAI_STREAM_PASSES", 5);
    if (passes == 0) {
        passes = 1;
    }

    size_t elements = size / sizeof(double);
    if (elements == 0 || elements > SIZE_MAX / sizeof(double)) {
        return -1;
    }

    double* a = (double*)buffer;
    double* b = NULL;
    double* c = NULL;
    double* pass_rates = NULL;
    unsigned char* b_buffer = NULL;
    unsigned char* c_buffer = NULL;
    int b_munmap = 0;
    int c_munmap = 0;
    size_t bytes = elements * sizeof(double);
    if (bytes > SIZE_MAX / 10 || passes > SIZE_MAX / (10 * bytes)) {
        return -1;
    }
    if (strcmp(mode, "stream_anon_mmap") == 0 ||
        strcmp(mode, "stream_shared_file") == 0 ||
        strcmp(mode, "stream_private_file") == 0) {
        if (allocate_benchmark_buffer(mode, bytes, &b_buffer, &b_munmap) != 0 ||
            allocate_benchmark_buffer(mode, bytes, &c_buffer, &c_munmap) != 0) {
            free_benchmark_buffer(b_buffer, bytes, b_munmap);
            free_benchmark_buffer(c_buffer, bytes, c_munmap);
            return -1;
        }
        b = (double*)b_buffer;
        c = (double*)c_buffer;
    } else {
        if (posix_memalign((void**)&b, page_size_bytes, bytes) != 0 ||
            posix_memalign((void**)&c, page_size_bytes, bytes) != 0) {
            free(b);
            free(c);
            return -1;
        }
    }
    pass_rates = calloc(passes, sizeof(*pass_rates));
    if (!pass_rates) {
        if (b_buffer || c_buffer) {
            free_benchmark_buffer(b_buffer, bytes, b_munmap);
            free_benchmark_buffer(c_buffer, bytes, c_munmap);
        } else {
            free(b);
            free(c);
        }
        return -1;
    }

    for (size_t i = 0; i < elements; i++) {
        a[i] = 1.0;
        b[i] = 2.0;
        c[i] = 0.0;
    }

    const double scalar = 3.0;
    struct timespec start;
    struct timespec end;

    for (size_t pass = 0; pass < passes; pass++) {
        uint64_t pass_copy_ns;
        uint64_t pass_scale_ns;
        uint64_t pass_add_ns;
        uint64_t pass_triad_ns;

        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (size_t i = 0; i < elements; i++) {
            a[i] = b[i];
        }
        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &end);
        pass_copy_ns = timespec_delta_ns(&start, &end);
        stream_copy_ns += pass_copy_ns;

        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (size_t i = 0; i < elements; i++) {
            b[i] = scalar * a[i];
        }
        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &end);
        pass_scale_ns = timespec_delta_ns(&start, &end);
        stream_scale_ns += pass_scale_ns;

        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (size_t i = 0; i < elements; i++) {
            c[i] = a[i] + b[i];
        }
        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &end);
        pass_add_ns = timespec_delta_ns(&start, &end);
        stream_add_ns += pass_add_ns;

        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (size_t i = 0; i < elements; i++) {
            a[i] = b[i] + scalar * c[i];
        }
        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &end);
        pass_triad_ns = timespec_delta_ns(&start, &end);
        stream_triad_ns += pass_triad_ns;

        uint64_t pass_ns = pass_copy_ns + pass_scale_ns +
            pass_add_ns + pass_triad_ns;
        double pass_mib = (double)(10 * bytes) / (1024.0 * 1024.0);
        pass_rates[pass] = pass_ns != 0 ?
            pass_mib / ((double)pass_ns / 1000000000.0) : 0.0;
    }

    double copy_mib = (double)(2 * bytes * passes) / (1024.0 * 1024.0);
    double scale_mib = (double)(2 * bytes * passes) / (1024.0 * 1024.0);
    double add_mib = (double)(3 * bytes * passes) / (1024.0 * 1024.0);
    double triad_mib = (double)(3 * bytes * passes) / (1024.0 * 1024.0);
    stream_copy_mib_per_sec = stream_copy_ns != 0 ?
        copy_mib / ((double)stream_copy_ns / 1000000000.0) : 0.0;
    stream_scale_mib_per_sec = stream_scale_ns != 0 ?
        scale_mib / ((double)stream_scale_ns / 1000000000.0) : 0.0;
    stream_add_mib_per_sec = stream_add_ns != 0 ?
        add_mib / ((double)stream_add_ns / 1000000000.0) : 0.0;
    stream_triad_mib_per_sec = stream_triad_ns != 0 ?
        triad_mib / ((double)stream_triad_ns / 1000000000.0) : 0.0;

    uint64_t total_ns = stream_copy_ns + stream_scale_ns +
        stream_add_ns + stream_triad_ns;
    double total_mib = copy_mib + scale_mib + add_mib + triad_mib;
    stream_total_mib_per_sec = total_ns != 0 ?
        total_mib / ((double)total_ns / 1000000000.0) : 0.0;
    stream_passes_recorded = passes;
    stream_first_pass_mib_per_sec = pass_rates[0];
    stream_last_pass_mib_per_sec = pass_rates[passes - 1];
    stream_min_pass_mib_per_sec = pass_rates[0];
    stream_max_pass_mib_per_sec = pass_rates[0];
    for (size_t i = 1; i < passes; i++) {
        if (pass_rates[i] < stream_min_pass_mib_per_sec) {
            stream_min_pass_mib_per_sec = pass_rates[i];
        }
        if (pass_rates[i] > stream_max_pass_mib_per_sec) {
            stream_max_pass_mib_per_sec = pass_rates[i];
        }
    }
    qsort(pass_rates, passes, sizeof(*pass_rates), compare_double);
    if (passes % 2 == 0) {
        stream_median_pass_mib_per_sec =
            (pass_rates[passes / 2 - 1] + pass_rates[passes / 2]) / 2.0;
    } else {
        stream_median_pass_mib_per_sec = pass_rates[passes / 2];
    }

    double expected_a = 1.0;
    double expected_b = 2.0;
    double expected_c = 0.0;
    for (size_t pass = 0; pass < passes; pass++) {
        expected_a = expected_b;
        expected_b = scalar * expected_a;
        expected_c = expected_a + expected_b;
        expected_a = expected_b + scalar * expected_c;
    }
    size_t sample_stride = 1024;
    for (size_t i = 0; i < elements; i += sample_stride) {
        double da = a[i] - expected_a;
        double db = b[i] - expected_b;
        double dc = c[i] - expected_c;
        if (da < 0.0) da = -da;
        if (db < 0.0) db = -db;
        if (dc < 0.0) dc = -dc;
        if (da > 0.001 || db > 0.001 || dc > 0.001) {
            if (b_buffer || c_buffer) {
                free_benchmark_buffer(b_buffer, bytes, b_munmap);
                free_benchmark_buffer(c_buffer, bytes, c_munmap);
            } else {
                free(b);
                free(c);
            }
            free(pass_rates);
            return -1;
        }
        *checksum += (uint64_t)a[i] + (uint64_t)b[i] + (uint64_t)c[i];
    }
    logical_bytes = 10 * bytes * passes;
    *touches += logical_bytes / page_size_bytes;
    measured_access_seconds = total_ns != 0 ?
        (double)total_ns / 1000000000.0 : 0.0;

    if (b_buffer || c_buffer) {
        free_benchmark_buffer(b_buffer, bytes, b_munmap);
        free_benchmark_buffer(c_buffer, bytes, c_munmap);
    } else {
        free(b);
        free(c);
    }
    free(pass_rates);
    return 0;
}

static int run_stream_tiled_bandwidth(unsigned char* buffer, size_t size,
                                      uint64_t* checksum, size_t* touches) {
    size_t passes = env_count_compat("MAI_BENCH_STREAM_PASSES",
                                     "MAI_STREAM_PASSES", 5);
    if (passes == 0) {
        passes = 1;
    }

    size_t elements = size / sizeof(double);
    if (elements == 0 || elements > SIZE_MAX / sizeof(double)) {
        return -1;
    }

    double* a = (double*)buffer;
    double* b = NULL;
    double* c = NULL;
    double* pass_rates = NULL;
    size_t bytes = elements * sizeof(double);
    if (bytes > SIZE_MAX / 10 || passes > SIZE_MAX / (10 * bytes)) {
        return -1;
    }

    if (posix_memalign((void**)&b, page_size_bytes, bytes) != 0 ||
        posix_memalign((void**)&c, page_size_bytes, bytes) != 0) {
        free(b);
        free(c);
        return -1;
    }

    pass_rates = calloc(passes, sizeof(*pass_rates));
    if (!pass_rates) {
        free(b);
        free(c);
        return -1;
    }

    size_t tile_bytes = env_size_compat("MAI_BENCH_STREAM_TILE",
                                        "MAI_STREAM_TILE",
                                        2ULL * 1024ULL * 1024ULL);
    if (tile_bytes < page_size_bytes) {
        tile_bytes = page_size_bytes;
    }
    tile_bytes -= tile_bytes % page_size_bytes;
    if (tile_bytes == 0) {
        tile_bytes = page_size_bytes;
    }
    if (tile_bytes > bytes) {
        tile_bytes = bytes;
    }
    tile_bytes -= tile_bytes % sizeof(double);
    if (tile_bytes == 0) {
        free(pass_rates);
        free(b);
        free(c);
        return -1;
    }

    int pure_workload = pure_workload_mode();
    int use_prefetch = !pure_workload &&
        env_count_compat("MAI_BENCH_STREAM_TILE_PREFETCH",
                         "MAI_STREAM_TILE_PREFETCH", 1) != 0;
    int use_prepare_write =
        !pure_workload &&
        env_count_compat("MAI_BENCH_STREAM_TILE_PREPARE_WRITE",
                         "MAI_STREAM_TILE_PREPARE_WRITE", 1) != 0;
    int use_reclaim = env_count_compat("MAI_BENCH_STREAM_TILE_RECLAIM",
                                       "MAI_STREAM_TILE_RECLAIM", 1) != 0 &&
        !pure_workload;
    load_range_ops_optional();
    size_t resident_arrays = choose_stream_resident_arrays(bytes, tile_bytes);
    stream_tile_bytes_recorded = tile_bytes;
    stream_resident_arrays_recorded = resident_arrays;

    const double scalar = 3.0;
    struct timespec start;
    struct timespec end;

    for (size_t pass = 0; pass < passes; pass++) {
        uint64_t pass_copy_ns = 0;
        uint64_t pass_scale_ns = 0;
        uint64_t pass_add_ns = 0;
        uint64_t pass_triad_ns = 0;

        for (size_t offset = 0; offset < bytes; offset += tile_bytes) {
            size_t tile_len = bytes - offset;
            if (tile_len > tile_bytes) {
                tile_len = tile_bytes;
            }
            size_t begin = offset / sizeof(double);
            size_t count = tile_len / sizeof(double);
            if (count == 0) {
                continue;
            }
            double* a_tile = a + begin;
            double* b_tile = b + begin;
            double* c_tile = c + begin;
            void* tiles[3] = {a_tile, b_tile, c_tile};

            if (use_prefetch && pass != 0 && resident_arrays <= 1) {
                if (timed_range_op(prefetch_range, b_tile, tile_len,
                                   &stream_prefetch_ns) != 0) {
                    free(pass_rates);
                    free(b);
                    free(c);
                    return -1;
                }
            }

            if (use_prepare_write && pass != 0) {
                if (resident_arrays == 0 &&
                    timed_range_op(prepare_write_range, a_tile, tile_len,
                                   &stream_prepare_write_ns) != 0) {
                    free(pass_rates);
                    free(b);
                    free(c);
                    return -1;
                }
                if (resident_arrays <= 2 &&
                    timed_range_op(prepare_write_range, c_tile, tile_len,
                                   &stream_prepare_write_ns) != 0) {
                    free(pass_rates);
                    free(b);
                    free(c);
                    return -1;
                }
            }

            if (pass == 0) {
                clock_gettime(CLOCK_MONOTONIC, &start);
                for (size_t i = 0; i < count; i++) {
                    a_tile[i] = 1.0;
                    b_tile[i] = 2.0;
                    c_tile[i] = 0.0;
                }
                clock_gettime(CLOCK_MONOTONIC, &end);
                stream_init_ns += timespec_delta_ns(&start, &end);
            }

            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                a_tile[i] = b_tile[i];
            }
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &end);
            pass_copy_ns += timespec_delta_ns(&start, &end);

            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                b_tile[i] = scalar * a_tile[i];
            }
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &end);
            pass_scale_ns += timespec_delta_ns(&start, &end);

            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                c_tile[i] = a_tile[i] + b_tile[i];
            }
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &end);
            pass_add_ns += timespec_delta_ns(&start, &end);

            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                a_tile[i] = b_tile[i] + scalar * c_tile[i];
            }
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &end);
            pass_triad_ns += timespec_delta_ns(&start, &end);

            if (pass == passes - 1) {
                for (size_t i = 0; i < count; i += 1024) {
                    *checksum += (uint64_t)a_tile[i] +
                        (uint64_t)b_tile[i] + (uint64_t)c_tile[i];
                }
            }

            if (use_reclaim) {
                for (size_t array_index = resident_arrays; array_index < 3;
                     array_index++) {
                    if (timed_range_op(reclaim_range, tiles[array_index],
                                       tile_len, &stream_reclaim_ns) != 0) {
                        free(pass_rates);
                        free(b);
                        free(c);
                        return -1;
                    }
                }
            }

            stream_tiles_recorded++;
        }

        stream_copy_ns += pass_copy_ns;
        stream_scale_ns += pass_scale_ns;
        stream_add_ns += pass_add_ns;
        stream_triad_ns += pass_triad_ns;

        uint64_t pass_ns = pass_copy_ns + pass_scale_ns +
            pass_add_ns + pass_triad_ns;
        double pass_mib = (double)(10 * bytes) / (1024.0 * 1024.0);
        pass_rates[pass] = pass_ns != 0 ?
            pass_mib / ((double)pass_ns / 1000000000.0) : 0.0;
    }

    double copy_mib = (double)(2 * bytes * passes) / (1024.0 * 1024.0);
    double scale_mib = (double)(2 * bytes * passes) / (1024.0 * 1024.0);
    double add_mib = (double)(3 * bytes * passes) / (1024.0 * 1024.0);
    double triad_mib = (double)(3 * bytes * passes) / (1024.0 * 1024.0);
    stream_copy_mib_per_sec = stream_copy_ns != 0 ?
        copy_mib / ((double)stream_copy_ns / 1000000000.0) : 0.0;
    stream_scale_mib_per_sec = stream_scale_ns != 0 ?
        scale_mib / ((double)stream_scale_ns / 1000000000.0) : 0.0;
    stream_add_mib_per_sec = stream_add_ns != 0 ?
        add_mib / ((double)stream_add_ns / 1000000000.0) : 0.0;
    stream_triad_mib_per_sec = stream_triad_ns != 0 ?
        triad_mib / ((double)stream_triad_ns / 1000000000.0) : 0.0;

    uint64_t total_ns = stream_copy_ns + stream_scale_ns +
        stream_add_ns + stream_triad_ns;
    double total_mib = copy_mib + scale_mib + add_mib + triad_mib;
    stream_total_mib_per_sec = total_ns != 0 ?
        total_mib / ((double)total_ns / 1000000000.0) : 0.0;
    stream_passes_recorded = passes;
    stream_first_pass_mib_per_sec = pass_rates[0];
    stream_last_pass_mib_per_sec = pass_rates[passes - 1];
    stream_min_pass_mib_per_sec = pass_rates[0];
    stream_max_pass_mib_per_sec = pass_rates[0];
    for (size_t i = 1; i < passes; i++) {
        if (pass_rates[i] < stream_min_pass_mib_per_sec) {
            stream_min_pass_mib_per_sec = pass_rates[i];
        }
        if (pass_rates[i] > stream_max_pass_mib_per_sec) {
            stream_max_pass_mib_per_sec = pass_rates[i];
        }
    }
    qsort(pass_rates, passes, sizeof(*pass_rates), compare_double);
    if (passes % 2 == 0) {
        stream_median_pass_mib_per_sec =
            (pass_rates[passes / 2 - 1] + pass_rates[passes / 2]) / 2.0;
    } else {
        stream_median_pass_mib_per_sec = pass_rates[passes / 2];
    }

    logical_bytes = 10 * bytes * passes;
    *touches += logical_bytes / page_size_bytes;
    measured_access_seconds = total_ns != 0 ?
        (double)total_ns / 1000000000.0 : 0.0;

    free(b);
    free(c);
    free(pass_rates);
    return 0;
}

enum {
    STREAM_PIPELINE_GROUPS = 3,
    STREAM_PIPELINE_GROUP_WIDTH = 3,
    STREAM_PIPELINE_MATRICES = STREAM_PIPELINE_GROUPS * STREAM_PIPELINE_GROUP_WIDTH
};

static uint64_t stream_pipeline_rng_next(uint64_t* state) {
    *state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
    return *state;
}

static size_t stream_pipeline_rng_mod(uint64_t* state, size_t modulo) {
    if (modulo == 0) {
        return 0;
    }
    return (size_t)((stream_pipeline_rng_next(state) >> 32) % modulo);
}

static int stream_pipeline_build_order(size_t* order, size_t cycles) {
    const char* mode = env_value_compat("MAI_BENCH_STREAM_PIPELINE_ORDER",
                                        "MAI_STREAM_PIPELINE_ORDER");
    if (!mode || mode[0] == '\0') {
        mode = "sequential";
    }

    if (strcmp(mode, "sequential") == 0) {
        stream_pipeline_order_recorded = "sequential";
        for (size_t cycle = 0; cycle < cycles; cycle++) {
            order[cycle] = cycle % STREAM_PIPELINE_GROUPS;
        }
        return 0;
    }

    if (strcmp(mode, "phase_decoy") == 0) {
        static const size_t phase_decoy_pattern[] = {0, 1, 0, 2};
        stream_pipeline_order_recorded = "phase_decoy";
        for (size_t cycle = 0; cycle < cycles; cycle++) {
            order[cycle] =
                phase_decoy_pattern[cycle %
                                    (sizeof(phase_decoy_pattern) /
                                     sizeof(phase_decoy_pattern[0]))];
        }
        return 0;
    }

    if (strcmp(mode, "random") != 0 && strcmp(mode, "random_no_repeat") != 0) {
        return -1;
    }

    size_t seed = env_count_compat("MAI_BENCH_STREAM_PIPELINE_SEED",
                                   "MAI_STREAM_PIPELINE_SEED", 1);
    if (seed == 0) {
        seed = 1;
    }
    stream_pipeline_seed_recorded = seed;
    stream_pipeline_order_recorded =
        strcmp(mode, "random_no_repeat") == 0 ? "random_no_repeat" : "random";

    uint64_t state = (uint64_t)seed;
    size_t current = stream_pipeline_rng_mod(&state, STREAM_PIPELINE_GROUPS);
    for (size_t cycle = 0; cycle < cycles; cycle++) {
        order[cycle] = current;
        if (strcmp(mode, "random_no_repeat") == 0) {
            current = (current + 1 + stream_pipeline_rng_mod(
                           &state, STREAM_PIPELINE_GROUPS - 1)) %
                STREAM_PIPELINE_GROUPS;
        } else {
            current = stream_pipeline_rng_mod(&state, STREAM_PIPELINE_GROUPS);
        }
    }
    return 0;
}

static void stream_pipeline_record_order_sequence(const size_t* order,
                                                  size_t cycles) {
    if (!order || cycles == 0) {
        snprintf(stream_pipeline_order_sequence_recorded,
                 sizeof(stream_pipeline_order_sequence_recorded), "none");
        return;
    }

    size_t offset = 0;
    for (size_t cycle = 0; cycle < cycles; cycle++) {
        int written = snprintf(stream_pipeline_order_sequence_recorded + offset,
                               sizeof(stream_pipeline_order_sequence_recorded) -
                                   offset,
                               "%s%zu", cycle == 0 ? "" : ",", order[cycle]);
        if (written < 0) {
            break;
        }
        size_t used = (size_t)written;
        if (used >= sizeof(stream_pipeline_order_sequence_recorded) - offset) {
            size_t length = sizeof(stream_pipeline_order_sequence_recorded);
            if (length > 4) {
                memcpy(stream_pipeline_order_sequence_recorded + length - 4,
                       "...", 4);
            }
            break;
        }
        offset += used;
    }
}

static int build_submatrix_group_order(size_t* order, size_t cycles,
                                       size_t groups, size_t* hot_groups_out,
                                       double* hot_probability_out) {
    const char* mode = env_value_compat("MAI_BENCH_SUBMATRIX_ORDER",
                                        "MAI_BENCH_STREAM_PIPELINE_ORDER");
    if (!mode || mode[0] == '\0') {
        mode = "sequential";
    }

    size_t seed = env_count_compat("MAI_BENCH_SUBMATRIX_SEED",
                                   "MAI_BENCH_STREAM_PIPELINE_SEED", 1);
    if (seed == 0) {
        seed = 1;
    }
    stream_pipeline_seed_recorded = seed;
    uint64_t state = (uint64_t)seed;

    if (hot_groups_out) {
        *hot_groups_out = 0;
    }
    if (hot_probability_out) {
        *hot_probability_out = 0.0;
    }

    if (strcmp(mode, "sequential") == 0) {
        stream_pipeline_order_recorded = "submatrix_sequential";
        stream_pipeline_prediction_recorded = "submatrix";
        for (size_t cycle = 0; cycle < cycles; cycle++) {
            order[cycle] = cycle % groups;
        }
        return 0;
    }

    if (strcmp(mode, "random") == 0 ||
        strcmp(mode, "random_no_repeat") == 0) {
        int no_repeat = strcmp(mode, "random_no_repeat") == 0;
        stream_pipeline_order_recorded =
            no_repeat ? "submatrix_random_no_repeat" : "submatrix_random";
        stream_pipeline_prediction_recorded = "submatrix_random";
        size_t current = stream_pipeline_rng_mod(&state, groups);
        for (size_t cycle = 0; cycle < cycles; cycle++) {
            order[cycle] = current;
            if (no_repeat && groups > 1) {
                current = (current + 1 +
                           stream_pipeline_rng_mod(&state, groups - 1)) %
                    groups;
            } else {
                current = stream_pipeline_rng_mod(&state, groups);
            }
        }
        return 0;
    }

    if (strcmp(mode, "hotset") == 0 || strcmp(mode, "hot_cold") == 0) {
        size_t hot_groups = env_count("MAI_BENCH_SUBMATRIX_HOT_GROUPS", 1);
        if (hot_groups == 0) {
            hot_groups = 1;
        }
        if (hot_groups > groups) {
            hot_groups = groups;
        }
        double hot_probability =
            env_double("MAI_BENCH_SUBMATRIX_HOT_PROBABILITY", 0.80);
        if (hot_probability > 1.0) {
            hot_probability = 1.0;
        }
        stream_pipeline_order_recorded = "submatrix_hotset";
        stream_pipeline_prediction_recorded = "submatrix_hot_cold";
        if (hot_groups_out) {
            *hot_groups_out = hot_groups;
        }
        if (hot_probability_out) {
            *hot_probability_out = hot_probability;
        }

        for (size_t cycle = 0; cycle < cycles; cycle++) {
            double draw =
                (double)(stream_pipeline_rng_next(&state) >> 11) *
                (1.0 / 9007199254740992.0);
            if (draw < hot_probability || hot_groups == groups) {
                order[cycle] = stream_pipeline_rng_mod(&state, hot_groups);
            } else {
                size_t cold_groups = groups - hot_groups;
                order[cycle] = hot_groups +
                    stream_pipeline_rng_mod(&state, cold_groups);
            }
        }
        return 0;
    }

    return -1;
}

static int stream_pipeline_process_group_phase(double** matrices, size_t group,
                                               size_t bytes, size_t tile_bytes,
                                               int phase, double scalar,
                                               uint64_t* phase_ns) {
    size_t base = group * STREAM_PIPELINE_GROUP_WIDTH;
    double* a = matrices[base];
    double* b = matrices[base + 1];
    double* c = matrices[base + 2];
    struct timespec start;
    struct timespec end;

    for (size_t offset = 0; offset < bytes;) {
        size_t tile_len = bytes - offset;
        if (tile_len > tile_bytes) {
            tile_len = tile_bytes;
        }
        size_t begin = offset / sizeof(double);
        size_t count = tile_len / sizeof(double);
        if (count == 0) {
            offset += tile_len;
            continue;
        }

        if (phase == 0) {
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                a[begin + i] = b[begin + i];
            }
        } else if (phase == 1) {
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                b[begin + i] = scalar * a[begin + i];
            }
        } else if (phase == 2) {
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                c[begin + i] = a[begin + i] + b[begin + i];
            }
        } else {
            benchmark_compiler_barrier();
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                a[begin + i] = b[begin + i] + scalar * c[begin + i];
            }
        }
        benchmark_compiler_barrier();
        clock_gettime(CLOCK_MONOTONIC, &end);
        *phase_ns += timespec_delta_ns(&start, &end);

        stream_tiles_recorded++;
        offset += tile_len;
    }

    return 0;
}

static int stream_pipeline_check_index(double** matrices, size_t group,
                                       size_t index, double expected_a,
                                       double expected_b, double expected_c,
                                       uint64_t* checksum) {
    size_t base = group * STREAM_PIPELINE_GROUP_WIDTH;
    double da = matrices[base][index] - expected_a;
    double db = matrices[base + 1][index] - expected_b;
    double dc = matrices[base + 2][index] - expected_c;
    if (da < 0.0) da = -da;
    if (db < 0.0) db = -db;
    if (dc < 0.0) dc = -dc;
    if (da > 0.001 || db > 0.001 || dc > 0.001) {
        return -1;
    }
    *checksum += (uint64_t)matrices[base][index] +
        (uint64_t)matrices[base + 1][index] +
        (uint64_t)matrices[base + 2][index];
    return 0;
}

static int run_submatrix_stream_pipeline(const char* mode,
                                         unsigned char* buffer, size_t size,
                                         uint64_t* checksum,
                                         size_t* touches) {
    int multi_alloc = mode_allocates_internally(mode);
    size_t cycles =
        env_count_compat("MAI_BENCH_SUBMATRIX_CYCLES",
                         "MAI_BENCH_STREAM_PIPELINE_CYCLES",
                         env_count_compat("MAI_BENCH_STREAM_PASSES",
                                          "MAI_STREAM_PASSES", 12));
    if (cycles == 0) {
        cycles = 1;
    }
    size_t group_iterations =
        env_count_compat("MAI_BENCH_SUBMATRIX_GROUP_ITERATIONS",
                         "MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS", 1);
    if (group_iterations == 0) {
        group_iterations = 1;
    }

    size_t unit_bytes = multi_alloc ?
        env_size("MAI_BENCH_MATRIX_ALLOC_SIZE",
                 env_size("MAI_BENCH_SUBMATRIX_SIZE",
                          2ULL * 1024ULL * 1024ULL * 1024ULL)) :
        env_size("MAI_BENCH_SUBMATRIX_SIZE",
                 2ULL * 1024ULL * 1024ULL * 1024ULL);
    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    if (align_size_to_page(&unit_bytes) != 0 ||
        unit_bytes > size / STREAM_PIPELINE_GROUP_WIDTH) {
        return -1;
    }
    unit_bytes -= unit_bytes % sizeof(double);
    if (unit_bytes == 0) {
        return -1;
    }
    if (!multi_alloc && !buffer) {
        return -1;
    }

    size_t group_bytes = 0;
    if (mul_size(unit_bytes, STREAM_PIPELINE_GROUP_WIDTH, &group_bytes) != 0 ||
        group_bytes == 0) {
        return -1;
    }
    size_t groups = size / group_bytes;
    if (groups == 0 || groups > 1000000) {
        return -1;
    }
    size_t submatrices = 0;
    size_t usable_bytes = 0;
    size_t total_iterations = 0;
    size_t total_logical_factor = 0;
    if (mul_size(groups, STREAM_PIPELINE_GROUP_WIDTH, &submatrices) != 0 ||
        mul_size(groups, group_bytes, &usable_bytes) != 0 ||
        mul_size(cycles, group_iterations, &total_iterations) != 0 ||
        mul_size(total_iterations, 10, &total_logical_factor) != 0 ||
        (unit_bytes != 0 && total_logical_factor > SIZE_MAX / unit_bytes)) {
        return -1;
    }

    double** matrices = calloc(submatrices, sizeof(*matrices));
    unsigned char** matrix_allocs = multi_alloc ?
        calloc(submatrices, sizeof(*matrix_allocs)) : NULL;
    uint64_t* cycle_demand_faults = calloc(cycles, sizeof(*cycle_demand_faults));
    uint64_t* cycle_read_bytes = calloc(cycles, sizeof(*cycle_read_bytes));
    uint64_t* cycle_write_bytes = calloc(cycles, sizeof(*cycle_write_bytes));
    uint64_t* cycle_stall_ns = calloc(cycles, sizeof(*cycle_stall_ns));
    uint64_t* cycle_unused_prefetch_evictions =
        calloc(cycles, sizeof(*cycle_unused_prefetch_evictions));
    double* cycle_rates = calloc(cycles, sizeof(*cycle_rates));
    size_t* group_order = calloc(cycles, sizeof(*group_order));
    size_t* group_visits = calloc(groups, sizeof(*group_visits));
    unsigned char* transition_seen = NULL;
    size_t* transition_counts = NULL;
    int track_transitions = 0;
    int* initialized = calloc(groups, sizeof(*initialized));
    if (!matrices || (multi_alloc && !matrix_allocs) ||
        !cycle_demand_faults || !cycle_read_bytes ||
        !cycle_write_bytes || !cycle_stall_ns ||
        !cycle_unused_prefetch_evictions || !cycle_rates || !group_order ||
        !group_visits || !initialized) {
        free(matrices);
        free(matrix_allocs);
        free(cycle_demand_faults);
        free(cycle_read_bytes);
        free(cycle_write_bytes);
        free(cycle_stall_ns);
        free(cycle_unused_prefetch_evictions);
        free(cycle_rates);
        free(group_order);
        free(group_visits);
        free(initialized);
        return -1;
    }
    const size_t max_transition_cells = 1024 * 1024;
    if (groups <= SIZE_MAX / groups && groups * groups <= max_transition_cells) {
        transition_seen = calloc(groups * groups, sizeof(*transition_seen));
        transition_counts = calloc(groups * groups, sizeof(*transition_counts));
        if (!transition_seen || !transition_counts) {
            free(matrices);
            free(matrix_allocs);
            free(cycle_demand_faults);
            free(cycle_read_bytes);
            free(cycle_write_bytes);
            free(cycle_stall_ns);
            free(cycle_unused_prefetch_evictions);
            free(cycle_rates);
            free(group_order);
            free(group_visits);
            free(initialized);
            free(transition_seen);
            free(transition_counts);
            return -1;
        }
        track_transitions = 1;
    }

    int rc = -1;
    if (multi_alloc) {
        stream_mapping_kind_recorded = "multi_malloc";
        snprintf(stream_backing_path_recorded,
                 sizeof(stream_backing_path_recorded), "%s", "none");
        stream_backing_fs_type = 0;
        stream_backing_is_tmpfs = 0;
        for (size_t matrix = 0; matrix < submatrices; matrix++) {
            matrix_allocs[matrix] = malloc(unit_bytes);
            if (!matrix_allocs[matrix]) {
                goto cleanup;
            }
            matrices[matrix] = (double*)matrix_allocs[matrix];
        }
    } else {
        for (size_t matrix = 0; matrix < submatrices; matrix++) {
            matrices[matrix] = (double*)(buffer + matrix * unit_bytes);
        }
    }

    size_t hot_groups = 0;
    double hot_probability = 0.0;
    if (build_submatrix_group_order(group_order, cycles, groups, &hot_groups,
                                    &hot_probability) != 0) {
        goto cleanup;
    }
    stream_pipeline_record_order_sequence(group_order, cycles);

    size_t tile_bytes = env_size_compat("MAI_BENCH_SUBMATRIX_TILE",
                                        "MAI_BENCH_STREAM_TILE",
                                        2ULL * 1024ULL * 1024ULL);
    if (tile_bytes < page_size_bytes) {
        tile_bytes = page_size_bytes;
    }
    tile_bytes -= tile_bytes % page_size_bytes;
    if (tile_bytes == 0) {
        tile_bytes = page_size_bytes;
    }
    if (tile_bytes > unit_bytes) {
        tile_bytes = unit_bytes;
    }
    tile_bytes -= tile_bytes % sizeof(double);
    if (tile_bytes == 0) {
        goto cleanup;
    }

    stream_tile_bytes_recorded = tile_bytes;
    stream_resident_arrays_recorded = STREAM_PIPELINE_GROUP_WIDTH;
    stream_pipeline_kernels_recorded = 4;
    stream_pipeline_cycles_recorded = cycles;
    stream_pipeline_groups_recorded = groups;
    stream_pipeline_group_iterations_recorded = group_iterations;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    stream_pipeline_group_bytes_recorded = group_bytes;
    stream_pipeline_total_matrix_bytes_recorded = usable_bytes;
    stream_pipeline_unique_cold_visits_recorded = hot_groups;
    stream_pipeline_reclaim_lag_recorded =
        (size_t)(hot_probability * 1000000.0);
    stream_pipeline_reclaim_horizon_recorded =
        env_flag("MAI_BENCH_SUBMATRIX_INIT_ALL", 1) ? 1 : 0;
    size_t migration_chunk =
        env_size("MAI_MIGRATION_CHUNK", 2ULL * 1024ULL * 1024ULL);
    if (migration_chunk < page_size_bytes) {
        migration_chunk = page_size_bytes;
    }
    if (align_size_to_page(&migration_chunk) != 0 || migration_chunk == 0) {
        goto cleanup;
    }
    stream_pipeline_phase_chunks_recorded =
        group_bytes / migration_chunk +
        (group_bytes % migration_chunk != 0 ? 1 : 0);

    const double scalar =
        env_double_compat("MAI_BENCH_SUBMATRIX_SCALAR",
                          "MAI_BENCH_STREAM_PIPELINE_SCALAR", 0.25);
    stream_pipeline_scalar_recorded = scalar;

    struct timespec start;
    struct timespec end;
    int init_all = env_flag("MAI_BENCH_SUBMATRIX_INIT_ALL", 1);
    for (size_t group = 0; group < groups; group++) {
        if (!init_all) {
            break;
        }
        size_t base = group * STREAM_PIPELINE_GROUP_WIDTH;
        for (size_t offset = 0; offset < unit_bytes;) {
            size_t tile_len = unit_bytes - offset;
            if (tile_len > tile_bytes) {
                tile_len = tile_bytes;
            }
            size_t begin = offset / sizeof(double);
            size_t count = tile_len / sizeof(double);
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                matrices[base][begin + i] = 1.0;
                matrices[base + 1][begin + i] = 2.0;
                matrices[base + 2][begin + i] = 0.0;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            stream_init_ns += timespec_delta_ns(&start, &end);
            offset += tile_len;
        }
        initialized[group] = 1;
    }

    size_t cycle_delta_samples = 0;
    MaiStats previous_cycle_stats;
    int cycle_stats_available = 0;
    if (load_stats_optional(&previous_cycle_stats, &cycle_stats_available) != 0) {
        cycle_stats_available = 0;
    }

    for (size_t cycle = 0; cycle < cycles; cycle++) {
        uint64_t cycle_copy_ns = 0;
        uint64_t cycle_scale_ns = 0;
        uint64_t cycle_add_ns = 0;
        uint64_t cycle_triad_ns = 0;
        size_t group = group_order[cycle];
        size_t previous_group = cycle == 0 ? group : group_order[cycle - 1];
        if (group >= groups) {
            goto cleanup;
        }
        if (!initialized[group]) {
            size_t base = group * STREAM_PIPELINE_GROUP_WIDTH;
            for (size_t offset = 0; offset < unit_bytes;) {
                size_t tile_len = unit_bytes - offset;
                if (tile_len > tile_bytes) {
                    tile_len = tile_bytes;
                }
                size_t begin = offset / sizeof(double);
                size_t count = tile_len / sizeof(double);
                clock_gettime(CLOCK_MONOTONIC, &start);
                for (size_t i = 0; i < count; i++) {
                    matrices[base][begin + i] = 1.0;
                    matrices[base + 1][begin + i] = 2.0;
                    matrices[base + 2][begin + i] = 0.0;
                }
                clock_gettime(CLOCK_MONOTONIC, &end);
                stream_init_ns += timespec_delta_ns(&start, &end);
                offset += tile_len;
            }
            initialized[group] = 1;
        }

        group_visits[group]++;
        if (track_transitions && cycle > 0) {
            size_t transition = previous_group * groups + group;
            transition_counts[transition]++;
            if (!transition_seen[transition]) {
                transition_seen[transition] = 1;
                stream_pipeline_unique_transitions_recorded++;
            }
        }

        for (size_t iteration = 0; iteration < group_iterations; iteration++) {
            if (stream_pipeline_process_group_phase(
                    matrices, group, unit_bytes, tile_bytes, 0, scalar,
                    &cycle_copy_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, unit_bytes, tile_bytes, 1, scalar,
                    &cycle_scale_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, unit_bytes, tile_bytes, 2, scalar,
                    &cycle_add_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, unit_bytes, tile_bytes, 3, scalar,
                    &cycle_triad_ns) != 0) {
                goto cleanup;
            }
        }

        stream_copy_ns += cycle_copy_ns;
        stream_scale_ns += cycle_scale_ns;
        stream_add_ns += cycle_add_ns;
        stream_triad_ns += cycle_triad_ns;

        uint64_t cycle_ns = cycle_copy_ns + cycle_scale_ns +
            cycle_add_ns + cycle_triad_ns;
        double cycle_mib =
            10.0 * (double)unit_bytes * (double)group_iterations /
            (1024.0 * 1024.0);
        cycle_rates[cycle] = cycle_ns != 0 ?
            cycle_mib / ((double)cycle_ns / 1000000000.0) : 0.0;

        if (cycle_stats_available) {
            MaiStats cycle_stats;
            int current_stats_available = 0;
            if (load_stats_optional(&cycle_stats,
                                    &current_stats_available) == 0 &&
                current_stats_available) {
                size_t demand_delta =
                    size_delta(cycle_stats.policy_demand_faults,
                               previous_cycle_stats.policy_demand_faults);
                size_t read_delta =
                    size_delta(cycle_stats.policy_migration_read_bytes,
                               previous_cycle_stats.policy_migration_read_bytes);
                size_t write_delta =
                    size_delta(cycle_stats.policy_migration_write_bytes,
                               previous_cycle_stats.policy_migration_write_bytes);
                size_t stall_delta =
                    size_delta(cycle_stats.policy_demand_fault_stall_ns,
                               previous_cycle_stats.policy_demand_fault_stall_ns);
                size_t demotion_delta =
                    size_delta(cycle_stats.policy_demotions,
                               previous_cycle_stats.policy_demotions);
                size_t hot_evicted_delta =
                    size_delta(cycle_stats.policy_evicted_hot_bytes,
                               previous_cycle_stats.policy_evicted_hot_bytes);
                size_t unused_prefetch_delta =
                    size_delta(cycle_stats.policy_prefetch_unused_evictions,
                               previous_cycle_stats.policy_prefetch_unused_evictions);

                cycle_demand_faults[cycle_delta_samples] = demand_delta;
                if (demand_delta >
                    stream_pipeline_max_cycle_policy_demand_faults) {
                    stream_pipeline_max_cycle_policy_demand_faults =
                        demand_delta;
                }
                cycle_read_bytes[cycle_delta_samples] = read_delta;
                if (read_delta > stream_pipeline_max_cycle_policy_read_bytes) {
                    stream_pipeline_max_cycle_policy_read_bytes = read_delta;
                }
                cycle_write_bytes[cycle_delta_samples] = write_delta;
                if (write_delta > stream_pipeline_max_cycle_policy_write_bytes) {
                    stream_pipeline_max_cycle_policy_write_bytes = write_delta;
                }
                cycle_stall_ns[cycle_delta_samples] = stall_delta;
                if (stall_delta > stream_pipeline_max_cycle_policy_stall_ns) {
                    stream_pipeline_max_cycle_policy_stall_ns = stall_delta;
                    stream_pipeline_worst_cycle_index_recorded = cycle;
                    stream_pipeline_worst_cycle_group_recorded = group;
                    stream_pipeline_worst_cycle_prev_group_recorded =
                        previous_group;
                }
                if (demotion_delta > stream_pipeline_max_cycle_policy_demotions) {
                    stream_pipeline_max_cycle_policy_demotions = demotion_delta;
                }
                if (hot_evicted_delta >
                    stream_pipeline_max_cycle_policy_hot_evicted_bytes) {
                    stream_pipeline_max_cycle_policy_hot_evicted_bytes =
                        hot_evicted_delta;
                }
                cycle_unused_prefetch_evictions[cycle_delta_samples] =
                    unused_prefetch_delta;
                cycle_delta_samples++;
                previous_cycle_stats = cycle_stats;
            } else {
                cycle_stats_available = 0;
            }
        }
    }

    for (size_t group = 0; group < groups; group++) {
        stream_pipeline_group_visits_recorded += group_visits[group];
    }
    stream_pipeline_group_visit_0_recorded = groups > 0 ? group_visits[0] : 0;
    stream_pipeline_group_visit_1_recorded = groups > 1 ? group_visits[1] : 0;
    stream_pipeline_group_visit_2_recorded = groups > 2 ? group_visits[2] : 0;
    stream_pipeline_transition_00_recorded =
        track_transitions && groups > 0 ? transition_counts[0 * groups + 0] : 0;
    stream_pipeline_transition_01_recorded =
        track_transitions && groups > 1 ? transition_counts[0 * groups + 1] : 0;
    stream_pipeline_transition_02_recorded =
        track_transitions && groups > 2 ? transition_counts[0 * groups + 2] : 0;
    stream_pipeline_transition_10_recorded =
        track_transitions && groups > 1 ? transition_counts[1 * groups + 0] : 0;
    stream_pipeline_transition_11_recorded =
        track_transitions && groups > 1 ? transition_counts[1 * groups + 1] : 0;
    stream_pipeline_transition_12_recorded =
        track_transitions && groups > 2 ? transition_counts[1 * groups + 2] : 0;
    stream_pipeline_transition_20_recorded =
        track_transitions && groups > 2 ? transition_counts[2 * groups + 0] : 0;
    stream_pipeline_transition_21_recorded =
        track_transitions && groups > 2 ? transition_counts[2 * groups + 1] : 0;
    stream_pipeline_transition_22_recorded =
        track_transitions && groups > 2 ? transition_counts[2 * groups + 2] : 0;

    if (cycle_delta_samples != 0) {
        stream_pipeline_cycle_policy_demand_faults_p50 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_demand_faults_p90 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_demand_faults_p99 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_read_bytes_p50 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_read_bytes_p90 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_read_bytes_p99 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_write_bytes_p50 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_write_bytes_p90 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_write_bytes_p99 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_stall_ns_p50 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_stall_ns_p90 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_stall_ns_p99 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p50 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p90 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p99 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 99);
    }

    double copy_mib =
        2.0 * (double)unit_bytes * (double)total_iterations /
        (1024.0 * 1024.0);
    double scale_mib = copy_mib;
    double add_mib =
        3.0 * (double)unit_bytes * (double)total_iterations /
        (1024.0 * 1024.0);
    double triad_mib = add_mib;
    stream_copy_mib_per_sec = stream_copy_ns != 0 ?
        copy_mib / ((double)stream_copy_ns / 1000000000.0) : 0.0;
    stream_scale_mib_per_sec = stream_scale_ns != 0 ?
        scale_mib / ((double)stream_scale_ns / 1000000000.0) : 0.0;
    stream_add_mib_per_sec = stream_add_ns != 0 ?
        add_mib / ((double)stream_add_ns / 1000000000.0) : 0.0;
    stream_triad_mib_per_sec = stream_triad_ns != 0 ?
        triad_mib / ((double)stream_triad_ns / 1000000000.0) : 0.0;

    uint64_t total_ns = stream_copy_ns + stream_scale_ns +
        stream_add_ns + stream_triad_ns;
    double total_mib = copy_mib + scale_mib + add_mib + triad_mib;
    stream_total_mib_per_sec = total_ns != 0 ?
        total_mib / ((double)total_ns / 1000000000.0) : 0.0;
    stream_passes_recorded = cycles;
    stream_first_pass_mib_per_sec = cycle_rates[0];
    stream_last_pass_mib_per_sec = cycle_rates[cycles - 1];
    stream_min_pass_mib_per_sec = cycle_rates[0];
    stream_max_pass_mib_per_sec = cycle_rates[0];
    for (size_t i = 1; i < cycles; i++) {
        if (cycle_rates[i] < stream_min_pass_mib_per_sec) {
            stream_min_pass_mib_per_sec = cycle_rates[i];
        }
        if (cycle_rates[i] > stream_max_pass_mib_per_sec) {
            stream_max_pass_mib_per_sec = cycle_rates[i];
        }
    }
    qsort(cycle_rates, cycles, sizeof(*cycle_rates), compare_double);
    if (cycles % 2 == 0) {
        stream_median_pass_mib_per_sec =
            (cycle_rates[cycles / 2 - 1] + cycle_rates[cycles / 2]) / 2.0;
    } else {
        stream_median_pass_mib_per_sec = cycle_rates[cycles / 2];
    }

    logical_bytes = total_logical_factor * unit_bytes;
    *touches += logical_bytes / page_size_bytes;
    measured_access_seconds = total_ns != 0 ?
        (double)total_ns / 1000000000.0 : 0.0;

    for (size_t group = 0; group < groups; group++) {
        if (!initialized[group] || group_visits[group] == 0) {
            continue;
        }
        size_t iterations = group_visits[group] * group_iterations;
        double expected_a = 1.0;
        double expected_b = 2.0;
        double expected_c = 0.0;
        for (size_t iteration = 0; iteration < iterations; iteration++) {
            expected_a = expected_b;
            expected_b = scalar * expected_a;
            expected_c = expected_a + expected_b;
            expected_a = expected_b + scalar * expected_c;
        }

        size_t sample_stride = unit_bytes / sizeof(double) / 4;
        if (sample_stride == 0) {
            sample_stride = 1;
        }
        for (size_t sample = 0; sample < 4; sample++) {
            size_t index = sample * sample_stride;
            size_t elements = unit_bytes / sizeof(double);
            if (index >= elements) {
                index = elements - 1;
            }
            if (stream_pipeline_check_index(matrices, group, index,
                                            expected_a, expected_b,
                                            expected_c, checksum) != 0) {
                goto cleanup;
            }
        }
    }

    rc = 0;

cleanup:
    if (matrix_allocs) {
        for (size_t matrix = 0; matrix < submatrices; matrix++) {
            free(matrix_allocs[matrix]);
        }
    }
    free(matrices);
    free(matrix_allocs);
    free(cycle_demand_faults);
    free(cycle_read_bytes);
    free(cycle_write_bytes);
    free(cycle_stall_ns);
    free(cycle_unused_prefetch_evictions);
    free(cycle_rates);
    free(group_order);
    free(group_visits);
    free(transition_seen);
    free(transition_counts);
    free(initialized);
    return rc;
}

static int run_policy_multistream_stride(unsigned char* buffer, size_t size,
                                         uint64_t* checksum,
                                         size_t* touches) {
    size_t streams = env_count("MAI_BENCH_POLICY_STREAMS", 4);
    size_t active_streams =
        env_count("MAI_BENCH_POLICY_ACTIVE_STREAMS", streams);
    size_t passes = env_count_compat("MAI_BENCH_POLICY_PASSES",
                                     "MAI_BENCH_STREAM_PASSES", 3);
    size_t unit_bytes =
        env_size("MAI_BENCH_POLICY_STRIDE_UNIT", 2ULL * 1024ULL * 1024ULL);

    if (streams == 0) {
        streams = 1;
    }
    if (passes == 0) {
        passes = 1;
    }
    if (unit_bytes < page_size_bytes) {
        unit_bytes = page_size_bytes;
    }
    unit_bytes -= unit_bytes % page_size_bytes;
    if (unit_bytes == 0 || unit_bytes > size) {
        return -1;
    }

    size_t units = size / unit_bytes;
    if (units == 0) {
        return -1;
    }
    if (streams > units) {
        streams = units;
    }
    if (active_streams == 0 || active_streams > streams) {
        active_streams = streams;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t pass = 0; pass < passes; pass++) {
        for (size_t stream = 0; stream < active_streams; stream++) {
            for (size_t step = 0; step < units; step++) {
                size_t unit = stream + step * streams;
                if (unit >= units) {
                    continue;
                }
                size_t offset = unit * unit_bytes;
                unsigned char value = expected_byte(unit, pass);
                buffer[offset] = value;
                *checksum += value;
                (*touches)++;
            }
        }
        for (size_t stream = 0; stream < active_streams; stream++) {
            for (size_t step = 0; step < units; step++) {
                size_t unit = stream + step * streams;
                if (unit >= units) {
                    continue;
                }
                size_t offset = unit * unit_bytes;
                unsigned char expected = expected_byte(unit, pass);
                if (buffer[offset] != expected) {
                    return -1;
                }
                *checksum += buffer[offset];
                (*touches)++;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    measured_access_seconds = seconds_since(&start, &end);
    if (mul_size(*touches, unit_bytes, &logical_bytes) != 0 ||
        mul_size(units, unit_bytes,
                 &stream_pipeline_total_matrix_bytes_recorded) != 0) {
        return -1;
    }
    stream_pipeline_prediction_recorded = "stride";
    stream_pipeline_groups_recorded = streams;
    stream_pipeline_group_visits_recorded = active_streams;
    stream_pipeline_order_recorded = "strided_streams";
    stream_pipeline_group_iterations_recorded = passes;
    stream_pipeline_matrix_bytes_recorded = unit_bytes;
    return 0;
}

static int run_stream_kernel_pipeline(const char* mode, unsigned char* buffer,
                                      size_t size, uint64_t* checksum,
                                      size_t* touches) {
    size_t cycles =
        env_count_compat("MAI_BENCH_STREAM_PIPELINE_CYCLES",
                         "MAI_STREAM_PIPELINE_CYCLES",
                         env_count_compat("MAI_BENCH_STREAM_PASSES",
                                          "MAI_STREAM_PASSES", 3));
    if (cycles == 0) {
        cycles = 1;
    }
    size_t group_iterations =
        env_count_compat("MAI_BENCH_STREAM_PIPELINE_GROUP_ITERATIONS",
                         "MAI_STREAM_PIPELINE_GROUP_ITERATIONS", 4);
    if (group_iterations == 0) {
        group_iterations = 1;
    }

    size_t elements = size / sizeof(double);
    if (elements == 0 || elements > SIZE_MAX / sizeof(double)) {
        return -1;
    }
    size_t bytes = elements * sizeof(double);
    size_t total_iterations = 0;
    size_t total_group_bytes = 0;
    size_t total_matrix_bytes = 0;
    size_t total_logical_factor = 0;
    if (mul_size(cycles, group_iterations, &total_iterations) != 0 ||
        mul_size(bytes, STREAM_PIPELINE_GROUP_WIDTH, &total_group_bytes) != 0 ||
        mul_size(bytes, STREAM_PIPELINE_MATRICES, &total_matrix_bytes) != 0 ||
        mul_size(total_iterations, 10, &total_logical_factor) != 0 ||
        (bytes != 0 && total_logical_factor > SIZE_MAX / bytes)) {
        return -1;
    }

    double* matrices[STREAM_PIPELINE_MATRICES] = {0};
    unsigned char* matrix_buffers[STREAM_PIPELINE_MATRICES] = {0};
    int matrix_munmap[STREAM_PIPELINE_MATRICES] = {0};
    double* cycle_rates = NULL;
    uint64_t* cycle_demand_faults = NULL;
    uint64_t* cycle_read_bytes = NULL;
    uint64_t* cycle_write_bytes = NULL;
    uint64_t* cycle_stall_ns = NULL;
    uint64_t* cycle_unused_prefetch_evictions = NULL;
    size_t* group_order = NULL;
    int rc = -1;
    matrices[0] = (double*)buffer;
    matrix_buffers[0] = buffer;
    for (size_t matrix = 1; matrix < STREAM_PIPELINE_MATRICES; matrix++) {
        if (allocate_benchmark_buffer(mode, bytes, &matrix_buffers[matrix],
                                      &matrix_munmap[matrix]) != 0 ||
            !matrix_buffers[matrix]) {
            goto cleanup;
        }
        matrices[matrix] = (double*)matrix_buffers[matrix];
    }

    cycle_rates = calloc(cycles, sizeof(*cycle_rates));
    cycle_demand_faults = calloc(cycles, sizeof(*cycle_demand_faults));
    cycle_read_bytes = calloc(cycles, sizeof(*cycle_read_bytes));
    cycle_write_bytes = calloc(cycles, sizeof(*cycle_write_bytes));
    cycle_stall_ns = calloc(cycles, sizeof(*cycle_stall_ns));
    cycle_unused_prefetch_evictions =
        calloc(cycles, sizeof(*cycle_unused_prefetch_evictions));
    if (!cycle_rates || !cycle_demand_faults || !cycle_read_bytes ||
        !cycle_write_bytes || !cycle_stall_ns ||
        !cycle_unused_prefetch_evictions) {
        goto cleanup;
    }
    group_order = calloc(cycles, sizeof(*group_order));
    if (!group_order || stream_pipeline_build_order(group_order, cycles) != 0) {
        goto cleanup;
    }
    stream_pipeline_record_order_sequence(group_order, cycles);

    size_t tile_bytes = env_size_compat("MAI_BENCH_STREAM_TILE",
                                        "MAI_STREAM_TILE",
                                        2ULL * 1024ULL * 1024ULL);
    if (tile_bytes < page_size_bytes) {
        tile_bytes = page_size_bytes;
    }
    tile_bytes -= tile_bytes % page_size_bytes;
    if (tile_bytes == 0) {
        tile_bytes = page_size_bytes;
    }
    if (tile_bytes > bytes) {
        tile_bytes = bytes;
    }
    tile_bytes -= tile_bytes % sizeof(double);
    if (tile_bytes == 0) {
        goto cleanup;
    }

    stream_pipeline_prediction_recorded = "none";

    stream_tile_bytes_recorded = tile_bytes;
    stream_resident_arrays_recorded = STREAM_PIPELINE_GROUP_WIDTH;
    stream_pipeline_kernels_recorded = 4;
    stream_pipeline_cycles_recorded = cycles;
    stream_pipeline_group_visits_recorded = 0;
    stream_pipeline_groups_recorded = STREAM_PIPELINE_GROUPS;
    stream_pipeline_group_iterations_recorded = group_iterations;
    stream_pipeline_matrix_bytes_recorded = bytes;
    stream_pipeline_group_bytes_recorded = total_group_bytes;
    stream_pipeline_total_matrix_bytes_recorded = total_matrix_bytes;
    stream_pipeline_reclaim_lag_recorded = 0;
    stream_pipeline_reclaim_horizon_recorded = 0;
    size_t migration_chunk =
        env_size("MAI_MIGRATION_CHUNK", 2ULL * 1024ULL * 1024ULL);
    if (migration_chunk < page_size_bytes) {
        migration_chunk = page_size_bytes;
    }
    if (align_size_to_page(&migration_chunk) != 0 || migration_chunk == 0) {
        goto cleanup;
    }
    stream_pipeline_phase_chunks_recorded =
        total_group_bytes / migration_chunk +
        (total_group_bytes % migration_chunk != 0 ? 1 : 0);

    const double scalar =
        env_double_compat("MAI_BENCH_STREAM_PIPELINE_SCALAR",
                          "MAI_STREAM_PIPELINE_SCALAR", 0.25);
    stream_pipeline_scalar_recorded = scalar;
    struct timespec start;
    struct timespec end;

    for (size_t group = 0; group < STREAM_PIPELINE_GROUPS; group++) {
        size_t base = group * STREAM_PIPELINE_GROUP_WIDTH;
        for (size_t offset = 0; offset < bytes;) {
            size_t tile_len = bytes - offset;
            if (tile_len > tile_bytes) {
                tile_len = tile_bytes;
            }
            size_t begin = offset / sizeof(double);
            size_t count = tile_len / sizeof(double);
            if (count == 0) {
                offset += tile_len;
                continue;
            }

            clock_gettime(CLOCK_MONOTONIC, &start);
            for (size_t i = 0; i < count; i++) {
                matrices[base][begin + i] = 1.0;
                matrices[base + 1][begin + i] = 2.0;
                matrices[base + 2][begin + i] = 0.0;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            stream_init_ns += timespec_delta_ns(&start, &end);
            offset += tile_len;
        }
    }

    size_t group_visits[STREAM_PIPELINE_GROUPS] = {0};
    size_t transition_counts[STREAM_PIPELINE_GROUPS][STREAM_PIPELINE_GROUPS] = {{0}};
    unsigned char transition_seen[STREAM_PIPELINE_GROUPS][STREAM_PIPELINE_GROUPS] = {{0}};
    size_t cycle_delta_samples = 0;
    MaiStats previous_cycle_stats;
    int cycle_stats_available = 0;
    if (load_stats_optional(&previous_cycle_stats, &cycle_stats_available) != 0) {
        cycle_stats_available = 0;
    }

    for (size_t cycle = 0; cycle < cycles; cycle++) {
        uint64_t cycle_copy_ns = 0;
        uint64_t cycle_scale_ns = 0;
        uint64_t cycle_add_ns = 0;
        uint64_t cycle_triad_ns = 0;
        size_t group = group_order[cycle];
        size_t previous_group = cycle == 0 ? group : group_order[cycle - 1];
        int phase_decoy_order =
            strcmp(stream_pipeline_order_recorded, "phase_decoy") == 0;
        int phase_return_cycle =
            phase_decoy_order && cycle > 0 && group == 0 && previous_group != 0;
        int phase_decoy_cycle = phase_decoy_order && group != 0;
        size_t transition_count_after = 0;
        if (phase_return_cycle) {
            stream_pipeline_phase_return_cycles_recorded++;
        } else if (phase_decoy_cycle) {
            stream_pipeline_phase_decoy_cycles_recorded++;
        }
        if (group < STREAM_PIPELINE_GROUPS) {
            group_visits[group]++;
            if (cycle > 0 && previous_group < STREAM_PIPELINE_GROUPS) {
                transition_counts[previous_group][group]++;
                transition_count_after =
                    transition_counts[previous_group][group];
                if (!transition_seen[previous_group][group]) {
                    transition_seen[previous_group][group] = 1;
                    stream_pipeline_unique_transitions_recorded++;
                }
            }
        }
        int phase_warm_return_cycle =
            phase_return_cycle && transition_count_after > 1;
        if (phase_warm_return_cycle) {
            stream_pipeline_phase_warm_return_cycles_recorded++;
        }

        for (size_t iteration = 0; iteration < group_iterations; iteration++) {
            if (stream_pipeline_process_group_phase(
                    matrices, group, bytes, tile_bytes, 0, scalar,
                    &cycle_copy_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, bytes, tile_bytes, 1, scalar,
                    &cycle_scale_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, bytes, tile_bytes, 2, scalar,
                    &cycle_add_ns) != 0 ||
                stream_pipeline_process_group_phase(
                    matrices, group, bytes, tile_bytes, 3, scalar,
                    &cycle_triad_ns) != 0) {
                goto cleanup;
            }
        }

        stream_copy_ns += cycle_copy_ns;
        stream_scale_ns += cycle_scale_ns;
        stream_add_ns += cycle_add_ns;
        stream_triad_ns += cycle_triad_ns;

        uint64_t cycle_ns = cycle_copy_ns + cycle_scale_ns + cycle_add_ns +
            cycle_triad_ns;
        double cycle_mib =
            10.0 * (double)bytes * (double)group_iterations /
            (1024.0 * 1024.0);
        cycle_rates[cycle] = cycle_ns != 0 ?
            cycle_mib / ((double)cycle_ns / 1000000000.0) : 0.0;
        if (cycle_stats_available) {
            MaiStats cycle_stats;
            int current_stats_available = 0;
            if (load_stats_optional(&cycle_stats, &current_stats_available) == 0 &&
                current_stats_available) {
                size_t demand_delta =
                    size_delta(cycle_stats.policy_demand_faults,
                               previous_cycle_stats.policy_demand_faults);
                size_t read_delta =
                    size_delta(cycle_stats.policy_migration_read_bytes,
                               previous_cycle_stats.policy_migration_read_bytes);
                size_t write_delta =
                    size_delta(cycle_stats.policy_migration_write_bytes,
                               previous_cycle_stats.policy_migration_write_bytes);
                size_t stall_delta =
                    size_delta(cycle_stats.policy_demand_fault_stall_ns,
                               previous_cycle_stats.policy_demand_fault_stall_ns);
                size_t demotion_delta =
                    size_delta(cycle_stats.policy_demotions,
                               previous_cycle_stats.policy_demotions);
                size_t hot_evicted_delta =
                    size_delta(cycle_stats.policy_evicted_hot_bytes,
                               previous_cycle_stats.policy_evicted_hot_bytes);
                size_t unused_prefetch_delta =
                    size_delta(cycle_stats.policy_prefetch_unused_evictions,
                               previous_cycle_stats.policy_prefetch_unused_evictions);

                cycle_demand_faults[cycle_delta_samples] = demand_delta;
                if (demand_delta >
                    stream_pipeline_max_cycle_policy_demand_faults) {
                    stream_pipeline_max_cycle_policy_demand_faults =
                        demand_delta;
                }
                cycle_read_bytes[cycle_delta_samples] = read_delta;
                if (read_delta > stream_pipeline_max_cycle_policy_read_bytes) {
                    stream_pipeline_max_cycle_policy_read_bytes = read_delta;
                }
                cycle_write_bytes[cycle_delta_samples] = write_delta;
                if (write_delta > stream_pipeline_max_cycle_policy_write_bytes) {
                    stream_pipeline_max_cycle_policy_write_bytes = write_delta;
                }
                cycle_stall_ns[cycle_delta_samples] = stall_delta;
                if (stall_delta > stream_pipeline_max_cycle_policy_stall_ns) {
                    stream_pipeline_max_cycle_policy_stall_ns = stall_delta;
                    stream_pipeline_worst_cycle_index_recorded = cycle;
                    stream_pipeline_worst_cycle_group_recorded = group;
                    stream_pipeline_worst_cycle_prev_group_recorded =
                        previous_group;
                }
                if (demotion_delta > stream_pipeline_max_cycle_policy_demotions) {
                    stream_pipeline_max_cycle_policy_demotions = demotion_delta;
                }
                if (hot_evicted_delta >
                    stream_pipeline_max_cycle_policy_hot_evicted_bytes) {
                    stream_pipeline_max_cycle_policy_hot_evicted_bytes =
                        hot_evicted_delta;
                }
                cycle_unused_prefetch_evictions[cycle_delta_samples] =
                    unused_prefetch_delta;
                if (phase_decoy_order) {
                    if (phase_return_cycle) {
                        stream_pipeline_phase_return_policy_demand_faults +=
                            demand_delta;
                        stream_pipeline_phase_return_policy_read_bytes +=
                            read_delta;
                        stream_pipeline_phase_return_policy_write_bytes +=
                            write_delta;
                        stream_pipeline_phase_return_policy_stall_ns +=
                            stall_delta;
                        stream_pipeline_phase_return_policy_hot_evicted_bytes +=
                            hot_evicted_delta;
                        stream_pipeline_phase_return_policy_unused_prefetch_evictions +=
                            unused_prefetch_delta;
                        if (phase_warm_return_cycle) {
                            stream_pipeline_phase_warm_return_policy_demand_faults +=
                                demand_delta;
                            stream_pipeline_phase_warm_return_policy_read_bytes +=
                                read_delta;
                            stream_pipeline_phase_warm_return_policy_write_bytes +=
                                write_delta;
                            stream_pipeline_phase_warm_return_policy_stall_ns +=
                                stall_delta;
                            stream_pipeline_phase_warm_return_policy_hot_evicted_bytes +=
                                hot_evicted_delta;
                            stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions +=
                                unused_prefetch_delta;
                        }
                    } else if (phase_decoy_cycle) {
                        stream_pipeline_phase_decoy_policy_demand_faults +=
                            demand_delta;
                        stream_pipeline_phase_decoy_policy_read_bytes +=
                            read_delta;
                        stream_pipeline_phase_decoy_policy_write_bytes +=
                            write_delta;
                        stream_pipeline_phase_decoy_policy_stall_ns +=
                            stall_delta;
                        stream_pipeline_phase_decoy_policy_hot_evicted_bytes +=
                            hot_evicted_delta;
                        stream_pipeline_phase_decoy_policy_unused_prefetch_evictions +=
                            unused_prefetch_delta;
                    }
                }
                cycle_delta_samples++;
                previous_cycle_stats = cycle_stats;
            } else {
                cycle_stats_available = 0;
            }
        }
    }

    stream_pipeline_group_visit_0_recorded = group_visits[0];
    stream_pipeline_group_visit_1_recorded = group_visits[1];
    stream_pipeline_group_visit_2_recorded = group_visits[2];
    stream_pipeline_transition_00_recorded = transition_counts[0][0];
    stream_pipeline_transition_01_recorded = transition_counts[0][1];
    stream_pipeline_transition_02_recorded = transition_counts[0][2];
    stream_pipeline_transition_10_recorded = transition_counts[1][0];
    stream_pipeline_transition_11_recorded = transition_counts[1][1];
    stream_pipeline_transition_12_recorded = transition_counts[1][2];
    stream_pipeline_transition_20_recorded = transition_counts[2][0];
    stream_pipeline_transition_21_recorded = transition_counts[2][1];
    stream_pipeline_transition_22_recorded = transition_counts[2][2];

    if (cycle_delta_samples != 0) {
        stream_pipeline_cycle_policy_demand_faults_p50 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_demand_faults_p90 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_demand_faults_p99 =
            (size_t)percentile_u64(cycle_demand_faults, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_read_bytes_p50 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_read_bytes_p90 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_read_bytes_p99 =
            (size_t)percentile_u64(cycle_read_bytes, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_write_bytes_p50 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_write_bytes_p90 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_write_bytes_p99 =
            (size_t)percentile_u64(cycle_write_bytes, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_stall_ns_p50 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_stall_ns_p90 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_stall_ns_p99 =
            (size_t)percentile_u64(cycle_stall_ns, cycle_delta_samples, 99);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p50 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 50);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p90 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 90);
        stream_pipeline_cycle_policy_unused_prefetch_evictions_p99 =
            (size_t)percentile_u64(cycle_unused_prefetch_evictions,
                                   cycle_delta_samples, 99);
    }
    size_t phase_return_expected_chunks = 0;
    if (stream_pipeline_phase_chunks_recorded != 0 &&
        stream_pipeline_phase_return_cycles_recorded <=
            SIZE_MAX / stream_pipeline_phase_chunks_recorded) {
        phase_return_expected_chunks =
            stream_pipeline_phase_return_cycles_recorded *
            stream_pipeline_phase_chunks_recorded;
    }
    if (phase_return_expected_chunks >
        stream_pipeline_phase_return_policy_demand_faults) {
        stream_pipeline_phase_return_estimated_hits =
            phase_return_expected_chunks -
            stream_pipeline_phase_return_policy_demand_faults;
    }
    stream_pipeline_phase_return_estimated_hit_ratio =
        phase_return_expected_chunks != 0 ?
        (double)stream_pipeline_phase_return_estimated_hits /
            (double)phase_return_expected_chunks :
        0.0;
    size_t phase_warm_return_expected_chunks = 0;
    if (stream_pipeline_phase_chunks_recorded != 0 &&
        stream_pipeline_phase_warm_return_cycles_recorded <=
            SIZE_MAX / stream_pipeline_phase_chunks_recorded) {
        phase_warm_return_expected_chunks =
            stream_pipeline_phase_warm_return_cycles_recorded *
            stream_pipeline_phase_chunks_recorded;
    }
    if (phase_warm_return_expected_chunks >
        stream_pipeline_phase_warm_return_policy_demand_faults) {
        stream_pipeline_phase_warm_return_estimated_hits =
            phase_warm_return_expected_chunks -
            stream_pipeline_phase_warm_return_policy_demand_faults;
    }
    stream_pipeline_phase_warm_return_estimated_hit_ratio =
        phase_warm_return_expected_chunks != 0 ?
        (double)stream_pipeline_phase_warm_return_estimated_hits /
            (double)phase_warm_return_expected_chunks :
        0.0;

    double copy_mib =
        2.0 * (double)bytes * (double)total_iterations / (1024.0 * 1024.0);
    double scale_mib =
        2.0 * (double)bytes * (double)total_iterations / (1024.0 * 1024.0);
    double add_mib =
        3.0 * (double)bytes * (double)total_iterations / (1024.0 * 1024.0);
    double triad_mib =
        3.0 * (double)bytes * (double)total_iterations / (1024.0 * 1024.0);
    stream_copy_mib_per_sec = stream_copy_ns != 0 ?
        copy_mib / ((double)stream_copy_ns / 1000000000.0) : 0.0;
    stream_scale_mib_per_sec = stream_scale_ns != 0 ?
        scale_mib / ((double)stream_scale_ns / 1000000000.0) : 0.0;
    stream_add_mib_per_sec = stream_add_ns != 0 ?
        add_mib / ((double)stream_add_ns / 1000000000.0) : 0.0;
    stream_triad_mib_per_sec = stream_triad_ns != 0 ?
        triad_mib / ((double)stream_triad_ns / 1000000000.0) : 0.0;

    uint64_t total_ns = stream_copy_ns + stream_scale_ns + stream_add_ns +
        stream_triad_ns;
    double total_mib = copy_mib + scale_mib + add_mib + triad_mib;
    stream_total_mib_per_sec = total_ns != 0 ?
        total_mib / ((double)total_ns / 1000000000.0) : 0.0;
    stream_passes_recorded = cycles;
    stream_first_pass_mib_per_sec = cycle_rates[0];
    stream_last_pass_mib_per_sec = cycle_rates[cycles - 1];
    stream_min_pass_mib_per_sec = cycle_rates[0];
    stream_max_pass_mib_per_sec = cycle_rates[0];
    for (size_t i = 1; i < cycles; i++) {
        if (cycle_rates[i] < stream_min_pass_mib_per_sec) {
            stream_min_pass_mib_per_sec = cycle_rates[i];
        }
        if (cycle_rates[i] > stream_max_pass_mib_per_sec) {
            stream_max_pass_mib_per_sec = cycle_rates[i];
        }
    }
    qsort(cycle_rates, cycles, sizeof(*cycle_rates), compare_double);
    if (cycles % 2 == 0) {
        stream_median_pass_mib_per_sec =
            (cycle_rates[cycles / 2 - 1] + cycle_rates[cycles / 2]) / 2.0;
    } else {
        stream_median_pass_mib_per_sec = cycle_rates[cycles / 2];
    }

    logical_bytes = total_logical_factor * bytes;
    *touches += logical_bytes / page_size_bytes;
    measured_access_seconds = total_ns != 0 ?
        (double)total_ns / 1000000000.0 : 0.0;

    for (size_t group = 0; group < STREAM_PIPELINE_GROUPS; group++) {
        size_t visits = group_visits[group];
        stream_pipeline_group_visits_recorded += visits;
        size_t iterations = visits * group_iterations;
        double expected_a = 1.0;
        double expected_b = 2.0;
        double expected_c = 0.0;
        for (size_t iteration = 0; iteration < iterations; iteration++) {
            expected_a = expected_b;
            expected_b = scalar * expected_a;
            expected_c = expected_a + expected_b;
            expected_a = expected_b + scalar * expected_c;
        }
        size_t sample_stride = page_size_bytes / sizeof(double);
        if (sample_stride == 0) {
            sample_stride = 1;
        }
        for (size_t i = 0; i < elements; i += sample_stride) {
            if (stream_pipeline_check_index(matrices, group, i, expected_a,
                                            expected_b, expected_c,
                                            checksum) != 0) {
                goto cleanup;
            }
        }
        size_t middle = elements / 2;
        size_t last = elements - 1;
        if (middle % sample_stride != 0 &&
            stream_pipeline_check_index(matrices, group, middle, expected_a,
                                        expected_b, expected_c, checksum) != 0) {
            goto cleanup;
        }
        if (last % sample_stride != 0 &&
            stream_pipeline_check_index(matrices, group, last, expected_a,
                                        expected_b, expected_c, checksum) != 0) {
            goto cleanup;
        }
    }

    rc = 0;

cleanup:
    free(cycle_unused_prefetch_evictions);
    free(cycle_stall_ns);
    free(cycle_write_bytes);
    free(cycle_read_bytes);
    free(cycle_demand_faults);
    for (size_t matrix = 1; matrix < STREAM_PIPELINE_MATRICES; matrix++) {
        free_benchmark_buffer(matrix_buffers[matrix], bytes,
                              matrix_munmap[matrix]);
    }
    free(cycle_rates);
    free(group_order);
    return rc;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s stream|stride|sparse|random_hotset|trace_chunks|"
                "stream_plain|stride_plain|sparse_plain|heartbeat_busy|"
                "mprotect_overhead|heartbeat_idle|chunk_position|"
                "heartbeat_concurrent|stream_bandwidth|stream_anon_mmap|"
                "stream_shared_file|stream_private_file|"
                "stream_tiled_bandwidth|policy_stream_pipeline|"
                "policy_stream_pipeline_phase_decoy|"
                "submatrix_stream_pipeline|"
                "multi_alloc_matrix_pipeline|"
                "policy_multistream_stride|policy_hotset_scan|"
                "policy_phase_shift_hotset|"
                "policy_irr_scan_return|"
                "policy_recency_frequency_pivot|"
                "policy_arc_adaptation_pivot|"
                "policy_long_tail_admission|"
                "policy_best_offset_lag|"
                "policy_successor_cycle|policy_signature_context_cycle|"
                "policy_hinted_sequential|"
                "policy_spatial_region_mask|"
                "policy_spatial_interleaved_mask|"
                "stream_kernel_pipeline|"
                "stream_kernel_pipeline_anon_mmap|"
                "stream_kernel_pipeline_shared_file|"
                "stream_kernel_pipeline_private_file <size>\n",
                argv[0]);
        return 2;
    }

    long configured_page_size = sysconf(_SC_PAGESIZE);
    if (configured_page_size > 0) {
        page_size_bytes = (size_t)configured_page_size;
    }

    size_t size = 0;
    if (parse_size_value(argv[2], &size) != 0 || size < page_size_bytes) {
        return fail("invalid allocation size");
    }
    size -= size % page_size_bytes;

    MaiStats before;
    MaiStats after;
    int pure_workload = pure_workload_mode();
    int expect_managed = pure_workload ? 0 : 1;
    const char* expect_managed_env = getenv("MAI_ACCESS_EXPECT_MANAGED");
    if (expect_managed_env && strcmp(expect_managed_env, "0") == 0) {
        expect_managed = 0;
    }

    int before_stats_available = 0;
    int after_stats_available = 0;
    if (load_stats_optional(&before, &before_stats_available) != 0 ||
        (expect_managed && !before_stats_available)) {
        return fail("mai_get_stats is unavailable; run with libmai preloaded");
    }

    struct rusage run_usage_before;
    struct rusage run_usage_after;
    int run_usage_available = getrusage(RUSAGE_SELF, &run_usage_before) == 0;
    CgroupSizeSample cgroup_memory_max = sample_cgroup_size(
        "memory.max", "memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes");
    cgroup_memory_max_bytes = cgroup_memory_max.bytes;
    cgroup_memory_max_available = cgroup_memory_max.available;
    cgroup_memory_max_is_max_token = cgroup_memory_max.max_token;
    cgroup_memory_max_unbounded =
        cgroup_limit_is_unbounded(cgroup_memory_max);
    cgroup_memory_current_before = sample_cgroup_size(
        "memory.current", "memory.usage_in_bytes",
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes").bytes;
    CgroupSizeSample cgroup_swap_max = sample_cgroup_size(
        "memory.swap.max", "memory.memsw.limit_in_bytes",
        "/sys/fs/cgroup/memory.swap.max",
        "/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes");
    cgroup_swap_max_bytes = cgroup_swap_max.bytes;
    cgroup_swap_max_available = cgroup_swap_max.available;
    cgroup_swap_max_is_max_token = cgroup_swap_max.max_token;
    cgroup_swap_max_unbounded =
        cgroup_limit_is_unbounded(cgroup_swap_max);
    cgroup_swap_current_before = sample_cgroup_size(
        "memory.swap.current", "memory.memsw.usage_in_bytes",
        "/sys/fs/cgroup/memory.swap.current",
        "/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes").bytes;
    CgroupMemoryEvents cgroup_events_before = sample_cgroup_memory_events();

    unsigned char* buffer = NULL;
    int free_with_munmap = 0;
    if (!mode_allocates_internally(argv[1])) {
        if (allocate_benchmark_buffer(argv[1], size, &buffer, &free_with_munmap) != 0 ||
            !buffer) {
            return fail("access-pattern allocation failed");
        }
    }

    uint64_t checksum = 0;
    size_t touches = 0;
    struct timespec start;
    struct timespec end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc;
    if (strcmp(argv[1], "stream") == 0) {
        rc = run_windowed(buffer, size, 0, &checksum, &touches);
    } else if (strcmp(argv[1], "stride") == 0) {
        rc = run_windowed(buffer, size, 1, &checksum, &touches);
    } else if (strcmp(argv[1], "sparse") == 0) {
        rc = run_sparse(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "random_hotset") == 0) {
        rc = run_random_hotset(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "trace_chunks") == 0) {
        rc = run_trace_chunks(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "stream_plain") == 0) {
        rc = run_windowed_plain(buffer, size, 0, &checksum, &touches);
    } else if (strcmp(argv[1], "stride_plain") == 0) {
        rc = run_windowed_plain(buffer, size, 1, &checksum, &touches);
    } else if (strcmp(argv[1], "sparse_plain") == 0) {
        rc = run_sparse_plain(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "heartbeat_busy") == 0) {
        rc = run_heartbeat_busy(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "mprotect_overhead") == 0) {
        rc = run_mprotect_overhead(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "heartbeat_idle") == 0) {
        rc = run_heartbeat_idle(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "chunk_position") == 0) {
        rc = run_chunk_position(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "heartbeat_concurrent") == 0) {
        rc = run_heartbeat_concurrent(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "stream_tiled_bandwidth") == 0) {
        rc = run_stream_tiled_bandwidth(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "submatrix_stream_pipeline") == 0 ||
               strcmp(argv[1], "multi_alloc_matrix_pipeline") == 0) {
        rc = run_submatrix_stream_pipeline(argv[1], buffer, size, &checksum,
                                           &touches);
    } else if (mode_uses_stream_pipeline(argv[1])) {
        rc = run_stream_kernel_pipeline(argv[1], buffer, size, &checksum,
                                        &touches);
    } else if (strcmp(argv[1], "policy_multistream_stride") == 0) {
        rc = run_policy_multistream_stride(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_hotset_scan") == 0) {
        rc = run_policy_hotset_scan(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_phase_shift_hotset") == 0) {
        rc = run_policy_phase_shift_hotset(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_irr_scan_return") == 0) {
        rc = run_policy_irr_scan_return(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_recency_frequency_pivot") == 0 ||
               strcmp(argv[1], "policy_arc_adaptation_pivot") == 0) {
        rc = run_policy_recency_frequency_pivot(buffer, size, &checksum,
                                                &touches);
    } else if (strcmp(argv[1], "policy_long_tail_admission") == 0) {
        rc = run_policy_long_tail_admission(buffer, size, &checksum,
                                            &touches);
    } else if (strcmp(argv[1], "policy_best_offset_lag") == 0) {
        rc = run_policy_best_offset_lag(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_successor_cycle") == 0) {
        rc = run_policy_successor_cycle(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_hinted_sequential") == 0) {
        rc = run_policy_hinted_sequential(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_signature_context_cycle") == 0) {
        rc = run_policy_signature_context_cycle(buffer, size, &checksum,
                                                &touches);
    } else if (strcmp(argv[1], "policy_spatial_region_mask") == 0) {
        rc = run_policy_spatial_region_mask(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_spatial_interleaved_mask") == 0) {
        rc = run_policy_spatial_interleaved_mask(buffer, size, &checksum,
                                                &touches);
    } else if (mode_uses_stream_kernel(argv[1])) {
        rc = run_stream_bandwidth(argv[1], buffer, size, &checksum, &touches);
    } else {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("unknown access pattern");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (rc != 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern failed or data verification failed");
    }

    if (load_stats_optional(&after, &after_stats_available) != 0 ||
        before_stats_available != after_stats_available) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("mai_get_stats failed after access pattern");
    }
    if (run_usage_available && getrusage(RUSAGE_SELF, &run_usage_after) == 0) {
        run_minor_faults_delta =
            run_usage_after.ru_minflt - run_usage_before.ru_minflt;
        run_major_faults_delta =
            run_usage_after.ru_majflt - run_usage_before.ru_majflt;
        run_inblock_delta =
            run_usage_after.ru_inblock - run_usage_before.ru_inblock;
        run_oublock_delta =
            run_usage_after.ru_oublock - run_usage_before.ru_oublock;
        run_voluntary_ctxt_delta =
            run_usage_after.ru_nvcsw - run_usage_before.ru_nvcsw;
        run_involuntary_ctxt_delta =
            run_usage_after.ru_nivcsw - run_usage_before.ru_nivcsw;
        run_user_cpu_us_delta =
            timeval_delta_us(&run_usage_before.ru_utime,
                             &run_usage_after.ru_utime);
        run_sys_cpu_us_delta =
            timeval_delta_us(&run_usage_before.ru_stime,
                             &run_usage_after.ru_stime);
        run_maxrss_kib = run_usage_after.ru_maxrss;
    }
    cgroup_memory_current_after = sample_cgroup_size(
        "memory.current", "memory.usage_in_bytes",
        "/sys/fs/cgroup/memory.current",
        "/sys/fs/cgroup/memory/memory.usage_in_bytes").bytes;
    cgroup_swap_current_after = sample_cgroup_size(
        "memory.swap.current", "memory.memsw.usage_in_bytes",
        "/sys/fs/cgroup/memory.swap.current",
        "/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes").bytes;
    CgroupMemoryEvents cgroup_events_after = sample_cgroup_memory_events();
    cgroup_memory_events_high_delta =
        delta_size_t(cgroup_events_before.high, cgroup_events_after.high);
    cgroup_memory_events_max_delta =
        delta_size_t(cgroup_events_before.max, cgroup_events_after.max);
    cgroup_memory_events_oom_delta =
        delta_size_t(cgroup_events_before.oom, cgroup_events_after.oom);

    size_t managed_delta = after_stats_available ?
        after.managed_allocations - before.managed_allocations : 0;
    size_t reclaim_delta = after_stats_available ?
        after.reclaim_calls - before.reclaim_calls : 0;
    size_t reclaimed_delta = after_stats_available ?
        after.reclaimed_bytes - before.reclaimed_bytes : 0;
    size_t anon_delta = after_stats_available ?
        after.anon_allocations - before.anon_allocations : 0;
    size_t file_delta = after_stats_available ?
        after.file_allocations - before.file_allocations : 0;
    size_t migrated_delta = after_stats_available ?
        after.migrated_to_file_bytes - before.migrated_to_file_bytes : 0;
    size_t promoted_delta = after_stats_available ?
        after.promoted_to_anon_bytes - before.promoted_to_anon_bytes : 0;
    size_t uffd_alloc_delta = after_stats_available ?
        after.uffd_pager_allocations - before.uffd_pager_allocations : 0;
    size_t uffd_fault_delta = after_stats_available ?
        after.uffd_faults - before.uffd_faults : 0;
    size_t uffd_eviction_delta = after_stats_available ?
        after.uffd_evictions - before.uffd_evictions : 0;
    size_t uffd_fallback_delta = after_stats_available ?
        after.uffd_fallbacks - before.uffd_fallbacks : 0;
    size_t migration_policy = after_stats_available ? after.migration_policy : 0;
    size_t policy_prefetch_requests = after_stats_available ?
        after.policy_prefetch_requests - before.policy_prefetch_requests : 0;
    size_t policy_prefetch_admitted = after_stats_available ?
        after.policy_prefetch_admitted - before.policy_prefetch_admitted : 0;
    size_t policy_prefetch_completed = after_stats_available ?
        after.policy_prefetch_completed - before.policy_prefetch_completed : 0;
    size_t policy_prefetch_useful = after_stats_available ?
        after.policy_prefetch_useful - before.policy_prefetch_useful : 0;
    size_t policy_prefetch_late = after_stats_available ?
        after.policy_prefetch_late - before.policy_prefetch_late : 0;
    size_t policy_prefetch_unused_evictions = after_stats_available ?
        after.policy_prefetch_unused_evictions -
        before.policy_prefetch_unused_evictions : 0;
    size_t policy_prefetch_bytes = after_stats_available ?
        after.policy_prefetch_bytes - before.policy_prefetch_bytes : 0;
    size_t policy_prefetch_useful_bytes = after_stats_available ?
        after.policy_prefetch_useful_bytes -
        before.policy_prefetch_useful_bytes : 0;
    size_t policy_prefetch_unused_evicted_bytes = after_stats_available ?
        after.policy_prefetch_unused_evicted_bytes -
        before.policy_prefetch_unused_evicted_bytes : 0;
    size_t policy_admission_requests = after_stats_available ?
        after.policy_admission_requests - before.policy_admission_requests : 0;
    size_t policy_admission_rejected = after_stats_available ?
        after.policy_admission_rejected - before.policy_admission_rejected : 0;
    size_t policy_demotions = after_stats_available ?
        after.policy_demotions - before.policy_demotions : 0;
    size_t policy_promotions = after_stats_available ?
        after.policy_promotions - before.policy_promotions : 0;
    size_t policy_evicted_hot_bytes = after_stats_available ?
        after.policy_evicted_hot_bytes - before.policy_evicted_hot_bytes : 0;
    size_t policy_migration_read_bytes = after_stats_available ?
        after.policy_migration_read_bytes -
        before.policy_migration_read_bytes : 0;
    size_t policy_migration_write_bytes = after_stats_available ?
        after.policy_migration_write_bytes -
        before.policy_migration_write_bytes : 0;
    size_t policy_demand_faults = after_stats_available ?
        after.policy_demand_faults - before.policy_demand_faults : 0;
    size_t policy_demand_fault_stall_ns = after_stats_available ?
        after.policy_demand_fault_stall_ns -
        before.policy_demand_fault_stall_ns : 0;
    size_t policy_demand_fault_stall_samples = after_stats_available ?
        after.policy_demand_fault_stall_samples -
        before.policy_demand_fault_stall_samples : 0;
    size_t policy_throttle_events = after_stats_available ?
        after.policy_throttle_events - before.policy_throttle_events : 0;
    size_t policy_throttle_slept_ns = after_stats_available ?
        after.policy_throttle_slept_ns - before.policy_throttle_slept_ns : 0;
    size_t policy_async_prefetch_enqueued = after_stats_available ?
        after.policy_async_prefetch_enqueued -
        before.policy_async_prefetch_enqueued : 0;
    size_t policy_async_prefetch_completed = after_stats_available ?
        after.policy_async_prefetch_completed -
        before.policy_async_prefetch_completed : 0;
    size_t policy_async_prefetch_dropped = after_stats_available ?
        after.policy_async_prefetch_dropped -
        before.policy_async_prefetch_dropped : 0;
    size_t policy_async_completed_without_prefetch =
        policy_async_prefetch_completed > policy_prefetch_completed ?
        policy_async_prefetch_completed - policy_prefetch_completed : 0;
    size_t policy_adaptive_windows = after_stats_available ?
        after.policy_adaptive_windows - before.policy_adaptive_windows : 0;
    size_t policy_adaptive_level = after_stats_available ?
        after.policy_adaptive_level : 0;
    size_t policy_adaptive_level_changes = after_stats_available ?
        after.policy_adaptive_level_changes -
        before.policy_adaptive_level_changes : 0;
    size_t policy_adaptive_prefetch_capped = after_stats_available ?
        after.policy_adaptive_prefetch_capped -
        before.policy_adaptive_prefetch_capped : 0;
    size_t policy_adaptive_admission_rejected = after_stats_available ?
        after.policy_adaptive_admission_rejected -
        before.policy_adaptive_admission_rejected : 0;
    size_t policy_adaptive_budget_gate = after_stats_available ?
        after.policy_adaptive_budget_gate : 0;
    size_t policy_adaptive_budget_bytes = after_stats_available ?
        after.policy_adaptive_budget_bytes : 0;
    size_t policy_adaptive_window_migration_bytes = after_stats_available ?
        after.policy_adaptive_window_migration_bytes : 0;
    size_t policy_clean_shadow_tracked_chunks = after_stats_available ?
        after.policy_clean_shadow_tracked_chunks -
        before.policy_clean_shadow_tracked_chunks : 0;
    size_t policy_clean_shadow_protect_failures = after_stats_available ?
        after.policy_clean_shadow_protect_failures -
        before.policy_clean_shadow_protect_failures : 0;
    size_t policy_clean_shadow_write_skipped_bytes = after_stats_available ?
        after.policy_clean_shadow_write_skipped_bytes -
        before.policy_clean_shadow_write_skipped_bytes : 0;
    size_t policy_clean_shadow_write_skipped_chunks = after_stats_available ?
        after.policy_clean_shadow_write_skipped_chunks -
        before.policy_clean_shadow_write_skipped_chunks : 0;
    size_t policy_clean_shadow_write_faults = after_stats_available ?
        after.policy_clean_shadow_write_faults -
        before.policy_clean_shadow_write_faults : 0;
    size_t policy_car_recent_chunks = after_stats_available ?
        after.policy_car_recent_chunks : 0;
    size_t policy_car_frequent_chunks = after_stats_available ?
        after.policy_car_frequent_chunks : 0;
    size_t policy_car_recent_ghost_chunks = after_stats_available ?
        after.policy_car_recent_ghost_chunks : 0;
    size_t policy_car_frequent_ghost_chunks = after_stats_available ?
        after.policy_car_frequent_ghost_chunks : 0;
    size_t policy_car_target_recent_chunks = after_stats_available ?
        after.policy_car_target_recent_chunks : 0;
    size_t policy_car_recent_ghost_hits = after_stats_available ?
        after.policy_car_recent_ghost_hits -
        before.policy_car_recent_ghost_hits : 0;
    size_t policy_car_frequent_ghost_hits = after_stats_available ?
        after.policy_car_frequent_ghost_hits -
        before.policy_car_frequent_ghost_hits : 0;
    size_t policy_car_target_increases = after_stats_available ?
        after.policy_car_target_increases -
        before.policy_car_target_increases : 0;
    size_t policy_car_target_decreases = after_stats_available ?
        after.policy_car_target_decreases -
        before.policy_car_target_decreases : 0;
    size_t policy_car_second_chances = after_stats_available ?
        after.policy_car_second_chances -
        before.policy_car_second_chances : 0;
    size_t policy_tinylfu_sketch_updates = after_stats_available ?
        after.policy_tinylfu_sketch_updates -
        before.policy_tinylfu_sketch_updates : 0;
    size_t policy_tinylfu_sketch_decays = after_stats_available ?
        after.policy_tinylfu_sketch_decays -
        before.policy_tinylfu_sketch_decays : 0;
    size_t policy_tinylfu_admission_rejected = after_stats_available ?
        after.policy_tinylfu_admission_rejected -
        before.policy_tinylfu_admission_rejected : 0;
    size_t policy_tinylfu_min_score = after_stats_available ?
        after.policy_tinylfu_min_score : 0;
    size_t policy_bestoffset_train_samples = after_stats_available ?
        after.policy_bestoffset_train_samples -
        before.policy_bestoffset_train_samples : 0;
    size_t policy_bestoffset_train_hits = after_stats_available ?
        after.policy_bestoffset_train_hits -
        before.policy_bestoffset_train_hits : 0;
    size_t policy_bestoffset_slots_created = after_stats_available ?
        after.policy_bestoffset_slots_created -
        before.policy_bestoffset_slots_created : 0;
    size_t policy_bestoffset_score_decays = after_stats_available ?
        after.policy_bestoffset_score_decays -
        before.policy_bestoffset_score_decays : 0;
    size_t policy_bestoffset_candidates = after_stats_available ?
        after.policy_bestoffset_candidates -
        before.policy_bestoffset_candidates : 0;
    size_t policy_bestoffset_pressure_rejected = after_stats_available ?
        after.policy_bestoffset_pressure_rejected -
        before.policy_bestoffset_pressure_rejected : 0;
    size_t policy_bestoffset_unused_penalties = after_stats_available ?
        after.policy_bestoffset_unused_penalties -
        before.policy_bestoffset_unused_penalties : 0;
    size_t policy_bestoffset_top_offset_magnitude = after_stats_available ?
        after.policy_bestoffset_top_offset_magnitude : 0;
    size_t policy_bestoffset_top_offset_sign = after_stats_available ?
        after.policy_bestoffset_top_offset_sign : 0;
    size_t policy_bestoffset_top_score = after_stats_available ?
        after.policy_bestoffset_top_score : 0;
    size_t policy_wtinylfu_window_chunks = after_stats_available ?
        after.policy_wtinylfu_window_chunks : 0;
    size_t policy_wtinylfu_probation_chunks = after_stats_available ?
        after.policy_wtinylfu_probation_chunks : 0;
    size_t policy_wtinylfu_protected_chunks = after_stats_available ?
        after.policy_wtinylfu_protected_chunks : 0;
    size_t policy_wtinylfu_window_evictions = after_stats_available ?
        after.policy_wtinylfu_window_evictions -
        before.policy_wtinylfu_window_evictions : 0;
    size_t policy_wtinylfu_main_admission_rejected = after_stats_available ?
        after.policy_wtinylfu_main_admission_rejected -
        before.policy_wtinylfu_main_admission_rejected : 0;
    size_t policy_wtinylfu_victim_score_rejected = after_stats_available ?
        after.policy_wtinylfu_victim_score_rejected -
        before.policy_wtinylfu_victim_score_rejected : 0;
    size_t policy_successor_chain_candidates = after_stats_available ?
        after.policy_successor_chain_candidates -
        before.policy_successor_chain_candidates : 0;
    size_t policy_successor_chain_rejected = after_stats_available ?
        after.policy_successor_chain_rejected -
        before.policy_successor_chain_rejected : 0;
    size_t policy_successor_chain_depth = after_stats_available ?
        after.policy_successor_chain_depth : 0;
    size_t policy_markov_lead_candidates = after_stats_available ?
        after.policy_markov_lead_candidates -
        before.policy_markov_lead_candidates : 0;
    size_t policy_markov_lead_admitted = after_stats_available ?
        after.policy_markov_lead_admitted -
        before.policy_markov_lead_admitted : 0;
    size_t policy_markov_lead_completed = after_stats_available ?
        after.policy_markov_lead_completed -
        before.policy_markov_lead_completed : 0;
    size_t policy_markov_lead_useful = after_stats_available ?
        after.policy_markov_lead_useful -
        before.policy_markov_lead_useful : 0;
    size_t policy_phase_candidates = after_stats_available ?
        after.policy_phase_candidates -
        before.policy_phase_candidates : 0;
    size_t policy_phase_admitted = after_stats_available ?
        after.policy_phase_admitted -
        before.policy_phase_admitted : 0;
    size_t policy_phase_completed = after_stats_available ?
        after.policy_phase_completed -
        before.policy_phase_completed : 0;
    size_t policy_phase_useful = after_stats_available ?
        after.policy_phase_useful -
        before.policy_phase_useful : 0;
    size_t policy_phase_conflicts = after_stats_available ?
        after.policy_phase_conflicts -
        before.policy_phase_conflicts : 0;
    size_t policy_phase_confidence_rejected = after_stats_available ?
        after.policy_phase_confidence_rejected -
        before.policy_phase_confidence_rejected : 0;
    size_t policy_phase_budget_rejected = after_stats_available ?
        after.policy_phase_budget_rejected -
        before.policy_phase_budget_rejected : 0;
    size_t policy_phase_safe_victim_rejected = after_stats_available ?
        after.policy_phase_safe_victim_rejected -
        before.policy_phase_safe_victim_rejected : 0;
    size_t policy_phase_victim_rejected = after_stats_available ?
        after.policy_phase_victim_rejected -
        before.policy_phase_victim_rejected : 0;
    size_t policy_phase_duplicate_candidates = after_stats_available ?
        after.policy_phase_duplicate_candidates -
        before.policy_phase_duplicate_candidates : 0;
    size_t policy_phase_target_hot_skipped = after_stats_available ?
        after.policy_phase_target_hot_skipped -
        before.policy_phase_target_hot_skipped : 0;
    size_t policy_phase_active_slots = after_stats_available ?
        after.policy_phase_active_slots : 0;
    size_t policy_phase_top_score = after_stats_available ?
        after.policy_phase_top_score : 0;
    size_t policy_phase_unused_evictions = after_stats_available ?
        after.policy_phase_unused_evictions -
        before.policy_phase_unused_evictions : 0;
    size_t policy_phase_boundary_prefetches = after_stats_available ?
        after.policy_phase_boundary_prefetches -
        before.policy_phase_boundary_prefetches : 0;
    size_t policy_phase_hold_activations = after_stats_available ?
        after.policy_phase_hold_activations -
        before.policy_phase_hold_activations : 0;
    size_t policy_phase_shadow_candidates = after_stats_available ?
        after.policy_phase_shadow_candidates -
        before.policy_phase_shadow_candidates : 0;
    size_t policy_phase_shadow_useful = after_stats_available ?
        after.policy_phase_shadow_useful -
        before.policy_phase_shadow_useful : 0;
    size_t policy_phase_shadow_late = after_stats_available ?
        after.policy_phase_shadow_late -
        before.policy_phase_shadow_late : 0;
    size_t policy_phase_shadow_expired = after_stats_available ?
        after.policy_phase_shadow_expired -
        before.policy_phase_shadow_expired : 0;
    size_t policy_phase_shadow_overwritten = after_stats_available ?
        after.policy_phase_shadow_overwritten -
        before.policy_phase_shadow_overwritten : 0;
    size_t policy_phase_shadow_probe_candidates = after_stats_available ?
        after.policy_phase_shadow_probe_candidates -
        before.policy_phase_shadow_probe_candidates : 0;
    size_t policy_phase_shadow_edge_rejected = after_stats_available ?
        after.policy_phase_shadow_edge_rejected -
        before.policy_phase_shadow_edge_rejected : 0;
    size_t policy_phase_shadow_edge_confirmed = after_stats_available ?
        after.policy_phase_shadow_edge_confirmed -
        before.policy_phase_shadow_edge_confirmed : 0;
    size_t policy_phase_shadow_top_late = after_stats_available ?
        after.policy_phase_shadow_top_late : 0;
    size_t policy_phase_shadow_max_late = after_stats_available ?
        after.policy_phase_shadow_max_late : 0;
    size_t policy_hint_candidates = after_stats_available ?
        after.policy_hint_candidates - before.policy_hint_candidates : 0;
    size_t policy_hint_admitted = after_stats_available ?
        after.policy_hint_admitted - before.policy_hint_admitted : 0;
    size_t policy_hint_completed = after_stats_available ?
        after.policy_hint_completed - before.policy_hint_completed : 0;
    size_t policy_hint_useful = after_stats_available ?
        after.policy_hint_useful - before.policy_hint_useful : 0;
    size_t policy_hint_rejected = after_stats_available ?
        after.policy_hint_rejected - before.policy_hint_rejected : 0;
    size_t policy_arc_t1_chunks = after_stats_available ?
        after.policy_arc_t1_chunks : 0;
    size_t policy_arc_t2_chunks = after_stats_available ?
        after.policy_arc_t2_chunks : 0;
    size_t policy_arc_b1_chunks = after_stats_available ?
        after.policy_arc_b1_chunks : 0;
    size_t policy_arc_b2_chunks = after_stats_available ?
        after.policy_arc_b2_chunks : 0;
    size_t policy_arc_p_chunks = after_stats_available ?
        after.policy_arc_p_chunks : 0;
    size_t policy_arc_b1_hits = after_stats_available ?
        after.policy_arc_b1_hits - before.policy_arc_b1_hits : 0;
    size_t policy_arc_b2_hits = after_stats_available ?
        after.policy_arc_b2_hits - before.policy_arc_b2_hits : 0;
    size_t policy_arc_target_increases = after_stats_available ?
        after.policy_arc_target_increases -
        before.policy_arc_target_increases : 0;
    size_t policy_arc_target_decreases = after_stats_available ?
        after.policy_arc_target_decreases -
        before.policy_arc_target_decreases : 0;
    size_t policy_arc_t1_hits = after_stats_available ?
        after.policy_arc_t1_hits - before.policy_arc_t1_hits : 0;
    size_t policy_arc_t2_hits = after_stats_available ?
        after.policy_arc_t2_hits - before.policy_arc_t2_hits : 0;
    size_t policy_arc_t1_to_t2_promotions = after_stats_available ?
        after.policy_arc_t1_to_t2_promotions -
        before.policy_arc_t1_to_t2_promotions : 0;
    size_t policy_arc_replace_t1 = after_stats_available ?
        after.policy_arc_replace_t1 - before.policy_arc_replace_t1 : 0;
    size_t policy_arc_replace_t2 = after_stats_available ?
        after.policy_arc_replace_t2 - before.policy_arc_replace_t2 : 0;
    size_t policy_arc_b1_pruned = after_stats_available ?
        after.policy_arc_b1_pruned - before.policy_arc_b1_pruned : 0;
    size_t policy_arc_b2_pruned = after_stats_available ?
        after.policy_arc_b2_pruned - before.policy_arc_b2_pruned : 0;
    size_t policy_arc_prefetch_admitted_t1 = after_stats_available ?
        after.policy_arc_prefetch_admitted_t1 -
        before.policy_arc_prefetch_admitted_t1 : 0;
    size_t policy_arc_prefetch_rejected_pressure = after_stats_available ?
        after.policy_arc_prefetch_rejected_pressure -
        before.policy_arc_prefetch_rejected_pressure : 0;
    size_t policy_arc_prefetch_promoted_to_t2 = after_stats_available ?
        after.policy_arc_prefetch_promoted_to_t2 -
        before.policy_arc_prefetch_promoted_to_t2 : 0;
    size_t policy_irr_resident_chunks = after_stats_available ?
        after.policy_irr_resident_chunks : 0;
    size_t policy_irr_protected_chunks = after_stats_available ?
        after.policy_irr_protected_chunks : 0;
    size_t policy_irr_ghost_chunks = after_stats_available ?
        after.policy_irr_ghost_chunks : 0;
    size_t policy_irr_target_protected_chunks = after_stats_available ?
        after.policy_irr_target_protected_chunks : 0;
    size_t policy_irr_ghost_hits = after_stats_available ?
        after.policy_irr_ghost_hits - before.policy_irr_ghost_hits : 0;
    size_t policy_irr_promotions = after_stats_available ?
        after.policy_irr_promotions - before.policy_irr_promotions : 0;
    size_t policy_irr_demotions = after_stats_available ?
        after.policy_irr_demotions - before.policy_irr_demotions : 0;
    size_t policy_irr_pressure_rejected = after_stats_available ?
        after.policy_irr_pressure_rejected -
        before.policy_irr_pressure_rejected : 0;
    size_t policy_irr_immature_rejected = after_stats_available ?
        after.policy_irr_immature_rejected -
        before.policy_irr_immature_rejected : 0;
    size_t policy_irr_max_interval_epochs = after_stats_available ?
        after.policy_irr_max_interval_epochs : 0;
    size_t policy_signature_train_samples = after_stats_available ?
        after.policy_signature_train_samples -
        before.policy_signature_train_samples : 0;
    size_t policy_signature_train_hits = after_stats_available ?
        after.policy_signature_train_hits -
        before.policy_signature_train_hits : 0;
    size_t policy_signature_slots_created = after_stats_available ?
        after.policy_signature_slots_created -
        before.policy_signature_slots_created : 0;
    size_t policy_signature_score_decays = after_stats_available ?
        after.policy_signature_score_decays -
        before.policy_signature_score_decays : 0;
    size_t policy_signature_candidates = after_stats_available ?
        after.policy_signature_candidates -
        before.policy_signature_candidates : 0;
    size_t policy_signature_pressure_rejected = after_stats_available ?
        after.policy_signature_pressure_rejected -
        before.policy_signature_pressure_rejected : 0;
    size_t policy_signature_unused_penalties = after_stats_available ?
        after.policy_signature_unused_penalties -
        before.policy_signature_unused_penalties : 0;
    size_t policy_signature_chain_candidates = after_stats_available ?
        after.policy_signature_chain_candidates -
        before.policy_signature_chain_candidates : 0;
    size_t policy_signature_chain_rejected = after_stats_available ?
        after.policy_signature_chain_rejected -
        before.policy_signature_chain_rejected : 0;
    size_t policy_signature_chain_depth = after_stats_available ?
        after.policy_signature_chain_depth : 0;
    size_t policy_signature_top_delta_magnitude = after_stats_available ?
        after.policy_signature_top_delta_magnitude : 0;
    size_t policy_signature_top_delta_sign = after_stats_available ?
        after.policy_signature_top_delta_sign : 0;
    size_t policy_signature_top_score = after_stats_available ?
        after.policy_signature_top_score : 0;
    size_t policy_hybrid_signature_candidates = after_stats_available ?
        after.policy_hybrid_signature_candidates -
        before.policy_hybrid_signature_candidates : 0;
    size_t policy_hybrid_successor_candidates = after_stats_available ?
        after.policy_hybrid_successor_candidates -
        before.policy_hybrid_successor_candidates : 0;
    size_t policy_hybrid_stream_candidates = after_stats_available ?
        after.policy_hybrid_stream_candidates -
        before.policy_hybrid_stream_candidates : 0;
    size_t policy_hybrid_cohort_candidates = after_stats_available ?
        after.policy_hybrid_cohort_candidates -
        before.policy_hybrid_cohort_candidates : 0;
    size_t policy_hybrid_admission_rejected = after_stats_available ?
        after.policy_hybrid_admission_rejected -
        before.policy_hybrid_admission_rejected : 0;
    size_t policy_hybrid_signature_admitted = after_stats_available ?
        after.policy_hybrid_signature_admitted -
        before.policy_hybrid_signature_admitted : 0;
    size_t policy_hybrid_successor_admitted = after_stats_available ?
        after.policy_hybrid_successor_admitted -
        before.policy_hybrid_successor_admitted : 0;
    size_t policy_hybrid_stream_admitted = after_stats_available ?
        after.policy_hybrid_stream_admitted -
        before.policy_hybrid_stream_admitted : 0;
    size_t policy_hybrid_cohort_admitted = after_stats_available ?
        after.policy_hybrid_cohort_admitted -
        before.policy_hybrid_cohort_admitted : 0;
    size_t policy_hybrid_signature_completed = after_stats_available ?
        after.policy_hybrid_signature_completed -
        before.policy_hybrid_signature_completed : 0;
    size_t policy_hybrid_successor_completed = after_stats_available ?
        after.policy_hybrid_successor_completed -
        before.policy_hybrid_successor_completed : 0;
    size_t policy_hybrid_stream_completed = after_stats_available ?
        after.policy_hybrid_stream_completed -
        before.policy_hybrid_stream_completed : 0;
    size_t policy_hybrid_cohort_completed = after_stats_available ?
        after.policy_hybrid_cohort_completed -
        before.policy_hybrid_cohort_completed : 0;
    size_t policy_hybrid_signature_useful = after_stats_available ?
        after.policy_hybrid_signature_useful -
        before.policy_hybrid_signature_useful : 0;
    size_t policy_hybrid_successor_useful = after_stats_available ?
        after.policy_hybrid_successor_useful -
        before.policy_hybrid_successor_useful : 0;
    size_t policy_hybrid_stream_useful = after_stats_available ?
        after.policy_hybrid_stream_useful -
        before.policy_hybrid_stream_useful : 0;
    size_t policy_hybrid_cohort_useful = after_stats_available ?
        after.policy_hybrid_cohort_useful -
        before.policy_hybrid_cohort_useful : 0;
    const char* policy_prefetch_observation =
        after_stats_available && after.policy_prefetch_observation != 0 ?
        "write_protect" : "unobserved";
    double seconds = seconds_since(&start, &end);
    double touched_mib = ((double)touches * (double)page_size_bytes) /
        (1024.0 * 1024.0);
    double mib_per_sec = seconds > 0.0 ? touched_mib / seconds : 0.0;
    double logical_mib = (double)logical_bytes / (1024.0 * 1024.0);
    double logical_mib_per_sec = measured_access_seconds > 0.0 ?
        logical_mib / measured_access_seconds : 0.0;
    double end_to_end_logical_mib_per_sec = seconds > 0.0 ?
        logical_mib / seconds : 0.0;
    double policy_sampled_units_per_sec = seconds > 0.0 ?
        (double)touches / seconds : 0.0;
    double policy_prefetch_accuracy_observed = policy_prefetch_completed != 0 ?
        (double)policy_prefetch_useful / (double)policy_prefetch_completed : 0.0;
    double policy_prefetch_coverage_observed = policy_demand_faults != 0 ?
        (double)policy_prefetch_useful / (double)policy_demand_faults : 0.0;
    double policy_read_amplification = logical_bytes != 0 ?
        (double)policy_migration_read_bytes / (double)logical_bytes : 0.0;
    double policy_write_amplification = logical_bytes != 0 ?
        (double)policy_migration_write_bytes / (double)logical_bytes : 0.0;
    double policy_migration_mib = (double)(policy_migration_read_bytes +
        policy_migration_write_bytes) / (1024.0 * 1024.0);
    double policy_migration_mib_per_sec = seconds > 0.0 ?
        policy_migration_mib / seconds : 0.0;
    size_t policy_async_prefetch_attempts =
        policy_async_prefetch_enqueued + policy_async_prefetch_dropped;
    double policy_async_drop_rate = policy_async_prefetch_attempts != 0 ?
        (double)policy_async_prefetch_dropped /
        (double)policy_async_prefetch_attempts : 0.0;
    double min_mib_per_sec = env_double("MAI_ACCESS_MIN_MIB_PER_SEC", 0.0);

    printf("mode=%s size=%zu touches=%zu touched_mib=%.3f seconds=%.6f "
           "mib_per_sec=%.3f checksum=%llu managed_delta=%zu "
           "reclaim_delta=%zu reclaimed_delta=%zu anon_delta=%zu "
           "file_delta=%zu migrated_delta=%zu promoted_delta=%zu "
           "uffd_available=%zu uffd_alloc_delta=%zu uffd_fault_delta=%zu "
           "uffd_eviction_delta=%zu uffd_resident_bytes=%zu "
           "uffd_fallback_delta=%zu migration_policy=%zu "
           "policy_prefetch_requests=%zu "
           "policy_prefetch_admitted=%zu "
           "policy_prefetch_completed=%zu "
           "policy_prefetch_useful=%zu policy_prefetch_late=%zu "
           "policy_prefetch_unused_evictions=%zu "
           "policy_prefetch_bytes=%zu "
           "policy_prefetch_useful_bytes=%zu "
           "policy_prefetch_unused_evicted_bytes=%zu "
           "policy_prefetch_observation=%s "
           "policy_prefetch_accuracy_observed=%.6f "
           "policy_prefetch_coverage_observed=%.6f "
           "policy_admission_requests=%zu "
           "policy_admission_rejected=%zu "
           "policy_demotions=%zu policy_promotions=%zu "
           "policy_evicted_hot_bytes=%zu "
           "policy_migration_read_bytes=%zu "
           "policy_migration_write_bytes=%zu "
           "policy_read_amplification=%.6f "
           "policy_write_amplification=%.6f "
           "policy_migration_mib_per_sec=%.3f "
           "policy_demand_faults=%zu "
           "policy_demand_fault_stall_ns=%zu "
           "policy_demand_fault_stall_samples=%zu "
           "policy_demand_fault_stall_p50_ns=%zu "
           "policy_demand_fault_stall_p90_ns=%zu "
           "policy_demand_fault_stall_p99_ns=%zu "
           "policy_demand_fault_stall_max_ns=%zu "
           "policy_throttle_events=%zu "
           "policy_throttle_slept_ns=%zu "
           "policy_async_prefetch_enqueued=%zu "
           "policy_async_prefetch_completed=%zu "
           "policy_async_prefetch_dropped=%zu "
           "policy_async_completed_without_prefetch=%zu "
           "policy_async_drop_rate=%.6f "
           "policy_adaptive_windows=%zu "
           "policy_adaptive_level=%zu "
           "policy_adaptive_level_changes=%zu "
           "policy_adaptive_prefetch_capped=%zu "
           "policy_adaptive_admission_rejected=%zu "
           "policy_adaptive_budget_gate=%zu "
           "policy_adaptive_budget_bytes=%zu "
           "policy_adaptive_window_migration_bytes=%zu "
           "policy_clean_shadow_tracked_chunks=%zu "
           "policy_clean_shadow_protect_failures=%zu "
           "policy_clean_shadow_write_skipped_bytes=%zu "
           "policy_clean_shadow_write_skipped_chunks=%zu "
           "policy_clean_shadow_write_faults=%zu "
           "policy_car_recent_chunks=%zu "
           "policy_car_frequent_chunks=%zu "
           "policy_car_recent_ghost_chunks=%zu "
           "policy_car_frequent_ghost_chunks=%zu "
           "policy_car_target_recent_chunks=%zu "
           "policy_car_recent_ghost_hits=%zu "
           "policy_car_frequent_ghost_hits=%zu "
           "policy_car_target_increases=%zu "
           "policy_car_target_decreases=%zu "
           "policy_car_second_chances=%zu "
           "policy_tinylfu_sketch_updates=%zu "
           "policy_tinylfu_sketch_decays=%zu "
           "policy_tinylfu_admission_rejected=%zu "
           "policy_tinylfu_min_score=%zu "
           "policy_bestoffset_train_samples=%zu "
           "policy_bestoffset_train_hits=%zu "
           "policy_bestoffset_slots_created=%zu "
           "policy_bestoffset_score_decays=%zu "
           "policy_bestoffset_candidates=%zu "
           "policy_bestoffset_pressure_rejected=%zu "
           "policy_bestoffset_unused_penalties=%zu "
           "policy_bestoffset_top_offset_magnitude=%zu "
           "policy_bestoffset_top_offset_sign=%zu "
           "policy_bestoffset_top_score=%zu "
           "policy_wtinylfu_window_chunks=%zu "
           "policy_wtinylfu_probation_chunks=%zu "
           "policy_wtinylfu_protected_chunks=%zu "
           "policy_wtinylfu_window_evictions=%zu "
           "policy_wtinylfu_main_admission_rejected=%zu "
           "policy_wtinylfu_victim_score_rejected=%zu "
           "policy_successor_chain_candidates=%zu "
           "policy_successor_chain_rejected=%zu "
           "policy_successor_chain_depth=%zu "
           "policy_markov_lead_candidates=%zu "
           "policy_markov_lead_admitted=%zu "
           "policy_markov_lead_completed=%zu "
           "policy_markov_lead_useful=%zu "
           "policy_phase_candidates=%zu "
           "policy_phase_admitted=%zu "
           "policy_phase_completed=%zu "
           "policy_phase_useful=%zu "
           "policy_phase_conflicts=%zu "
           "policy_phase_confidence_rejected=%zu "
           "policy_phase_budget_rejected=%zu "
           "policy_phase_safe_victim_rejected=%zu "
           "policy_phase_victim_rejected=%zu "
           "policy_phase_duplicate_candidates=%zu "
           "policy_phase_target_hot_skipped=%zu "
           "policy_phase_active_slots=%zu "
           "policy_phase_top_score=%zu "
           "policy_phase_unused_evictions=%zu "
           "policy_phase_boundary_prefetches=%zu "
           "policy_phase_hold_activations=%zu "
           "policy_phase_shadow_candidates=%zu "
           "policy_phase_shadow_useful=%zu "
           "policy_phase_shadow_late=%zu "
           "policy_phase_shadow_expired=%zu "
           "policy_phase_shadow_overwritten=%zu "
           "policy_phase_shadow_probe_candidates=%zu "
           "policy_phase_shadow_edge_rejected=%zu "
           "policy_phase_shadow_edge_confirmed=%zu "
           "policy_phase_shadow_top_late=%zu "
           "policy_phase_shadow_max_late=%zu "
           "policy_hint_candidates=%zu "
           "policy_hint_admitted=%zu "
           "policy_hint_completed=%zu "
           "policy_hint_useful=%zu "
           "policy_hint_rejected=%zu "
           "policy_arc_t1_chunks=%zu "
           "policy_arc_t2_chunks=%zu "
           "policy_arc_b1_chunks=%zu "
           "policy_arc_b2_chunks=%zu "
           "policy_arc_p_chunks=%zu "
           "policy_arc_b1_hits=%zu "
           "policy_arc_b2_hits=%zu "
           "policy_arc_target_increases=%zu "
           "policy_arc_target_decreases=%zu "
           "policy_arc_t1_hits=%zu "
           "policy_arc_t2_hits=%zu "
           "policy_arc_t1_to_t2_promotions=%zu "
           "policy_arc_replace_t1=%zu "
           "policy_arc_replace_t2=%zu "
           "policy_arc_b1_pruned=%zu "
           "policy_arc_b2_pruned=%zu "
           "policy_arc_prefetch_admitted_t1=%zu "
           "policy_arc_prefetch_rejected_pressure=%zu "
           "policy_arc_prefetch_promoted_to_t2=%zu "
           "policy_irr_resident_chunks=%zu "
           "policy_irr_protected_chunks=%zu "
           "policy_irr_ghost_chunks=%zu "
           "policy_irr_target_protected_chunks=%zu "
           "policy_irr_ghost_hits=%zu "
           "policy_irr_promotions=%zu "
           "policy_irr_demotions=%zu "
           "policy_irr_pressure_rejected=%zu "
           "policy_irr_immature_rejected=%zu "
           "policy_irr_max_interval_epochs=%zu "
           "policy_signature_train_samples=%zu "
           "policy_signature_train_hits=%zu "
           "policy_signature_slots_created=%zu "
           "policy_signature_score_decays=%zu "
           "policy_signature_candidates=%zu "
           "policy_signature_pressure_rejected=%zu "
           "policy_signature_unused_penalties=%zu "
           "policy_signature_chain_candidates=%zu "
           "policy_signature_chain_rejected=%zu "
           "policy_signature_chain_depth=%zu "
           "policy_signature_top_delta_magnitude=%zu "
           "policy_signature_top_delta_sign=%zu "
           "policy_signature_top_score=%zu "
           "policy_hybrid_signature_candidates=%zu "
           "policy_hybrid_successor_candidates=%zu "
           "policy_hybrid_stream_candidates=%zu "
           "policy_hybrid_cohort_candidates=%zu "
           "policy_hybrid_admission_rejected=%zu "
           "policy_hybrid_signature_admitted=%zu "
           "policy_hybrid_successor_admitted=%zu "
           "policy_hybrid_stream_admitted=%zu "
           "policy_hybrid_cohort_admitted=%zu "
           "policy_hybrid_signature_completed=%zu "
           "policy_hybrid_successor_completed=%zu "
           "policy_hybrid_stream_completed=%zu "
           "policy_hybrid_cohort_completed=%zu "
           "policy_hybrid_signature_useful=%zu "
           "policy_hybrid_successor_useful=%zu "
           "policy_hybrid_stream_useful=%zu "
           "policy_hybrid_cohort_useful=%zu "
           "max_rss=%zu "
           "current_rss_before=%zu current_rss_after=%zu "
           "high_water_rss_after=%zu "
           "heartbeat_calls=%zu heartbeat_busy_ticks=%zu "
           "heartbeat_migrate_bytes=%zu heartbeat_reclaimed_bytes=%zu "
           "trace_setup_calls=%zu trace_stop_calls=%zu "
           "trace_faulted_pages=%zu latency_ops=%zu logical_mib=%.3f "
           "policy_sampled_units=%zu "
           "policy_sampled_units_per_sec=%.3f "
           "logical_mib_per_sec=%.3f "
           "kernel_logical_mib_per_sec=%.3f "
           "end_to_end_logical_mib_per_sec=%.3f "
           "mprotect_mechanism=%s "
           "mprotect_chunk_bytes=%zu mprotect_sample_pages=%zu "
           "mprotect_warmup_ns=%llu "
           "mprotect_setup_ns=%llu mprotect_first_touch_total_ns=%llu "
           "mprotect_first_touch_min_ns=%llu "
           "mprotect_first_touch_p50_ns=%llu "
           "mprotect_first_touch_p90_ns=%llu "
           "mprotect_first_touch_p99_ns=%llu "
           "mprotect_first_touch_max_ns=%llu "
           "mprotect_finish_ns=%llu mprotect_sweep_ns=%llu "
           "mprotect_minor_faults_delta=%ld "
           "mprotect_major_faults_delta=%ld "
           "mprotect_voluntary_ctxt_delta=%ld "
           "mprotect_involuntary_ctxt_delta=%ld "
           "mprotect_user_cpu_us_delta=%ld "
           "mprotect_sys_cpu_us_delta=%ld "
           "run_minor_faults_delta=%ld "
           "run_major_faults_delta=%ld "
           "run_inblock_delta=%ld "
           "run_oublock_delta=%ld "
           "run_voluntary_ctxt_delta=%ld "
           "run_involuntary_ctxt_delta=%ld "
           "run_user_cpu_us_delta=%ld "
           "run_sys_cpu_us_delta=%ld "
           "run_maxrss_kib=%ld "
           "cgroup_memory_max_bytes=%zu "
           "cgroup_memory_max_available=%d "
           "cgroup_memory_max_unbounded=%d "
           "cgroup_memory_max_is_max_token=%d "
           "cgroup_memory_current_before=%zu "
           "cgroup_memory_current_after=%zu "
           "cgroup_memory_events_high_delta=%zu "
           "cgroup_memory_events_max_delta=%zu "
           "cgroup_memory_events_oom_delta=%zu "
           "cgroup_swap_max_bytes=%zu "
           "cgroup_swap_max_available=%d "
           "cgroup_swap_max_unbounded=%d "
           "cgroup_swap_max_is_max_token=%d "
           "cgroup_swap_current_before=%zu "
           "cgroup_swap_current_after=%zu "
           "stream_mapping_kind=%s "
           "stream_backing_path=%s "
           "stream_backing_fs_type=%llu "
           "stream_backing_is_tmpfs=%d "
           "heartbeat_total_ns=%llu "
           "chunk_touch_position=%s "
           "stream_copy_mib_per_sec=%.3f "
           "stream_scale_mib_per_sec=%.3f "
           "stream_add_mib_per_sec=%.3f "
           "stream_triad_mib_per_sec=%.3f "
           "stream_total_mib_per_sec=%.3f "
           "stream_passes=%zu "
           "stream_first_pass_mib_per_sec=%.3f "
           "stream_median_pass_mib_per_sec=%.3f "
           "stream_last_pass_mib_per_sec=%.3f "
           "stream_min_pass_mib_per_sec=%.3f "
           "stream_max_pass_mib_per_sec=%.3f "
           "stream_tile_bytes=%zu stream_tiles=%zu "
           "stream_resident_arrays=%zu "
           "stream_pipeline_kernels=%zu stream_pipeline_cycles=%zu "
           "stream_pipeline_group_visits=%zu "
           "stream_pipeline_groups=%zu "
           "stream_pipeline_group_iterations=%zu "
           "stream_pipeline_matrix_bytes=%zu "
           "stream_pipeline_group_bytes=%zu "
           "stream_pipeline_total_matrix_bytes=%zu "
           "stream_pipeline_scalar=%.6f "
           "stream_pipeline_order=%s "
           "stream_pipeline_seed=%zu "
           "stream_pipeline_prediction=%s "
           "stream_pipeline_reclaim_lag=%zu "
           "stream_pipeline_reclaim_horizon=%zu "
           "stream_pipeline_unique_cold_visits=%zu "
           "stream_pipeline_max_cycle_policy_demand_faults=%zu "
           "stream_pipeline_max_cycle_policy_read_bytes=%zu "
           "stream_pipeline_max_cycle_policy_write_bytes=%zu "
           "stream_pipeline_max_cycle_policy_stall_ns=%zu "
           "stream_pipeline_max_cycle_policy_demotions=%zu "
           "stream_pipeline_max_cycle_policy_hot_evicted_bytes=%zu "
           "stream_pipeline_cycle_policy_demand_faults_p50=%zu "
           "stream_pipeline_cycle_policy_demand_faults_p90=%zu "
           "stream_pipeline_cycle_policy_demand_faults_p99=%zu "
           "stream_pipeline_cycle_policy_read_bytes_p50=%zu "
           "stream_pipeline_cycle_policy_read_bytes_p90=%zu "
           "stream_pipeline_cycle_policy_read_bytes_p99=%zu "
           "stream_pipeline_cycle_policy_write_bytes_p50=%zu "
           "stream_pipeline_cycle_policy_write_bytes_p90=%zu "
           "stream_pipeline_cycle_policy_write_bytes_p99=%zu "
           "stream_pipeline_cycle_policy_stall_ns_p50=%zu "
           "stream_pipeline_cycle_policy_stall_ns_p90=%zu "
           "stream_pipeline_cycle_policy_stall_ns_p99=%zu "
           "stream_pipeline_cycle_policy_unused_prefetch_evictions_p50=%zu "
           "stream_pipeline_cycle_policy_unused_prefetch_evictions_p90=%zu "
           "stream_pipeline_cycle_policy_unused_prefetch_evictions_p99=%zu "
           "stream_pipeline_group_visit_0=%zu "
           "stream_pipeline_group_visit_1=%zu "
           "stream_pipeline_group_visit_2=%zu "
           "stream_pipeline_transition_00=%zu "
           "stream_pipeline_transition_01=%zu "
           "stream_pipeline_transition_02=%zu "
           "stream_pipeline_transition_10=%zu "
           "stream_pipeline_transition_11=%zu "
           "stream_pipeline_transition_12=%zu "
           "stream_pipeline_transition_20=%zu "
           "stream_pipeline_transition_21=%zu "
           "stream_pipeline_transition_22=%zu "
           "stream_pipeline_unique_transitions=%zu "
           "stream_pipeline_worst_cycle_index=%zu "
           "stream_pipeline_worst_cycle_group=%zu "
           "stream_pipeline_worst_cycle_prev_group=%zu "
           "stream_pipeline_order_sequence=%s "
           "stream_pipeline_phase_chunks=%zu "
           "stream_pipeline_phase_return_cycles=%zu "
           "stream_pipeline_phase_return_policy_demand_faults=%zu "
           "stream_pipeline_phase_return_policy_read_bytes=%zu "
           "stream_pipeline_phase_return_policy_write_bytes=%zu "
           "stream_pipeline_phase_return_policy_stall_ns=%zu "
           "stream_pipeline_phase_return_policy_hot_evicted_bytes=%zu "
           "stream_pipeline_phase_return_policy_unused_prefetch_evictions=%zu "
           "stream_pipeline_phase_return_estimated_hits=%zu "
           "stream_pipeline_phase_return_estimated_hit_ratio=%.6f "
           "stream_pipeline_phase_warm_return_cycles=%zu "
           "stream_pipeline_phase_warm_return_policy_demand_faults=%zu "
           "stream_pipeline_phase_warm_return_policy_read_bytes=%zu "
           "stream_pipeline_phase_warm_return_policy_write_bytes=%zu "
           "stream_pipeline_phase_warm_return_policy_stall_ns=%zu "
           "stream_pipeline_phase_warm_return_policy_hot_evicted_bytes=%zu "
           "stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions=%zu "
           "stream_pipeline_phase_warm_return_estimated_hits=%zu "
           "stream_pipeline_phase_warm_return_estimated_hit_ratio=%.6f "
           "stream_pipeline_phase_decoy_cycles=%zu "
           "stream_pipeline_phase_decoy_policy_demand_faults=%zu "
           "stream_pipeline_phase_decoy_policy_read_bytes=%zu "
           "stream_pipeline_phase_decoy_policy_write_bytes=%zu "
           "stream_pipeline_phase_decoy_policy_stall_ns=%zu "
           "stream_pipeline_phase_decoy_policy_hot_evicted_bytes=%zu "
           "stream_pipeline_phase_decoy_policy_unused_prefetch_evictions=%zu "
           "policy_pivot_return_faults=%zu "
           "policy_pivot_return_touches=%zu "
           "policy_pivot_return_hits=%zu "
           "policy_pivot_hot_return_hit_ratio=%.6f "
           "policy_pivot_adaptation_lag_touches=%zu "
           "policy_irr_hot_return_faults=%zu "
           "policy_irr_hot_return_touches=%zu "
           "policy_irr_hot_return_hits=%zu "
           "policy_irr_hot_return_hit_ratio=%.6f "
           "policy_irr_decoy_return_faults=%zu "
           "policy_irr_decoy_return_touches=%zu "
           "policy_irr_decoy_return_hits=%zu "
           "policy_irr_decoy_return_hit_ratio=%.6f "
           "policy_irr_discrimination_score=%.6f "
           "policy_irr_adaptation_lag_touches=%zu "
           "policy_irr_scan_faults=%zu "
           "policy_irr_scan_read_bytes=%zu "
           "policy_irr_scan_write_bytes=%zu "
           "policy_irr_scan_hot_evicted_bytes=%zu "
           "policy_irr_scan_unused_prefetch_evictions=%zu "
           "policy_irr_scan_stall_ns=%zu "
           "stream_prefetch_ns=%llu stream_prepare_write_ns=%llu "
           "stream_reclaim_ns=%llu stream_init_ns=%llu "
           "stream_copy_ns=%llu stream_scale_ns=%llu "
           "stream_add_ns=%llu stream_triad_ns=%llu\n",
           argv[1], size, touches, touched_mib, seconds, mib_per_sec,
           (unsigned long long)checksum, managed_delta, reclaim_delta,
           reclaimed_delta, anon_delta, file_delta, migrated_delta,
           promoted_delta, after.uffd_pager_available, uffd_alloc_delta,
           uffd_fault_delta, uffd_eviction_delta, after.uffd_resident_bytes,
           uffd_fallback_delta, migration_policy,
           policy_prefetch_requests, policy_prefetch_admitted,
           policy_prefetch_completed, policy_prefetch_useful,
           policy_prefetch_late, policy_prefetch_unused_evictions,
           policy_prefetch_bytes, policy_prefetch_useful_bytes,
           policy_prefetch_unused_evicted_bytes,
           policy_prefetch_observation,
           policy_prefetch_accuracy_observed,
           policy_prefetch_coverage_observed, policy_admission_requests,
           policy_admission_rejected, policy_demotions, policy_promotions,
           policy_evicted_hot_bytes, policy_migration_read_bytes,
           policy_migration_write_bytes, policy_read_amplification,
           policy_write_amplification, policy_migration_mib_per_sec,
           policy_demand_faults, policy_demand_fault_stall_ns,
           policy_demand_fault_stall_samples,
           after.policy_demand_fault_stall_p50_ns,
           after.policy_demand_fault_stall_p90_ns,
           after.policy_demand_fault_stall_p99_ns,
           after.policy_demand_fault_stall_max_ns,
           policy_throttle_events, policy_throttle_slept_ns,
           policy_async_prefetch_enqueued,
           policy_async_prefetch_completed,
           policy_async_prefetch_dropped,
           policy_async_completed_without_prefetch,
           policy_async_drop_rate,
           policy_adaptive_windows, policy_adaptive_level,
           policy_adaptive_level_changes, policy_adaptive_prefetch_capped,
           policy_adaptive_admission_rejected,
           policy_adaptive_budget_gate, policy_adaptive_budget_bytes,
           policy_adaptive_window_migration_bytes,
           policy_clean_shadow_tracked_chunks,
           policy_clean_shadow_protect_failures,
           policy_clean_shadow_write_skipped_bytes,
           policy_clean_shadow_write_skipped_chunks,
           policy_clean_shadow_write_faults,
           policy_car_recent_chunks, policy_car_frequent_chunks,
           policy_car_recent_ghost_chunks,
           policy_car_frequent_ghost_chunks,
           policy_car_target_recent_chunks,
           policy_car_recent_ghost_hits,
           policy_car_frequent_ghost_hits,
           policy_car_target_increases,
           policy_car_target_decreases,
           policy_car_second_chances,
           policy_tinylfu_sketch_updates,
           policy_tinylfu_sketch_decays,
           policy_tinylfu_admission_rejected,
           policy_tinylfu_min_score,
           policy_bestoffset_train_samples,
           policy_bestoffset_train_hits,
           policy_bestoffset_slots_created,
           policy_bestoffset_score_decays,
           policy_bestoffset_candidates,
           policy_bestoffset_pressure_rejected,
           policy_bestoffset_unused_penalties,
           policy_bestoffset_top_offset_magnitude,
           policy_bestoffset_top_offset_sign,
           policy_bestoffset_top_score,
           policy_wtinylfu_window_chunks,
           policy_wtinylfu_probation_chunks,
           policy_wtinylfu_protected_chunks,
           policy_wtinylfu_window_evictions,
           policy_wtinylfu_main_admission_rejected,
           policy_wtinylfu_victim_score_rejected,
           policy_successor_chain_candidates,
           policy_successor_chain_rejected,
           policy_successor_chain_depth,
           policy_markov_lead_candidates,
           policy_markov_lead_admitted,
           policy_markov_lead_completed,
           policy_markov_lead_useful,
           policy_phase_candidates,
           policy_phase_admitted,
           policy_phase_completed,
           policy_phase_useful,
           policy_phase_conflicts,
           policy_phase_confidence_rejected,
           policy_phase_budget_rejected,
           policy_phase_safe_victim_rejected,
           policy_phase_victim_rejected,
           policy_phase_duplicate_candidates,
           policy_phase_target_hot_skipped,
           policy_phase_active_slots,
           policy_phase_top_score,
           policy_phase_unused_evictions,
           policy_phase_boundary_prefetches,
           policy_phase_hold_activations,
           policy_phase_shadow_candidates,
           policy_phase_shadow_useful,
           policy_phase_shadow_late,
           policy_phase_shadow_expired,
           policy_phase_shadow_overwritten,
           policy_phase_shadow_probe_candidates,
           policy_phase_shadow_edge_rejected,
           policy_phase_shadow_edge_confirmed,
           policy_phase_shadow_top_late,
           policy_phase_shadow_max_late,
           policy_hint_candidates,
           policy_hint_admitted,
           policy_hint_completed,
           policy_hint_useful,
           policy_hint_rejected,
           policy_arc_t1_chunks,
           policy_arc_t2_chunks,
           policy_arc_b1_chunks,
           policy_arc_b2_chunks,
           policy_arc_p_chunks,
           policy_arc_b1_hits,
           policy_arc_b2_hits,
           policy_arc_target_increases,
           policy_arc_target_decreases,
           policy_arc_t1_hits,
           policy_arc_t2_hits,
           policy_arc_t1_to_t2_promotions,
           policy_arc_replace_t1,
           policy_arc_replace_t2,
           policy_arc_b1_pruned,
           policy_arc_b2_pruned,
           policy_arc_prefetch_admitted_t1,
           policy_arc_prefetch_rejected_pressure,
           policy_arc_prefetch_promoted_to_t2,
           policy_irr_resident_chunks,
           policy_irr_protected_chunks,
           policy_irr_ghost_chunks,
           policy_irr_target_protected_chunks,
           policy_irr_ghost_hits,
           policy_irr_promotions,
           policy_irr_demotions,
           policy_irr_pressure_rejected,
           policy_irr_immature_rejected,
           policy_irr_max_interval_epochs,
           policy_signature_train_samples,
           policy_signature_train_hits,
           policy_signature_slots_created,
           policy_signature_score_decays,
           policy_signature_candidates,
           policy_signature_pressure_rejected,
           policy_signature_unused_penalties,
           policy_signature_chain_candidates,
           policy_signature_chain_rejected,
           policy_signature_chain_depth,
           policy_signature_top_delta_magnitude,
           policy_signature_top_delta_sign,
           policy_signature_top_score,
           policy_hybrid_signature_candidates,
           policy_hybrid_successor_candidates,
           policy_hybrid_stream_candidates,
           policy_hybrid_cohort_candidates,
           policy_hybrid_admission_rejected,
           policy_hybrid_signature_admitted,
           policy_hybrid_successor_admitted,
           policy_hybrid_stream_admitted,
           policy_hybrid_cohort_admitted,
           policy_hybrid_signature_completed,
           policy_hybrid_successor_completed,
           policy_hybrid_stream_completed,
           policy_hybrid_cohort_completed,
           policy_hybrid_signature_useful,
           policy_hybrid_successor_useful,
           policy_hybrid_stream_useful,
           policy_hybrid_cohort_useful,
           after.max_rss, before.current_rss_bytes,
           after.current_rss_bytes, after.high_water_rss_bytes, heartbeat_calls,
           heartbeat_busy_ticks, heartbeat_migrate_bytes,
           heartbeat_reclaimed_bytes, trace_setup_calls, trace_stop_calls,
           trace_faulted_pages, latency_ops, logical_mib, touches,
           policy_sampled_units_per_sec, logical_mib_per_sec,
           logical_mib_per_sec, end_to_end_logical_mib_per_sec,
           mprotect_mechanism_label, mprotect_chunk_bytes, mprotect_sample_pages,
           (unsigned long long)mprotect_warmup_ns,
           (unsigned long long)mprotect_setup_ns,
           (unsigned long long)mprotect_first_touch_total_ns,
           (unsigned long long)mprotect_first_touch_min_ns,
           (unsigned long long)mprotect_first_touch_p50_ns,
           (unsigned long long)mprotect_first_touch_p90_ns,
           (unsigned long long)mprotect_first_touch_p99_ns,
           (unsigned long long)mprotect_first_touch_max_ns,
           (unsigned long long)mprotect_finish_ns,
           (unsigned long long)mprotect_sweep_ns, mprotect_minor_faults_delta,
           mprotect_major_faults_delta, mprotect_voluntary_ctxt_delta,
           mprotect_involuntary_ctxt_delta, mprotect_user_cpu_us_delta,
           mprotect_sys_cpu_us_delta, run_minor_faults_delta,
           run_major_faults_delta, run_inblock_delta, run_oublock_delta,
           run_voluntary_ctxt_delta, run_involuntary_ctxt_delta,
           run_user_cpu_us_delta, run_sys_cpu_us_delta, run_maxrss_kib,
           cgroup_memory_max_bytes, cgroup_memory_max_available,
           cgroup_memory_max_unbounded, cgroup_memory_max_is_max_token,
           cgroup_memory_current_before,
           cgroup_memory_current_after, cgroup_memory_events_high_delta,
           cgroup_memory_events_max_delta, cgroup_memory_events_oom_delta,
           cgroup_swap_max_bytes, cgroup_swap_max_available,
           cgroup_swap_max_unbounded, cgroup_swap_max_is_max_token,
           cgroup_swap_current_before, cgroup_swap_current_after,
           stream_mapping_kind_recorded,
           stream_backing_path_recorded, stream_backing_fs_type,
           stream_backing_is_tmpfs,
           (unsigned long long)heartbeat_total_ns,
           chunk_touch_position_label, stream_copy_mib_per_sec,
           stream_scale_mib_per_sec, stream_add_mib_per_sec,
           stream_triad_mib_per_sec, stream_total_mib_per_sec,
           stream_passes_recorded, stream_first_pass_mib_per_sec,
           stream_median_pass_mib_per_sec, stream_last_pass_mib_per_sec,
           stream_min_pass_mib_per_sec, stream_max_pass_mib_per_sec,
           stream_tile_bytes_recorded, stream_tiles_recorded,
           stream_resident_arrays_recorded,
           stream_pipeline_kernels_recorded, stream_pipeline_cycles_recorded,
           stream_pipeline_group_visits_recorded,
           stream_pipeline_groups_recorded,
           stream_pipeline_group_iterations_recorded,
           stream_pipeline_matrix_bytes_recorded,
           stream_pipeline_group_bytes_recorded,
           stream_pipeline_total_matrix_bytes_recorded,
           stream_pipeline_scalar_recorded,
           stream_pipeline_order_recorded,
           stream_pipeline_seed_recorded,
           stream_pipeline_prediction_recorded,
           stream_pipeline_reclaim_lag_recorded,
           stream_pipeline_reclaim_horizon_recorded,
           stream_pipeline_unique_cold_visits_recorded,
           stream_pipeline_max_cycle_policy_demand_faults,
           stream_pipeline_max_cycle_policy_read_bytes,
           stream_pipeline_max_cycle_policy_write_bytes,
           stream_pipeline_max_cycle_policy_stall_ns,
           stream_pipeline_max_cycle_policy_demotions,
           stream_pipeline_max_cycle_policy_hot_evicted_bytes,
           stream_pipeline_cycle_policy_demand_faults_p50,
           stream_pipeline_cycle_policy_demand_faults_p90,
           stream_pipeline_cycle_policy_demand_faults_p99,
           stream_pipeline_cycle_policy_read_bytes_p50,
           stream_pipeline_cycle_policy_read_bytes_p90,
           stream_pipeline_cycle_policy_read_bytes_p99,
           stream_pipeline_cycle_policy_write_bytes_p50,
           stream_pipeline_cycle_policy_write_bytes_p90,
           stream_pipeline_cycle_policy_write_bytes_p99,
           stream_pipeline_cycle_policy_stall_ns_p50,
           stream_pipeline_cycle_policy_stall_ns_p90,
           stream_pipeline_cycle_policy_stall_ns_p99,
           stream_pipeline_cycle_policy_unused_prefetch_evictions_p50,
           stream_pipeline_cycle_policy_unused_prefetch_evictions_p90,
           stream_pipeline_cycle_policy_unused_prefetch_evictions_p99,
           stream_pipeline_group_visit_0_recorded,
           stream_pipeline_group_visit_1_recorded,
           stream_pipeline_group_visit_2_recorded,
           stream_pipeline_transition_00_recorded,
           stream_pipeline_transition_01_recorded,
           stream_pipeline_transition_02_recorded,
           stream_pipeline_transition_10_recorded,
           stream_pipeline_transition_11_recorded,
           stream_pipeline_transition_12_recorded,
           stream_pipeline_transition_20_recorded,
           stream_pipeline_transition_21_recorded,
           stream_pipeline_transition_22_recorded,
           stream_pipeline_unique_transitions_recorded,
           stream_pipeline_worst_cycle_index_recorded,
           stream_pipeline_worst_cycle_group_recorded,
           stream_pipeline_worst_cycle_prev_group_recorded,
           stream_pipeline_order_sequence_recorded,
           stream_pipeline_phase_chunks_recorded,
           stream_pipeline_phase_return_cycles_recorded,
           stream_pipeline_phase_return_policy_demand_faults,
           stream_pipeline_phase_return_policy_read_bytes,
           stream_pipeline_phase_return_policy_write_bytes,
           stream_pipeline_phase_return_policy_stall_ns,
           stream_pipeline_phase_return_policy_hot_evicted_bytes,
           stream_pipeline_phase_return_policy_unused_prefetch_evictions,
           stream_pipeline_phase_return_estimated_hits,
           stream_pipeline_phase_return_estimated_hit_ratio,
           stream_pipeline_phase_warm_return_cycles_recorded,
           stream_pipeline_phase_warm_return_policy_demand_faults,
           stream_pipeline_phase_warm_return_policy_read_bytes,
           stream_pipeline_phase_warm_return_policy_write_bytes,
           stream_pipeline_phase_warm_return_policy_stall_ns,
           stream_pipeline_phase_warm_return_policy_hot_evicted_bytes,
           stream_pipeline_phase_warm_return_policy_unused_prefetch_evictions,
           stream_pipeline_phase_warm_return_estimated_hits,
           stream_pipeline_phase_warm_return_estimated_hit_ratio,
           stream_pipeline_phase_decoy_cycles_recorded,
           stream_pipeline_phase_decoy_policy_demand_faults,
           stream_pipeline_phase_decoy_policy_read_bytes,
           stream_pipeline_phase_decoy_policy_write_bytes,
           stream_pipeline_phase_decoy_policy_stall_ns,
           stream_pipeline_phase_decoy_policy_hot_evicted_bytes,
           stream_pipeline_phase_decoy_policy_unused_prefetch_evictions,
           policy_pivot_return_faults_recorded,
           policy_pivot_return_touches_recorded,
           policy_pivot_return_hits_recorded,
           policy_pivot_hot_return_hit_ratio_recorded,
           policy_pivot_adaptation_lag_touches_recorded,
           policy_irr_hot_return_faults_recorded,
           policy_irr_hot_return_touches_recorded,
           policy_irr_hot_return_hits_recorded,
           policy_irr_hot_return_hit_ratio_recorded,
           policy_irr_decoy_return_faults_recorded,
           policy_irr_decoy_return_touches_recorded,
           policy_irr_decoy_return_hits_recorded,
           policy_irr_decoy_return_hit_ratio_recorded,
           policy_irr_discrimination_score_recorded,
           policy_irr_adaptation_lag_touches_recorded,
           policy_irr_scan_faults_recorded,
           policy_irr_scan_read_bytes_recorded,
           policy_irr_scan_write_bytes_recorded,
           policy_irr_scan_hot_evicted_bytes_recorded,
           policy_irr_scan_unused_prefetch_evictions_recorded,
           policy_irr_scan_stall_ns_recorded,
           (unsigned long long)stream_prefetch_ns,
           (unsigned long long)stream_prepare_write_ns,
           (unsigned long long)stream_reclaim_ns,
           (unsigned long long)stream_init_ns,
           (unsigned long long)stream_copy_ns,
           (unsigned long long)stream_scale_ns,
           (unsigned long long)stream_add_ns,
           (unsigned long long)stream_triad_ns);

    int expect_reclaim = getenv("MAI_ACCESS_EXPECT_RECLAIM") != NULL;
    size_t expected_managed_delta =
        env_count("MAI_ACCESS_EXPECT_MANAGED_DELTA", 0);
    int expect_migrated = getenv("MAI_ACCESS_EXPECT_MIGRATED") != NULL;
    int expect_promoted = getenv("MAI_ACCESS_EXPECT_PROMOTED") != NULL;
    int expect_uffd = getenv("MAI_ACCESS_EXPECT_UFFD") != NULL;
    size_t expected_uffd_delta =
        env_count("MAI_ACCESS_EXPECT_UFFD_DELTA", 0);
    int expect_uffd_faults = getenv("MAI_ACCESS_EXPECT_UFFD_FAULTS") != NULL;
    int expect_uffd_evictions =
        getenv("MAI_ACCESS_EXPECT_UFFD_EVICTIONS") != NULL;
    int expect_no_uffd_fallback =
        getenv("MAI_ACCESS_EXPECT_NO_UFFD_FALLBACK") != NULL;
    if (expect_managed && managed_delta == 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access-pattern allocation was not MAI-managed");
    }
    if (expected_managed_delta != 0 &&
        managed_delta != expected_managed_delta) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access-pattern managed allocation count was unexpected");
    }
    if (expect_reclaim && (reclaim_delta == 0 || reclaimed_delta == 0)) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not exercise MAI reclaim");
    }
    if (expect_migrated && migrated_delta == 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not migrate managed pages");
    }
    if (expect_promoted && promoted_delta == 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not promote managed pages");
    }
    if (expect_uffd &&
        (after.uffd_pager_available == 0 || uffd_alloc_delta == 0)) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not use the UFFD pager");
    }
    if (expected_uffd_delta != 0 &&
        uffd_alloc_delta != expected_uffd_delta) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access-pattern UFFD allocation count was unexpected");
    }
    if (expect_uffd_faults && uffd_fault_delta == 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not exercise UFFD faults");
    }
    if (expect_uffd_evictions && uffd_eviction_delta == 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern did not exercise UFFD evictions");
    }
    if (expect_no_uffd_fallback && uffd_fallback_delta != 0) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern unexpectedly fell back from UFFD");
    }
    if (mib_per_sec < min_mib_per_sec) {
        free_benchmark_buffer(buffer, size, free_with_munmap);
        return fail("access pattern throughput was below the configured floor");
    }

    free_benchmark_buffer(buffer, size, free_with_munmap);
    return 0;
}
