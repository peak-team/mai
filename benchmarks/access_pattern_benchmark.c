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
#include <time.h>
#include <unistd.h>

typedef int (*get_stats_fn)(MaiStats*);
typedef int (*get_stats_sized_fn)(MaiStats*, size_t);
typedef int (*reclaim_all_fn)(void);
typedef int (*trace_access_fn)(void*, size_t, const MaiAccessTraceOptions*);
typedef int (*get_access_trace_fn)(void*, MaiAccessTraceSnapshot*);
typedef int (*stop_access_trace_fn)(void*);
typedef int (*heartbeat_fn)(const MaiHeartbeatOptions*, MaiHeartbeatSnapshot*);
typedef int (*range_op_fn)(void*, size_t);

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
static size_t stream_pipeline_max_cycle_policy_demand_faults = 0;
static size_t stream_pipeline_max_cycle_policy_read_bytes = 0;
static size_t stream_pipeline_max_cycle_policy_write_bytes = 0;
static size_t stream_pipeline_max_cycle_policy_stall_ns = 0;
static size_t stream_pipeline_max_cycle_policy_demotions = 0;
static size_t stream_pipeline_max_cycle_policy_hot_evicted_bytes = 0;
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

static int mode_uses_stream_kernel(const char* mode) {
    return strcmp(mode, "stream_bandwidth") == 0 ||
           strcmp(mode, "stream_tiled_bandwidth") == 0 ||
           strcmp(mode, "stream_anon_mmap") == 0 ||
           strcmp(mode, "stream_shared_file") == 0 ||
           strcmp(mode, "stream_private_file") == 0;
}

static int mode_uses_stream_pipeline(const char* mode) {
    return strcmp(mode, "policy_stream_pipeline") == 0 ||
           strcmp(mode, "stream_kernel_pipeline") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_anon_mmap") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_shared_file") == 0 ||
           strcmp(mode, "stream_kernel_pipeline_private_file") == 0;
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
    if (!reclaim_all) {
        reclaim_all = (reclaim_all_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_all");
    }
    if (!reclaim_all) {
        return -1;
    }
    return reclaim_all();
}

static void load_range_ops_optional(void) {
    if (!prefetch_range) {
        prefetch_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_prefetch");
    }
    if (!prepare_write_range) {
        prepare_write_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_prepare_write");
    }
    if (!reclaim_range) {
        reclaim_range = (range_op_fn)dlsym(RTLD_DEFAULT, "mai_reclaim_range");
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

    int use_prefetch = env_count_compat("MAI_BENCH_STREAM_TILE_PREFETCH",
                                        "MAI_STREAM_TILE_PREFETCH", 1) != 0;
    int use_prepare_write =
        env_count_compat("MAI_BENCH_STREAM_TILE_PREPARE_WRITE",
                         "MAI_STREAM_TILE_PREPARE_WRITE", 1) != 0;
    int use_reclaim = env_count_compat("MAI_BENCH_STREAM_TILE_RECLAIM",
                                       "MAI_STREAM_TILE_RECLAIM", 1) != 0;
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
    size_t current = stream_pipeline_rng_next(&state) % STREAM_PIPELINE_GROUPS;
    for (size_t cycle = 0; cycle < cycles; cycle++) {
        order[cycle] = current;
        if (strcmp(mode, "random_no_repeat") == 0) {
            current = (current + 1 +
                       (stream_pipeline_rng_next(&state) %
                        (STREAM_PIPELINE_GROUPS - 1))) %
                STREAM_PIPELINE_GROUPS;
        } else {
            current = stream_pipeline_rng_next(&state) % STREAM_PIPELINE_GROUPS;
        }
    }
    return 0;
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
    if (!cycle_rates) {
        goto cleanup;
    }
    group_order = calloc(cycles, sizeof(*group_order));
    if (!group_order || stream_pipeline_build_order(group_order, cycles) != 0) {
        goto cleanup;
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
        group_visits[group]++;

        if (cycle_stats_available) {
            MaiStats cycle_stats;
            int current_stats_available = 0;
            if (load_stats_optional(&cycle_stats, &current_stats_available) == 0 &&
                current_stats_available) {
                size_t delta =
                    size_delta(cycle_stats.policy_demand_faults,
                               previous_cycle_stats.policy_demand_faults);
                if (delta > stream_pipeline_max_cycle_policy_demand_faults) {
                    stream_pipeline_max_cycle_policy_demand_faults = delta;
                }
                delta = size_delta(cycle_stats.policy_migration_read_bytes,
                                   previous_cycle_stats.policy_migration_read_bytes);
                if (delta > stream_pipeline_max_cycle_policy_read_bytes) {
                    stream_pipeline_max_cycle_policy_read_bytes = delta;
                }
                delta = size_delta(cycle_stats.policy_migration_write_bytes,
                                   previous_cycle_stats.policy_migration_write_bytes);
                if (delta > stream_pipeline_max_cycle_policy_write_bytes) {
                    stream_pipeline_max_cycle_policy_write_bytes = delta;
                }
                delta = size_delta(cycle_stats.policy_demand_fault_stall_ns,
                                   previous_cycle_stats.policy_demand_fault_stall_ns);
                if (delta > stream_pipeline_max_cycle_policy_stall_ns) {
                    stream_pipeline_max_cycle_policy_stall_ns = delta;
                }
                delta = size_delta(cycle_stats.policy_demotions,
                                   previous_cycle_stats.policy_demotions);
                if (delta > stream_pipeline_max_cycle_policy_demotions) {
                    stream_pipeline_max_cycle_policy_demotions = delta;
                }
                delta = size_delta(cycle_stats.policy_evicted_hot_bytes,
                                   previous_cycle_stats.policy_evicted_hot_bytes);
                if (delta > stream_pipeline_max_cycle_policy_hot_evicted_bytes) {
                    stream_pipeline_max_cycle_policy_hot_evicted_bytes = delta;
                }
                previous_cycle_stats = cycle_stats;
            } else {
                cycle_stats_available = 0;
            }
        }
    }

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
                "policy_multistream_stride|policy_hotset_scan|"
                "policy_successor_cycle|policy_spatial_region_mask|"
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
    int expect_managed = 1;
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

    unsigned char* buffer = NULL;
    int free_with_munmap = 0;
    if (allocate_benchmark_buffer(argv[1], size, &buffer, &free_with_munmap) != 0 ||
        !buffer) {
        return fail("access-pattern allocation failed");
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
    } else if (mode_uses_stream_pipeline(argv[1])) {
        rc = run_stream_kernel_pipeline(argv[1], buffer, size, &checksum,
                                        &touches);
    } else if (strcmp(argv[1], "policy_multistream_stride") == 0) {
        rc = run_policy_multistream_stride(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_hotset_scan") == 0) {
        rc = run_policy_hotset_scan(buffer, size, &checksum, &touches);
    } else if (strcmp(argv[1], "policy_successor_cycle") == 0) {
        rc = run_policy_successor_cycle(buffer, size, &checksum, &touches);
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
           "policy_adaptive_windows=%zu "
           "policy_adaptive_level=%zu "
           "policy_adaptive_level_changes=%zu "
           "policy_adaptive_prefetch_capped=%zu "
           "policy_adaptive_admission_rejected=%zu "
           "policy_clean_shadow_tracked_chunks=%zu "
           "policy_clean_shadow_protect_failures=%zu "
           "policy_clean_shadow_write_skipped_bytes=%zu "
           "policy_clean_shadow_write_skipped_chunks=%zu "
           "policy_clean_shadow_write_faults=%zu "
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
           "mprotect_sys_cpu_us_delta=%ld heartbeat_total_ns=%llu "
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
           "stream_pipeline_max_cycle_policy_demand_faults=%zu "
           "stream_pipeline_max_cycle_policy_read_bytes=%zu "
           "stream_pipeline_max_cycle_policy_write_bytes=%zu "
           "stream_pipeline_max_cycle_policy_stall_ns=%zu "
           "stream_pipeline_max_cycle_policy_demotions=%zu "
           "stream_pipeline_max_cycle_policy_hot_evicted_bytes=%zu "
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
           policy_adaptive_windows, policy_adaptive_level,
           policy_adaptive_level_changes, policy_adaptive_prefetch_capped,
           policy_adaptive_admission_rejected,
           policy_clean_shadow_tracked_chunks,
           policy_clean_shadow_protect_failures,
           policy_clean_shadow_write_skipped_bytes,
           policy_clean_shadow_write_skipped_chunks,
           policy_clean_shadow_write_faults,
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
           mprotect_sys_cpu_us_delta, (unsigned long long)heartbeat_total_ns,
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
           stream_pipeline_max_cycle_policy_demand_faults,
           stream_pipeline_max_cycle_policy_read_bytes,
           stream_pipeline_max_cycle_policy_write_bytes,
           stream_pipeline_max_cycle_policy_stall_ns,
           stream_pipeline_max_cycle_policy_demotions,
           stream_pipeline_max_cycle_policy_hot_evicted_bytes,
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
