#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    size_t iterations;
    size_t size;
    int zero_allocate;
    uintptr_t checksum;
} WorkerArgs;

typedef void* (*bench_malloc_fn)(size_t);
typedef void* (*bench_calloc_fn)(size_t, size_t);
typedef void (*bench_free_fn)(void*);
typedef int (*get_stats_fn)(MaiStats*);
typedef int (*get_stats_sized_fn)(MaiStats*, size_t);

static bench_malloc_fn benchmark_malloc = malloc;
static bench_calloc_fn benchmark_calloc = calloc;
static bench_free_fn benchmark_free = free;
static const char* allocator_source = "default";

static double seconds_since(const struct timespec* start, const struct timespec* end) {
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    }
    return (double)sec + (double)nsec / 1000000000.0;
}

static int parse_size(const char* value, size_t* out) {
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

static int configure_allocator_source(void) {
    const char* source = getenv("MAI_BENCH_ALLOCATOR");
    if (!source || source[0] == '\0' || strcmp(source, "default") == 0) {
        allocator_source = "default";
        benchmark_malloc = malloc;
        benchmark_calloc = calloc;
        benchmark_free = free;
        return 0;
    }

    if (strcmp(source, "libc") == 0) {
        void* handle = dlopen("libc.so.6", RTLD_LAZY | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "failed to open libc.so.6: %s\n", dlerror());
            return -1;
        }

        void* malloc_symbol = dlsym(handle, "malloc");
        void* calloc_symbol = dlsym(handle, "calloc");
        void* free_symbol = dlsym(handle, "free");
        if (!malloc_symbol || !calloc_symbol || !free_symbol) {
            fprintf(stderr, "failed to resolve libc malloc/free: %s\n", dlerror());
            return -1;
        }

        benchmark_malloc = (bench_malloc_fn)malloc_symbol;
        benchmark_calloc = (bench_calloc_fn)calloc_symbol;
        benchmark_free = (bench_free_fn)free_symbol;
        allocator_source = "libc";
        return 0;
    }

    fprintf(stderr, "unknown MAI_BENCH_ALLOCATOR: %s\n", source);
    return -1;
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

static void* worker_loop(void* arg) {
    WorkerArgs* worker = (WorkerArgs*)arg;
    uintptr_t checksum = 0;

    for (size_t i = 0; i < worker->iterations; i++) {
        unsigned char* ptr = worker->zero_allocate ?
            benchmark_calloc(1, worker->size) : benchmark_malloc(worker->size);
        if (!ptr) {
            worker->checksum = UINTPTR_MAX;
            return NULL;
        }
        if (worker->zero_allocate &&
            (ptr[0] != 0 || ptr[worker->size - 1] != 0)) {
            benchmark_free(ptr);
            worker->checksum = UINTPTR_MAX;
            return NULL;
        }
        ptr[0] = (unsigned char)i;
        ptr[worker->size - 1] = (unsigned char)(i >> 8);
        checksum += (uintptr_t)ptr;
        checksum += ptr[0];
        checksum += ptr[worker->size - 1];
        benchmark_free(ptr);
    }

    worker->checksum = checksum;
    return NULL;
}

static int run_single(size_t iterations, size_t size, int zero_allocate,
                      double* seconds_out, uintptr_t* checksum_out) {
    WorkerArgs worker = {
        .iterations = iterations,
        .size = size,
        .zero_allocate = zero_allocate,
        .checksum = 0,
    };
    struct timespec start;
    struct timespec end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    worker_loop(&worker);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (worker.checksum == UINTPTR_MAX) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    *seconds_out = seconds_since(&start, &end);
    *checksum_out = worker.checksum;
    return 0;
}

static int run_threaded(size_t iterations, size_t size, size_t thread_count,
                        int zero_allocate, size_t* actual_iterations_out,
                        double* seconds_out, uintptr_t* checksum_out) {
    if (thread_count > SIZE_MAX / sizeof(pthread_t) ||
        thread_count > SIZE_MAX / sizeof(WorkerArgs)) {
        return 1;
    }

    pthread_t* threads = benchmark_malloc(thread_count * sizeof(*threads));
    WorkerArgs* workers = benchmark_malloc(thread_count * sizeof(*workers));
    if (!threads || !workers) {
        if (threads) {
            benchmark_free(threads);
        }
        if (workers) {
            benchmark_free(workers);
        }
        return 1;
    }
    memset(threads, 0, thread_count * sizeof(*threads));
    memset(workers, 0, thread_count * sizeof(*workers));

    size_t per_thread = iterations / thread_count;
    if (per_thread == 0) {
        per_thread = 1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (size_t i = 0; i < thread_count; i++) {
        workers[i].iterations = per_thread;
        workers[i].size = size;
        workers[i].zero_allocate = zero_allocate;
        if (pthread_create(&threads[i], NULL, worker_loop, &workers[i]) != 0) {
            benchmark_free(threads);
            benchmark_free(workers);
            return 1;
        }
    }

    uintptr_t checksum = 0;
    for (size_t i = 0; i < thread_count; i++) {
        if (pthread_join(threads[i], NULL) != 0 || workers[i].checksum == UINTPTR_MAX) {
            benchmark_free(threads);
            benchmark_free(workers);
            return 1;
        }
        checksum += workers[i].checksum;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    benchmark_free(threads);
    benchmark_free(workers);

    size_t total_iterations = per_thread * thread_count;
    *actual_iterations_out = total_iterations;
    *seconds_out = seconds_since(&start, &end);
    *checksum_out = checksum;
    return 0;
}

static int verify_expected_path(const char* expected_path, int stats_available,
                                const MaiStats* before, const MaiStats* after) {
    if (!expected_path || expected_path[0] == '\0') {
        return 0;
    }

    if (!stats_available) {
        fprintf(stderr, "MAI_BENCH_EXPECT_PATH requires mai_get_stats\n");
        return 1;
    }

    size_t preload_delta =
        after->allocator_preload_calls - before->allocator_preload_calls;
    size_t frida_delta = after->allocator_frida_calls - before->allocator_frida_calls;
    size_t managed_delta = after->managed_allocations - before->managed_allocations;

    if (strcmp(expected_path, "preload") == 0) {
        if (after->allocator_hook_mode != 1 ||
            (preload_delta == 0 && managed_delta == 0) ||
            frida_delta != 0) {
            fprintf(stderr,
                    "expected preload path, got hook_mode=%zu preload_delta=%zu "
                    "frida_delta=%zu managed_delta=%zu\n",
                    after->allocator_hook_mode, preload_delta, frida_delta,
                    managed_delta);
            return 1;
        }
        return 0;
    }

    if (strcmp(expected_path, "frida") == 0) {
        if (after->allocator_hook_mode != 2 ||
            (frida_delta == 0 && managed_delta == 0) ||
            preload_delta != 0) {
            fprintf(stderr,
                    "expected Frida path, got hook_mode=%zu preload_delta=%zu "
                    "frida_delta=%zu managed_delta=%zu\n",
                    after->allocator_hook_mode, preload_delta, frida_delta,
                    managed_delta);
            return 1;
        }
        return 0;
    }

    if (strcmp(expected_path, "any") == 0) {
        if (preload_delta == 0 && frida_delta == 0 && managed_delta == 0) {
            fprintf(stderr, "expected any MAI allocator path, got no path calls\n");
            return 1;
        }
        return 0;
    }

    fprintf(stderr, "unknown MAI_BENCH_EXPECT_PATH: %s\n", expected_path);
    return 1;
}

static void print_result(const char* mode, size_t iterations, size_t size,
                         size_t thread_count, double seconds, uintptr_t checksum,
                         int stats_available, const MaiStats* before,
                         const MaiStats* after) {
    double ns_per_op = seconds * 1000000000.0 / (double)iterations;

    printf("mode=%s iterations=%zu", mode, iterations);
    if (strcmp(mode, "threaded") == 0) {
        printf(" threads=%zu", thread_count);
    }
    printf(" size=%zu allocator=%s seconds=%.9f ns_per_op=%.3f checksum=%zu",
           size, allocator_source, seconds, ns_per_op, (size_t)checksum);

    if (stats_available) {
        printf(" hook_mode=%zu libc_patches=%zu preload_delta=%zu frida_delta=%zu "
               "managed_delta=%zu",
               after->allocator_hook_mode,
               after->allocator_libc_patches,
               after->allocator_preload_calls - before->allocator_preload_calls,
               after->allocator_frida_calls - before->allocator_frida_calls,
               after->managed_allocations - before->managed_allocations);
    } else {
        printf(" hook_mode=unavailable preload_delta=unavailable frida_delta=unavailable "
               "managed_delta=unavailable");
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s single|single_calloc|threaded|threaded_calloc "
                "<iterations> <size> [threads]\n"
                "  MAI_BENCH_ALLOCATOR=default|libc\n"
                "  MAI_BENCH_EXPECT_PATH=preload|frida|any\n",
                argv[0]);
        return 2;
    }

    size_t iterations = 0;
    size_t size = 0;
    if (parse_size(argv[2], &iterations) != 0 || parse_size(argv[3], &size) != 0 ||
        iterations == 0 || size == 0) {
        fprintf(stderr, "invalid iterations or size\n");
        return 2;
    }

    if (configure_allocator_source() != 0) {
        return 2;
    }

    MaiStats before;
    MaiStats after;
    int stats_available = load_stats(&before) == 0;
    const char* expected_path = getenv("MAI_BENCH_EXPECT_PATH");

    int rc = 0;
    double seconds = 0.0;
    uintptr_t checksum = 0;
    size_t actual_iterations = iterations;
    size_t threads = 1;

    int zero_allocate = 0;
    if (strcmp(argv[1], "single") == 0 || strcmp(argv[1], "single_calloc") == 0) {
        zero_allocate = strcmp(argv[1], "single_calloc") == 0;
        rc = run_single(iterations, size, zero_allocate, &seconds, &checksum);
    } else if (strcmp(argv[1], "threaded") == 0 ||
               strcmp(argv[1], "threaded_calloc") == 0) {
        zero_allocate = strcmp(argv[1], "threaded_calloc") == 0;
        threads = 4;
        if (argc >= 5 && (parse_size(argv[4], &threads) != 0 || threads == 0)) {
            fprintf(stderr, "invalid thread count\n");
            return 2;
        }
        rc = run_threaded(iterations, size, threads, zero_allocate,
                          &actual_iterations, &seconds, &checksum);
    } else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 2;
    }

    if (rc != 0) {
        return rc;
    }

    if (stats_available && load_stats(&after) != 0) {
        fprintf(stderr, "mai_get_stats failed after benchmark\n");
        return 1;
    }

    if (stats_available &&
        verify_expected_path(expected_path, stats_available, &before, &after) != 0) {
        return 1;
    }
    if (!stats_available && expected_path && expected_path[0] != '\0') {
        return verify_expected_path(expected_path, stats_available, &before, &after);
    }

    print_result(argv[1], actual_iterations, size, threads, seconds, checksum,
                 stats_available, &before, &after);
    return 0;
}
