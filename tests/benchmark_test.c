#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    size_t iterations;
    size_t size;
    uintptr_t checksum;
} WorkerArgs;

static double seconds_since(const struct timespec* start, const struct timespec* end) {
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    return (double)sec + (double)nsec / 1000000000.0;
}

static int parse_size(const char* value, size_t* out) {
    char* end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    *out = (size_t)parsed;
    return 0;
}

static void* worker_loop(void* arg) {
    WorkerArgs* worker = (WorkerArgs*)arg;
    uintptr_t checksum = 0;

    for (size_t i = 0; i < worker->iterations; i++) {
        unsigned char* ptr = malloc(worker->size);
        if (!ptr) {
            worker->checksum = UINTPTR_MAX;
            return NULL;
        }
        ptr[0] = (unsigned char)i;
        ptr[worker->size - 1] = (unsigned char)(i >> 8);
        checksum += (uintptr_t)ptr;
        checksum += ptr[0];
        checksum += ptr[worker->size - 1];
        free(ptr);
    }

    worker->checksum = checksum;
    return NULL;
}

static int run_single(size_t iterations, size_t size) {
    WorkerArgs worker = {
        .iterations = iterations,
        .size = size,
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

    double seconds = seconds_since(&start, &end);
    double ns_per_op = seconds * 1000000000.0 / (double)iterations;
    printf("mode=single iterations=%zu size=%zu seconds=%.9f ns_per_op=%.3f checksum=%zu\n",
           iterations, size, seconds, ns_per_op, (size_t)worker.checksum);
    return 0;
}

static int run_threaded(size_t iterations, size_t size, size_t thread_count) {
    pthread_t* threads = calloc(thread_count, sizeof(*threads));
    WorkerArgs* workers = calloc(thread_count, sizeof(*workers));
    if (!threads || !workers) {
        free(threads);
        free(workers);
        return 1;
    }

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
        if (pthread_create(&threads[i], NULL, worker_loop, &workers[i]) != 0) {
            free(threads);
            free(workers);
            return 1;
        }
    }

    uintptr_t checksum = 0;
    for (size_t i = 0; i < thread_count; i++) {
        if (pthread_join(threads[i], NULL) != 0 || workers[i].checksum == UINTPTR_MAX) {
            free(threads);
            free(workers);
            return 1;
        }
        checksum += workers[i].checksum;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    free(threads);
    free(workers);

    size_t total_iterations = per_thread * thread_count;
    double seconds = seconds_since(&start, &end);
    double ns_per_op = seconds * 1000000000.0 / (double)total_iterations;
    printf("mode=threaded iterations=%zu threads=%zu size=%zu seconds=%.9f ns_per_op=%.3f checksum=%zu\n",
           total_iterations, thread_count, size, seconds, ns_per_op, (size_t)checksum);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s single|threaded <iterations> <size> [threads]\n", argv[0]);
        return 2;
    }

    size_t iterations = 0;
    size_t size = 0;
    if (parse_size(argv[2], &iterations) != 0 || parse_size(argv[3], &size) != 0 ||
        iterations == 0 || size == 0) {
        fprintf(stderr, "invalid iterations or size\n");
        return 2;
    }

    if (strcmp(argv[1], "single") == 0) {
        return run_single(iterations, size);
    }
    if (strcmp(argv[1], "threaded") == 0) {
        size_t threads = 4;
        if (argc >= 5 && (parse_size(argv[4], &threads) != 0 || threads == 0)) {
            fprintf(stderr, "invalid thread count\n");
            return 2;
        }
        return run_threaded(iterations, size, threads);
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
