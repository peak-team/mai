#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef int (*get_stats_fn)(MaiStats*);
typedef int (*reclaim_all_fn)(void);

static size_t page_size_bytes = 4096;
static get_stats_fn get_stats = NULL;
static reclaim_all_fn reclaim_all = NULL;

static int fail(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 1;
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

static int load_stats(MaiStats* stats) {
    if (!get_stats) {
        get_stats = (get_stats_fn)dlsym(RTLD_DEFAULT, "mai_get_stats");
    }
    if (!get_stats) {
        return -1;
    }
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

static unsigned char expected_byte(size_t page_index, size_t pass) {
    return (unsigned char)((page_index * 1315423911ULL + pass * 2654435761ULL) & 0xff);
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

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s stream|stride|sparse|random_hotset <size>\n", argv[0]);
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
    if (load_stats(&before) != 0) {
        return fail("mai_get_stats is unavailable; run with libmai preloaded");
    }

    unsigned char* buffer = malloc(size);
    if (!buffer) {
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
    } else {
        free(buffer);
        return fail("unknown access pattern");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (rc != 0) {
        free(buffer);
        return fail("access pattern failed or data verification failed");
    }

    if (load_stats(&after) != 0) {
        free(buffer);
        return fail("mai_get_stats failed after access pattern");
    }

    size_t managed_delta = after.managed_allocations - before.managed_allocations;
    size_t reclaim_delta = after.reclaim_calls - before.reclaim_calls;
    size_t reclaimed_delta = after.reclaimed_bytes - before.reclaimed_bytes;
    double seconds = seconds_since(&start, &end);
    double touched_mib = ((double)touches * (double)page_size_bytes) /
        (1024.0 * 1024.0);
    double mib_per_sec = seconds > 0.0 ? touched_mib / seconds : 0.0;
    double min_mib_per_sec = env_double("MAI_ACCESS_MIN_MIB_PER_SEC", 0.0);

    printf("mode=%s size=%zu touches=%zu touched_mib=%.3f seconds=%.6f "
           "mib_per_sec=%.3f checksum=%llu managed_delta=%zu "
           "reclaim_delta=%zu reclaimed_delta=%zu max_rss=%zu\n",
           argv[1], size, touches, touched_mib, seconds, mib_per_sec,
           (unsigned long long)checksum, managed_delta, reclaim_delta,
           reclaimed_delta, after.max_rss);

    int expect_reclaim = getenv("MAI_ACCESS_EXPECT_RECLAIM") != NULL;
    if (managed_delta == 0) {
        free(buffer);
        return fail("access-pattern allocation was not MAI-managed");
    }
    if (expect_reclaim && (reclaim_delta == 0 || reclaimed_delta == 0)) {
        free(buffer);
        return fail("access pattern did not exercise MAI reclaim");
    }
    if (mib_per_sec < min_mib_per_sec) {
        free(buffer);
        return fail("access pattern throughput was below the configured floor");
    }

    free(buffer);
    return 0;
}
