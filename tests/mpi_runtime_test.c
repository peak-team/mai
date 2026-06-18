#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <dlfcn.h>
#include <mpi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*get_stats_fn)(MaiStats*);

static int fail(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int skip(const char* message) {
    fprintf(stderr, "%s\n", message);
    return 77;
}

static int load_stats(MaiStats* stats) {
    get_stats_fn get_stats = (get_stats_fn)dlsym(RTLD_DEFAULT, "mai_get_stats");
    if (!get_stats) {
        return -1;
    }
    return get_stats(stats);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    int rc = MPI_Init(NULL, NULL);
    if (rc != MPI_SUCCESS) {
        return fail("MPI_Init failed");
    }

    const size_t size = 8192;
    MaiStats before;
    MaiStats after_alloc;
    MaiStats after_free;
    int result = 0;

    if (load_stats(&before) != 0) {
        result = fail("mai_get_stats failed before MPI_Alloc_mem");
        goto done;
    }

    void* ptr = NULL;
    rc = MPI_Alloc_mem((MPI_Aint)size, MPI_INFO_NULL, &ptr);
    if (rc != MPI_SUCCESS || !ptr) {
        result = skip("MPI_Alloc_mem is unavailable in this MPI configuration");
        goto done;
    }
    memset(ptr, 0x4d, size);

    if (load_stats(&after_alloc) != 0) {
        MPI_Free_mem(ptr);
        result = fail("mai_get_stats failed after MPI_Alloc_mem");
        goto done;
    }

    if (after_alloc.excluded_ranges <= before.excluded_ranges ||
        after_alloc.exclusion_events <= before.exclusion_events ||
        after_alloc.excluded_bytes < before.excluded_bytes + size) {
        MPI_Free_mem(ptr);
        result = fail("MPI_Alloc_mem did not mark the buffer excluded");
        goto done;
    }
    if (after_alloc.managed_allocations != before.managed_allocations) {
        MPI_Free_mem(ptr);
        result = fail("MPI_Alloc_mem allocation was routed into the MAI arena");
        goto done;
    }

    if (MPI_Free_mem(ptr) != MPI_SUCCESS) {
        result = fail("MPI_Free_mem failed");
        goto done;
    }

    if (load_stats(&after_free) != 0) {
        result = fail("mai_get_stats failed after MPI_Free_mem");
        goto done;
    }

    if (after_free.exclusion_release_events <= after_alloc.exclusion_release_events ||
        after_free.excluded_ranges >= after_alloc.excluded_ranges) {
        result = fail("MPI_Free_mem did not release the exclusion");
        goto done;
    }

done:
    if (MPI_Finalize() != MPI_SUCCESS && result == 0) {
        result = fail("MPI_Finalize failed");
    }
    return result;
}
