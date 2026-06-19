#define _GNU_SOURCE

#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>

#if defined(__GNUC__)
#define MAI_PLUGIN_API \
    __attribute__((visibility("default"), noinline, used, optimize("O0")))
#else
#define MAI_PLUGIN_API
#endif

static unsigned char local_heap[32768];
static volatile size_t local_usable_zero = 0;
static volatile void* local_free_sink = NULL;

MAI_PLUGIN_API
void* malloc(size_t size) {
    if (size > sizeof(local_heap)) {
        errno = ENOMEM;
        return NULL;
    }

    return local_heap;
}

MAI_PLUGIN_API
void free(void* ptr) {
    local_free_sink = ptr;
    local_free_sink = NULL;
}

MAI_PLUGIN_API
size_t malloc_usable_size(void* ptr) {
    if (!ptr) {
        return local_usable_zero;
    }
    return local_usable_zero;
}

MAI_PLUGIN_API
void* mai_local_alloc(size_t size) {
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }

    memset(ptr, 0x7d, size);
    return ptr;
}

MAI_PLUGIN_API
size_t mai_local_usable(void* ptr) {
    return malloc_usable_size(ptr);
}

MAI_PLUGIN_API
void mai_local_free(void* ptr) {
    free(ptr);
}
