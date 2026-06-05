#define _GNU_SOURCE

#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>

static unsigned char local_heap[32768];

__attribute__((visibility("default")))
void* malloc(size_t size) {
    if (size > sizeof(local_heap)) {
        errno = ENOMEM;
        return NULL;
    }

    return local_heap;
}

__attribute__((visibility("default")))
void free(void* ptr) {
    (void)ptr;
}

__attribute__((visibility("default")))
size_t malloc_usable_size(void* ptr) {
    (void)ptr;
    return 0;
}

__attribute__((visibility("default")))
void* mai_local_alloc(size_t size) {
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }

    memset(ptr, 0x7d, size);
    return ptr;
}

__attribute__((visibility("default")))
size_t mai_local_usable(void* ptr) {
    return malloc_usable_size(ptr);
}

__attribute__((visibility("default")))
void mai_local_free(void* ptr) {
    free(ptr);
}
