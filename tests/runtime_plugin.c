#define _GNU_SOURCE

#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

__attribute__((visibility("default")))
void* mai_plugin_alloc(size_t size) {
    unsigned char* ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }

    memset(ptr, 0x3c, size);
    return ptr;
}

__attribute__((visibility("default")))
size_t mai_plugin_usable(void* ptr) {
    return malloc_usable_size(ptr);
}

__attribute__((visibility("default")))
void mai_plugin_free(void* ptr) {
    free(ptr);
}
