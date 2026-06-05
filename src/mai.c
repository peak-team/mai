#include "malloc_interceptor.h"

static pthread_mutex_t peak_lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static int peak_initialized = 0;

void peak_init(void) {
    pthread_mutex_lock(&peak_lifecycle_mutex);

    if (!peak_initialized && malloc_interceptor_attach() == 0) {
        peak_initialized = 1;
    }

    pthread_mutex_unlock(&peak_lifecycle_mutex);
}

void peak_fini(void) {
    pthread_mutex_lock(&peak_lifecycle_mutex);

    if (peak_initialized) {
        malloc_interceptor_detach();
        peak_initialized = 0;
    }

    pthread_mutex_unlock(&peak_lifecycle_mutex);
}

__attribute__((constructor))
static void mai_constructor(void) {
    peak_init();
}

__attribute__((destructor))
static void mai_destructor(void) {
    peak_fini();
}
