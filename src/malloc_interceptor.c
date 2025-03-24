#include "malloc_interceptor.h"

// Configuration
#define MMAP_DIR_ENV "MAI_MMAP_PATH"
#define DEFAULT_MMAP_DIR "./"
#define MMAP_FILE_FORMAT "%s/mai_%x_%lx_%lx_%x"

typedef struct {
    void* ptr;
    size_t size;
    int is_mmap;
    char* filename;  // Store filename for mmap allocations
} AllocationEntry;

// Global variables
static GumInterceptor* malloc_interceptor;
static pthread_mutex_t track_mutex = PTHREAD_MUTEX_INITIALIZER;
static GumMetalHashTable* track_table = NULL;
static char mmap_dir[PATH_MAX];
static unsigned int random_seed;
static int cleanup_in_progress = 0;
static gulong max_memory = 0;
static gulong current_memory = 0;

// Original function pointers
static void* (*original_malloc)(size_t size);
static void (*original_free)(void* ptr);
static void* (*original_calloc)(size_t nmemb, size_t size);
static void* (*original_realloc)(void* ptr, size_t size);
static void* (*original_aligned_alloc)(size_t alignment, size_t size);
static int (*original_posix_memalign)(void** memptr, size_t alignment, size_t size);

// Forward declarations for internal use
static void* internal_malloc(size_t size);
static void internal_free(void* ptr);
static void init_table();

static void add_tracking_entry(void* ptr, size_t size, int is_mmap, char* filename) {
    if (!track_table || cleanup_in_progress) return;
    
    AllocationEntry* entry = internal_malloc(sizeof(AllocationEntry));
    if (!entry) return;
    
    entry->ptr = ptr;
    entry->size = size;
    entry->is_mmap = is_mmap;
    entry->filename = filename;  // May be NULL for non-mmap allocations
    
    pthread_mutex_lock(&track_mutex);
        
    gum_metal_hash_table_insert(track_table, ptr, entry);
    current_memory+=size;
    max_memory = current_memory > max_memory ? current_memory : max_memory;
    
    pthread_mutex_unlock(&track_mutex);
}

static AllocationEntry* find_tracking_entry(void* ptr) {
    if (!track_table || cleanup_in_progress) return NULL;
    
    pthread_mutex_lock(&track_mutex);
    
    AllocationEntry* entry = gum_metal_hash_table_lookup(track_table, ptr);

    if (entry && entry->ptr == ptr) {
        pthread_mutex_unlock(&track_mutex);
        return entry;
    }
        
    pthread_mutex_unlock(&track_mutex);
    return NULL;
}

static void remove_tracking_entry(void* ptr) {
    if (!track_table || cleanup_in_progress) return;
    
    pthread_mutex_lock(&track_mutex);

    AllocationEntry* entry = gum_metal_hash_table_lookup(track_table, ptr);
    gum_metal_hash_table_remove(track_table, ptr);
    current_memory-=entry->size;

    pthread_mutex_unlock(&track_mutex);
    if (entry->filename) {
        remove(entry->filename);
        internal_free(entry->filename);
    }
}

// Internal versions of malloc/free for our own use
static void* internal_malloc(size_t size) {
    return original_malloc(size);
}

static void internal_free(void* ptr) {
    original_free(ptr);
}

static void init_table() {
    // Initialize random seed
    random_seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    
    // Get mmap directory from environment
    const char* env_dir = getenv(MMAP_DIR_ENV);
    snprintf(mmap_dir, sizeof(mmap_dir), "%s", 
             env_dir ? env_dir : DEFAULT_MMAP_DIR);
    
    // Create tracking table
    track_table = gum_metal_hash_table_new(g_direct_hash, g_direct_equal);
    if (!track_table) {
        fprintf(stderr, "Failed to initialize tracking table\n");
        exit(1);
    }
}

static void* mmap_fallback(size_t size) {
    char* filename = NULL;
    int fd = -1;
    void* ptr = NULL;
    // fprintf(stderr, "mmap_fallback: %lu\n", size);
    // Generate unique filename with PID, TID, timestamp, and random number
    pid_t pid = getpid();
    pthread_t tid = pthread_self();
    time_t timestamp = time(NULL);
    unsigned int random_val = rand_r(&random_seed);
    
    filename = internal_malloc(PATH_MAX);
    if (!filename) goto error;
    
    int result = snprintf(filename, PATH_MAX, MMAP_FILE_FORMAT, 
            mmap_dir, pid, (unsigned long)tid, (unsigned long)timestamp, random_val);

    // Check for truncation
    if (result < 0 || result >= PATH_MAX) goto error;

    // Create the file
    fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd == -1) goto error;
    
    // Set file size
    if (ftruncate(fd, size) == -1) goto error;
    
    // Map the file
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) goto error;
    
    close(fd);
    
    // Track this allocation
    add_tracking_entry(ptr, size, 1, filename);
    return ptr;
    
error:
    if (fd != -1) close(fd);
    if (filename) {
        unlink(filename);
        internal_free(filename);
    }
    return NULL;
}

// Custom implementation of malloc
static void* custom_malloc(size_t size) {
    void* ptr = original_malloc(size);
    if (ptr) {
        add_tracking_entry(ptr, size, 0, NULL);
        return ptr;
    }
    
    return mmap_fallback(size);
}

// Custom implementation of free
static void custom_free(void* ptr) {
    if (!ptr) return;
    
    AllocationEntry* entry = find_tracking_entry(ptr);
    if (!entry) {
        original_free(ptr);
        return;
    }
        
    if (entry->is_mmap) {
        munmap(ptr, entry->size);
    } else {
        original_free(ptr);
    }
    
    remove_tracking_entry(ptr);
}

// Custom implementation of calloc
static void* custom_calloc(size_t nmemb, size_t size) {
    // Check for overflow in nmemb * size
    if (size && nmemb > SIZE_MAX / size) {
        errno = ENOMEM;
        return NULL;
    }

    size_t total_size = nmemb * size;
    
    // Try original calloc first
    void* ptr = original_calloc(nmemb, size);
    if (ptr) {
        add_tracking_entry(ptr, total_size, 0, NULL);
        return ptr;
    }
    
    // Fall back to mmap + memset
    ptr = mmap_fallback(total_size);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

// Custom implementation of realloc
static void* custom_realloc(void* ptr, size_t size) {
    if (!ptr) return custom_malloc(size);
    if (!size) { custom_free(ptr); return NULL; }
    
    AllocationEntry* entry = find_tracking_entry(ptr);
    if (!entry) {
        // Not tracked by us, use original realloc
        return original_realloc(ptr, size);
    }
    
    void* new_ptr;
    
    if (entry->is_mmap) {
        // For mmap'd regions, we need to do a manual copy
        new_ptr = custom_malloc(size);  // This might use mmap_fallback if needed
        if (!new_ptr) return NULL;
        
        memcpy(new_ptr, ptr, entry->size < size ? entry->size : size);
        custom_free(ptr);  // This will handle unmapping
    } else {
        // Try original realloc first
        new_ptr = original_realloc(ptr, size);
        if (new_ptr) {
            remove_tracking_entry(ptr);
            add_tracking_entry(new_ptr, size, 0, NULL);
        } else {
            // Original realloc failed, try mmap fallback
            new_ptr = mmap_fallback(size);
            if (new_ptr) {
                memcpy(new_ptr, ptr, entry->size < size ? entry->size : size);
                original_free(ptr);
                remove_tracking_entry(ptr);
            }
        }
    }
    
    return new_ptr;
}

// Custom implementation of aligned_alloc
static void* custom_aligned_alloc(size_t alignment, size_t size) {
    void* ptr = original_aligned_alloc(alignment, size);
    if (ptr) {
        add_tracking_entry(ptr, size, 0, NULL);
        return ptr;
    }
    
    // For mmap fallback, we'd need to ensure alignment
    size_t padded_size = size + alignment;
    void* base_ptr = mmap_fallback(padded_size);
    if (!base_ptr) return NULL;
    
    // Adjust pointer to meet alignment
    uintptr_t addr = (uintptr_t)base_ptr;
    uintptr_t aligned_addr = (addr + alignment - 1) & ~(alignment - 1);
    
    // If already aligned, just return
    if (addr == aligned_addr) return base_ptr;
    
    // Update tracking entry
    remove_tracking_entry(base_ptr);
    fprintf(stderr, "Align: %lu %lu\n", addr, aligned_addr);
    add_tracking_entry((void*)aligned_addr, size, 1, NULL);
    
    return (void*)aligned_addr;
}

// Custom implementation of posix_memalign
static int custom_posix_memalign(void** memptr, size_t alignment, size_t size) {    
    int ret = original_posix_memalign(memptr, alignment, size);
    if (ret == 0) {
        add_tracking_entry(*memptr, size, 0, NULL);
        return 0;
    }
    
    // Fallback implementation
    size_t padded_size = size + alignment;
    void* base_ptr = mmap_fallback(padded_size);
    if (!base_ptr) return ENOMEM;
    
    uintptr_t addr = (uintptr_t)base_ptr;
    uintptr_t aligned_addr = (addr + alignment - 1) & ~(alignment - 1);
    
    *memptr = (void*)aligned_addr;
    
    // Update tracking if needed
    if (addr != aligned_addr) {
        remove_tracking_entry(base_ptr);
        add_tracking_entry(*memptr, size, 1, NULL);
    }
    
    return 0;
}

// Main function to attach interceptors
int malloc_interceptor_attach() {
    GumReplaceReturn replace_check;
    gpointer malloc_addr, free_addr, calloc_addr, realloc_addr, aligned_alloc_addr, posix_memalign_addr;
    
    // Initialize Frida interceptor
    malloc_interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(malloc_interceptor);
    
    // Find function addresses
    malloc_addr = gum_find_function("malloc");
    free_addr = gum_find_function("free");
    calloc_addr = gum_find_function("calloc");
    realloc_addr = gum_find_function("realloc");
    aligned_alloc_addr = gum_find_function("aligned_alloc");
    posix_memalign_addr = gum_find_function("posix_memalign");
    
    // Replace functions with our custom implementations
    if (malloc_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  malloc_addr, 
                                                  custom_malloc,
                                                  (gpointer*)(&original_malloc));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace malloc: %d\n", replace_check);
        }
    }
    
    if (free_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  free_addr, 
                                                  custom_free,
                                                  (gpointer*)(&original_free));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace free: %d\n", replace_check);
        }
    }
    
    if (calloc_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  calloc_addr, 
                                                  custom_calloc,
                                                  (gpointer*)(&original_calloc));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace calloc: %d\n", replace_check);
        }
    }
    
    if (realloc_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  realloc_addr, 
                                                  custom_realloc,
                                                  (gpointer*)(&original_realloc));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace realloc: %d\n", replace_check);
        }
    }
    
    if (aligned_alloc_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  aligned_alloc_addr, 
                                                  custom_aligned_alloc,
                                                  (gpointer*)(&original_aligned_alloc));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace aligned_alloc: %d\n", replace_check);
        }
    }
    
    if (posix_memalign_addr) {
        replace_check = gum_interceptor_replace_fast(malloc_interceptor, 
                                                  posix_memalign_addr, 
                                                  custom_posix_memalign,
                                                  (gpointer*)(&original_posix_memalign));
        if (replace_check != GUM_REPLACE_OK) {
            fprintf(stderr, "Failed to replace posix_memalign: %d\n", replace_check);
        }
    }
    
    gum_interceptor_end_transaction(malloc_interceptor);
    
    // Initialize the tracking table if not already done
    init_table();
    
    fprintf(stderr, "Memory allocation functions intercepted successfully\n");
    
    return 0;
}

// Function to detach interceptors and clean up
void malloc_interceptor_dettach() {
    cleanup_in_progress = 1;
    
    gpointer malloc_addr, free_addr, calloc_addr, realloc_addr, aligned_alloc_addr, posix_memalign_addr;
    
    // Find function addresses
    malloc_addr = gum_find_function("malloc");
    free_addr = gum_find_function("free");
    calloc_addr = gum_find_function("calloc");
    realloc_addr = gum_find_function("realloc");
    aligned_alloc_addr = gum_find_function("aligned_alloc");
    posix_memalign_addr = gum_find_function("posix_memalign");
    
    // Revert all interceptors
    if (malloc_addr) gum_interceptor_revert(malloc_interceptor, malloc_addr);
    if (free_addr) gum_interceptor_revert(malloc_interceptor, free_addr);
    if (calloc_addr) gum_interceptor_revert(malloc_interceptor, calloc_addr);
    if (realloc_addr) gum_interceptor_revert(malloc_interceptor, realloc_addr);
    if (aligned_alloc_addr) gum_interceptor_revert(malloc_interceptor, aligned_alloc_addr);
    if (posix_memalign_addr) gum_interceptor_revert(malloc_interceptor, posix_memalign_addr);
    
    // Clean up tracking table if it exists
    gum_metal_hash_table_unref(track_table);
    
    // Release interceptor
    g_object_unref(malloc_interceptor);
    
    fprintf(stderr, "Memory allocation interceptors detached and resources cleaned up\n");
    fprintf(stderr, "Max usage (bytes): %lu\n", max_memory);
}
