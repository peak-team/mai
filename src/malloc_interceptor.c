#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <ctype.h>
#include <dlfcn.h>
#include <malloc.h>
#include <stddef.h>
#include <stdatomic.h>
#include <sys/syscall.h>

#include "frida-gum.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define MAI_DEFAULT_THRESHOLD (64ULL * 1024ULL * 1024ULL)
#define MAI_DEFAULT_ARENA_SIZE (1024ULL * 1024ULL * 1024ULL)
#define MAI_MIN_ARENA_SIZE (1024ULL * 1024ULL)
#define MAI_TRACK_BUCKETS 8192
#define MAI_PROFILE_BUCKETS 1024
#define MAI_FILE_TEMPLATE "mai-arena-XXXXXX"
#define MAI_DEFAULT_HOTNESS_SAMPLE_PAGES 64
#define MAI_MAX_HOTNESS_SAMPLE_PAGES 4096
#define MAI_PASS_THROUGH_FLUSH_INTERVAL 1024
#define MAI_ALLOCATOR_HOOK_MODE_PRELOAD 1
#define MAI_ALLOCATOR_HOOK_MODE_FRIDA 2

#if defined(__GNUC__) || defined(__clang__)
#define MAI_LIKELY(value) __builtin_expect(!!(value), 1)
#define MAI_UNLIKELY(value) __builtin_expect(!!(value), 0)
#define MAI_TLS_INITIAL_EXEC __attribute__((tls_model("initial-exec")))
#else
#define MAI_LIKELY(value) (value)
#define MAI_UNLIKELY(value) (value)
#define MAI_TLS_INITIAL_EXEC
#endif

typedef enum {
    RECLAIM_NONE = 0,
    RECLAIM_DONTNEED,
    RECLAIM_PAGEOUT
} ReclaimPolicy;

typedef enum {
    RECLAIM_SELECT_OLDEST = 0,
    RECLAIM_SELECT_LARGEST,
    RECLAIM_SELECT_ALL,
    RECLAIM_SELECT_ADAPTIVE
} ReclaimSelection;

typedef enum {
    BACKEND_ARENA = 0
} BackendType;

typedef enum {
    EXCLUSION_MLOCK = 0,
    EXCLUSION_MLOCKALL,
    EXCLUSION_CUDA_HOST,
    EXCLUSION_CUDA_MANAGED,
    EXCLUSION_HIP_HOST,
    EXCLUSION_HIP_MANAGED,
    EXCLUSION_MPI,
    EXCLUSION_RDMA
} ExclusionKind;

typedef enum {
    HOOK_MALLOC = 0,
    HOOK_FREE,
    HOOK_CALLOC,
    HOOK_REALLOC,
    HOOK_ALIGNED_ALLOC,
    HOOK_POSIX_MEMALIGN,
    HOOK_MEMALIGN,
    HOOK_VALLOC,
    HOOK_PVALLOC,
    HOOK_MALLOC_USABLE_SIZE,
    HOOK_MLOCK,
    HOOK_MLOCK2,
    HOOK_MLOCKALL,
    HOOK_MUNLOCK,
    HOOK_MUNLOCKALL,
    HOOK_CUDA_HOST_ALLOC,
    HOOK_CUDA_MALLOC_HOST,
    HOOK_CUDA_HOST_REGISTER,
    HOOK_CUDA_HOST_UNREGISTER,
    HOOK_CUDA_FREE_HOST,
    HOOK_CUDA_MALLOC_MANAGED,
    HOOK_CUDA_FREE,
    HOOK_HIP_HOST_MALLOC,
    HOOK_HIP_HOST_REGISTER,
    HOOK_HIP_HOST_UNREGISTER,
    HOOK_HIP_HOST_FREE,
    HOOK_HIP_MALLOC_MANAGED,
    HOOK_HIP_FREE,
    HOOK_MPI_ALLOC_MEM,
    HOOK_MPI_FREE_MEM,
    HOOK_IBV_REG_MR,
    HOOK_IBV_REG_MR_IOVA,
    HOOK_IBV_REREG_MR,
    HOOK_IBV_DEREG_MR,
    HOOK_RDMA_REG_MSGS,
    HOOK_RDMA_REG_READ,
    HOOK_RDMA_REG_WRITE,
    HOOK_RDMA_DEREG_MR
} HookKind;

typedef struct ArenaSegment ArenaSegment;
typedef struct ArenaBlock ArenaBlock;
typedef struct AllocationRecord AllocationRecord;
typedef struct ProfileRecord ProfileRecord;
typedef struct PassThroughCounter PassThroughCounter;
typedef struct DynamicReplacement DynamicReplacement;
typedef struct DynamicHandleRecord DynamicHandleRecord;
typedef struct ExclusionRange ExclusionRange;
typedef struct RegistrationRecord RegistrationRecord;

struct ArenaBlock {
    size_t offset;
    size_t size;
    int free;
    ArenaSegment* segment;
    ArenaBlock* prev;
    ArenaBlock* next;
};

struct ArenaSegment {
    void* base;
    size_t length;
    size_t id;
    ArenaBlock* blocks;
    ArenaSegment* next;
};

struct AllocationRecord {
    void* user_ptr;
    void* base_ptr;
    size_t user_size;
    size_t mapped_length;
    size_t alignment;
    BackendType backend;
    void* call_site;
    size_t allocation_seq;
    size_t reclaim_epoch;
    size_t hotness_samples;
    size_t hotness_sampled_pages;
    size_t hotness_resident_pages;
    ArenaSegment* segment;
    ArenaBlock* block;
    AllocationRecord* hash_next;
    AllocationRecord* live_prev;
    AllocationRecord* live_next;
};

typedef struct {
    size_t length;
} MetaHeader;

struct ProfileRecord {
    void* call_site;
    size_t allocations;
    size_t bytes;
    ProfileRecord* next;
};

struct PassThroughCounter {
    size_t pending_allocations;
    size_t pending_bytes;
    size_t pending_preload_allocator_calls;
    size_t pending_frida_allocator_calls;
    atomic_size_t flushed_allocations;
    atomic_size_t flushed_bytes;
    atomic_size_t flushed_preload_allocator_calls;
    atomic_size_t flushed_frida_allocator_calls;
    size_t generation;
    PassThroughCounter* next;
};

struct DynamicReplacement {
    HookKind kind;
    const char* symbol;
    void* handle;
    void* address;
    void* original;
    DynamicReplacement* next;
};

struct DynamicHandleRecord {
    void* handle;
    size_t refs;
    DynamicHandleRecord* next;
};

struct ExclusionRange {
    uintptr_t start;
    uintptr_t end;
    ExclusionKind kind;
    void* token;
    ExclusionRange* next;
};

struct RegistrationRecord {
    void* token;
    uintptr_t start;
    uintptr_t end;
    ExclusionKind kind;
    RegistrationRecord* next;
};

static GumInterceptor* malloc_interceptor = NULL;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int in_mai_hook MAI_TLS_INITIAL_EXEC = 0;
static __thread PassThroughCounter* tls_pass_through_counter MAI_TLS_INITIAL_EXEC = NULL;
static __thread int resolving_original_allocators MAI_TLS_INITIAL_EXEC = 0;

static int runtime_enabled = 0;
static int runtime_configured = 0;
static int runtime_config_error = 0;
static int hooks_attached = 0;
static int gum_initialized = 0;
static int verbose_logging = 0;
static int stats_logging = 0;
static int path_stats_enabled = 0;
static int cleanup_in_progress = 0;
static int direct_allocator_interposition = 0;
static char mai_path[PATH_MAX];
static size_t page_size = 4096;
static size_t threshold_bytes = MAI_DEFAULT_THRESHOLD;
static size_t arena_size_bytes = MAI_DEFAULT_ARENA_SIZE;
static size_t target_rss_bytes = 0;
static ReclaimPolicy reclaim_policy = RECLAIM_NONE;
static ReclaimSelection reclaim_selection = RECLAIM_SELECT_OLDEST;
static int profile_enabled = 0;
static int hotness_enabled = 0;
static size_t hotness_sample_pages = MAI_DEFAULT_HOTNESS_SAMPLE_PAGES;

static ArenaSegment* arena_segments = NULL;
static size_t next_segment_id = 0;
static AllocationRecord* allocation_buckets[MAI_TRACK_BUCKETS];
static AllocationRecord* live_head = NULL;
static ProfileRecord* profile_buckets[MAI_PROFILE_BUCKETS];
static DynamicReplacement* dynamic_replacements = NULL;
static atomic_int dynamic_replacements_active;
static DynamicHandleRecord* dynamic_handles = NULL;
static ExclusionRange* exclusion_ranges = NULL;
static RegistrationRecord* registration_records = NULL;
static size_t allocation_sequence = 0;
static size_t reclaim_epoch = 0;
static int mlockall_future_active = 0;
static _Atomic(uintptr_t) managed_range_low;
static _Atomic(uintptr_t) managed_range_high;

static MaiStats stats_snapshot = {0};
static PassThroughCounter* pass_through_counters = NULL;
static pthread_key_t pass_through_counter_key;
static pthread_once_t pass_through_counter_key_once = PTHREAD_ONCE_INIT;
static int pass_through_counter_key_ready = 0;
static size_t pass_through_counter_generation = 1;
static atomic_size_t pass_through_fallback_allocations_counter;
static atomic_size_t pass_through_fallback_bytes_counter;

static gpointer malloc_addr = NULL;
static gpointer free_addr = NULL;
static gpointer calloc_addr = NULL;
static gpointer realloc_addr = NULL;
static gpointer aligned_alloc_addr = NULL;
static gpointer posix_memalign_addr = NULL;
static gpointer memalign_addr = NULL;
static gpointer valloc_addr = NULL;
static gpointer pvalloc_addr = NULL;
static gpointer malloc_usable_size_addr = NULL;
static gpointer dlopen_addr = NULL;
static gpointer dlmopen_addr = NULL;
static gpointer dlclose_addr = NULL;
static gpointer mmap_addr = NULL;
static gpointer munmap_addr = NULL;
static gpointer mremap_addr = NULL;
static gpointer brk_addr = NULL;
static gpointer sbrk_addr = NULL;
static gpointer mlock_addr = NULL;
static gpointer mlock2_addr = NULL;
static gpointer mlockall_addr = NULL;
static gpointer munlock_addr = NULL;
static gpointer munlockall_addr = NULL;
static gpointer cuda_host_alloc_addr = NULL;
static gpointer cuda_malloc_host_addr = NULL;
static gpointer cuda_host_register_addr = NULL;
static gpointer cuda_host_unregister_addr = NULL;
static gpointer cuda_free_host_addr = NULL;
static gpointer cuda_malloc_managed_addr = NULL;
static gpointer cuda_free_addr = NULL;
static gpointer hip_host_malloc_addr = NULL;
static gpointer hip_host_register_addr = NULL;
static gpointer hip_host_unregister_addr = NULL;
static gpointer hip_host_free_addr = NULL;
static gpointer hip_malloc_managed_addr = NULL;
static gpointer hip_free_addr = NULL;
static gpointer mpi_alloc_mem_addr = NULL;
static gpointer mpi_free_mem_addr = NULL;
static gpointer ibv_reg_mr_addr = NULL;
static gpointer ibv_reg_mr_iova_addr = NULL;
static gpointer ibv_rereg_mr_addr = NULL;
static gpointer ibv_dereg_mr_addr = NULL;
static gpointer rdma_reg_msgs_addr = NULL;
static gpointer rdma_reg_read_addr = NULL;
static gpointer rdma_reg_write_addr = NULL;
static gpointer rdma_dereg_mr_addr = NULL;

static int malloc_replaced = 0;
static int free_replaced = 0;
static int calloc_replaced = 0;
static int realloc_replaced = 0;
static int aligned_alloc_replaced = 0;
static int posix_memalign_replaced = 0;
static int memalign_replaced = 0;
static int valloc_replaced = 0;
static int pvalloc_replaced = 0;
static int malloc_usable_size_replaced = 0;
static int dlopen_replaced = 0;
static int dlmopen_replaced = 0;
static int dlclose_replaced = 0;
static int mmap_replaced = 0;
static int munmap_replaced = 0;
static int mremap_replaced = 0;
static int brk_replaced = 0;
static int sbrk_replaced = 0;
static int mlock_replaced = 0;
static int mlock2_replaced = 0;
static int mlockall_replaced = 0;
static int munlock_replaced = 0;
static int munlockall_replaced = 0;
static int cuda_host_alloc_replaced = 0;
static int cuda_malloc_host_replaced = 0;
static int cuda_host_register_replaced = 0;
static int cuda_host_unregister_replaced = 0;
static int cuda_free_host_replaced = 0;
static int cuda_malloc_managed_replaced = 0;
static int cuda_free_replaced = 0;
static int hip_host_malloc_replaced = 0;
static int hip_host_register_replaced = 0;
static int hip_host_unregister_replaced = 0;
static int hip_host_free_replaced = 0;
static int hip_malloc_managed_replaced = 0;
static int hip_free_replaced = 0;
static int mpi_alloc_mem_replaced = 0;
static int mpi_free_mem_replaced = 0;
static int ibv_reg_mr_replaced = 0;
static int ibv_reg_mr_iova_replaced = 0;
static int ibv_rereg_mr_replaced = 0;
static int ibv_dereg_mr_replaced = 0;
static int rdma_reg_msgs_replaced = 0;
static int rdma_reg_read_replaced = 0;
static int rdma_reg_write_replaced = 0;
static int rdma_dereg_mr_replaced = 0;

static void* (*original_malloc)(size_t size) = NULL;
static void (*original_free)(void* ptr) = NULL;
static void* (*original_calloc)(size_t nmemb, size_t size) = NULL;
static void* (*original_realloc)(void* ptr, size_t size) = NULL;
static void* (*original_aligned_alloc)(size_t alignment, size_t size) = NULL;
static int (*original_posix_memalign)(void** memptr, size_t alignment, size_t size) = NULL;
static void* (*original_memalign)(size_t alignment, size_t size) = NULL;
static void* (*original_valloc)(size_t size) = NULL;
static void* (*original_pvalloc)(size_t size) = NULL;
static size_t (*original_malloc_usable_size)(void* ptr) = NULL;
static void* (*original_dlopen)(const char* filename, int flags) = NULL;
static void* (*original_dlmopen)(Lmid_t nsid, const char* filename, int flags) = NULL;
static int (*original_dlclose)(void* handle) = NULL;
static void* (*original_mmap)(void* addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
static int (*original_munmap)(void* addr, size_t length) = NULL;
static void* (*original_mremap)(void* old_address, size_t old_size, size_t new_size, int flags, ...) = NULL;
static int (*original_brk)(void* addr) = NULL;
static void* (*original_sbrk)(intptr_t increment) = NULL;
static int (*original_mlock)(const void* addr, size_t len) = NULL;
static int (*original_mlock2)(const void* addr, size_t len, unsigned int flags) = NULL;
static int (*original_mlockall)(int flags) = NULL;
static int (*original_munlock)(const void* addr, size_t len) = NULL;
static int (*original_munlockall)(void) = NULL;
static int (*original_cudaHostAlloc)(void** ptr, size_t size, unsigned int flags) = NULL;
static int (*original_cudaMallocHost)(void** ptr, size_t size) = NULL;
static int (*original_cudaHostRegister)(void* ptr, size_t size, unsigned int flags) = NULL;
static int (*original_cudaHostUnregister)(void* ptr) = NULL;
static int (*original_cudaFreeHost)(void* ptr) = NULL;
static int (*original_cudaMallocManaged)(void** ptr, size_t size, unsigned int flags) = NULL;
static int (*original_cudaFree)(void* ptr) = NULL;
static int (*original_hipHostMalloc)(void** ptr, size_t size, unsigned int flags) = NULL;
static int (*original_hipHostRegister)(void* ptr, size_t size, unsigned int flags) = NULL;
static int (*original_hipHostUnregister)(void* ptr) = NULL;
static int (*original_hipHostFree)(void* ptr) = NULL;
static int (*original_hipMallocManaged)(void** ptr, size_t size, unsigned int flags) = NULL;
static int (*original_hipFree)(void* ptr) = NULL;
static int (*original_MPI_Alloc_mem)(intptr_t size, void* info, void* baseptr) = NULL;
static int (*original_MPI_Free_mem)(void* base) = NULL;
static void* (*original_ibv_reg_mr)(void* pd, void* addr, size_t length, int access) = NULL;
static void* (*original_ibv_reg_mr_iova)(void* pd, void* addr, size_t length, uint64_t iova, int access) = NULL;
static int (*original_ibv_rereg_mr)(void* mr, int flags, void* pd, void* addr, size_t length, int access) = NULL;
static int (*original_ibv_dereg_mr)(void* mr) = NULL;
static void* (*original_rdma_reg_msgs)(void* id, void* addr, size_t length) = NULL;
static void* (*original_rdma_reg_read)(void* id, void* addr, size_t length) = NULL;
static void* (*original_rdma_reg_write)(void* id, void* addr, size_t length) = NULL;
static int (*original_rdma_dereg_mr)(void* mr) = NULL;

extern void* __libc_malloc(size_t size) __attribute__((weak));
extern void __libc_free(void* ptr) __attribute__((weak));
extern void* __libc_calloc(size_t nmemb, size_t size) __attribute__((weak));
extern void* __libc_realloc(void* ptr, size_t size) __attribute__((weak));
extern void* __libc_memalign(size_t alignment, size_t size) __attribute__((weak));

static void* custom_malloc(size_t size);
static void custom_free(void* ptr);
static void* custom_calloc(size_t nmemb, size_t size);
static void* custom_realloc(void* ptr, size_t size);
static void* custom_aligned_alloc(size_t alignment, size_t size);
static int custom_posix_memalign(void** memptr, size_t alignment, size_t size);
static void* custom_memalign(size_t alignment, size_t size);
static void* custom_valloc(size_t size);
static void* custom_pvalloc(size_t size);
static size_t custom_malloc_usable_size(void* ptr);
static void* custom_dlopen(const char* filename, int flags);
static void* custom_dlmopen(Lmid_t nsid, const char* filename, int flags);
static int custom_dlclose(void* handle);
static void* custom_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
static int custom_munmap(void* addr, size_t length);
static void* custom_mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address);
static int custom_brk(void* addr);
static void* custom_sbrk(intptr_t increment);
static int custom_mlock(const void* addr, size_t len);
static int custom_mlock2(const void* addr, size_t len, unsigned int flags);
static int custom_mlockall(int flags);
static int custom_munlock(const void* addr, size_t len);
static int custom_munlockall(void);
static int custom_cudaHostAlloc(void** ptr, size_t size, unsigned int flags);
static int custom_cudaMallocHost(void** ptr, size_t size);
static int custom_cudaHostRegister(void* ptr, size_t size, unsigned int flags);
static int custom_cudaHostUnregister(void* ptr);
static int custom_cudaFreeHost(void* ptr);
static int custom_cudaMallocManaged(void** ptr, size_t size, unsigned int flags);
static int custom_cudaFree(void* ptr);
static int custom_hipHostMalloc(void** ptr, size_t size, unsigned int flags);
static int custom_hipHostRegister(void* ptr, size_t size, unsigned int flags);
static int custom_hipHostUnregister(void* ptr);
static int custom_hipHostFree(void* ptr);
static int custom_hipMallocManaged(void** ptr, size_t size, unsigned int flags);
static int custom_hipFree(void* ptr);
static int custom_MPI_Alloc_mem(intptr_t size, void* info, void* baseptr);
static int custom_MPI_Free_mem(void* base);
static void* custom_ibv_reg_mr(void* pd, void* addr, size_t length, int access);
static void* custom_ibv_reg_mr_iova(void* pd, void* addr, size_t length, uint64_t iova, int access);
static int custom_ibv_rereg_mr(void* mr, int flags, void* pd, void* addr, size_t length, int access);
static int custom_ibv_dereg_mr(void* mr);
static void* custom_rdma_reg_msgs(void* id, void* addr, size_t length);
static void* custom_rdma_reg_read(void* id, void* addr, size_t length);
static void* custom_rdma_reg_write(void* id, void* addr, size_t length);
static int custom_rdma_dereg_mr(void* mr);

__attribute__((visibility("default"))) int mlock2(const void* addr, size_t len,
                                                  unsigned int flags);
__attribute__((visibility("default"))) int cudaHostAlloc(void** ptr, size_t size,
                                                         unsigned int flags);
__attribute__((visibility("default"))) int cudaMallocHost(void** ptr, size_t size);
__attribute__((visibility("default"))) int cudaHostRegister(void* ptr, size_t size,
                                                            unsigned int flags);
__attribute__((visibility("default"))) int cudaHostUnregister(void* ptr);
__attribute__((visibility("default"))) int cudaFreeHost(void* ptr);
__attribute__((visibility("default"))) int cudaMallocManaged(void** ptr, size_t size,
                                                             unsigned int flags);
__attribute__((visibility("default"))) int cudaFree(void* ptr);
__attribute__((visibility("default"))) int hipHostMalloc(void** ptr, size_t size,
                                                         unsigned int flags);
__attribute__((visibility("default"))) int hipHostRegister(void* ptr, size_t size,
                                                           unsigned int flags);
__attribute__((visibility("default"))) int hipHostUnregister(void* ptr);
__attribute__((visibility("default"))) int hipHostFree(void* ptr);
__attribute__((visibility("default"))) int hipMallocManaged(void** ptr, size_t size,
                                                            unsigned int flags);
__attribute__((visibility("default"))) int hipFree(void* ptr);
__attribute__((visibility("default"))) int MPI_Alloc_mem(intptr_t size, void* info,
                                                         void* baseptr);
__attribute__((visibility("default"))) int MPI_Free_mem(void* base);
__attribute__((visibility("default"))) void* ibv_reg_mr(void* pd, void* addr,
                                                        size_t length, int access);
__attribute__((visibility("default"))) void* ibv_reg_mr_iova(void* pd, void* addr,
                                                             size_t length,
                                                             uint64_t iova, int access);
__attribute__((visibility("default"))) int ibv_rereg_mr(void* mr, int flags, void* pd,
                                                        void* addr, size_t length,
                                                        int access);
__attribute__((visibility("default"))) int ibv_dereg_mr(void* mr);
__attribute__((visibility("default"))) void* rdma_reg_msgs(void* id, void* addr,
                                                           size_t length);
__attribute__((visibility("default"))) void* rdma_reg_read(void* id, void* addr,
                                                           size_t length);
__attribute__((visibility("default"))) void* rdma_reg_write(void* id, void* addr,
                                                            size_t length);
__attribute__((visibility("default"))) int rdma_dereg_mr(void* mr);
static size_t record_page_range(AllocationRecord* record, void** range_start);

static size_t max_size(size_t a, size_t b) {
    return a > b ? a : b;
}

static int add_overflow(size_t a, size_t b, size_t* out) {
    if (a > SIZE_MAX - b) {
        errno = ENOMEM;
        return -1;
    }

    *out = a + b;
    return 0;
}

static int mul_overflow(size_t a, size_t b, size_t* out) {
    if (a != 0 && b > SIZE_MAX / a) {
        errno = ENOMEM;
        return -1;
    }

    *out = a * b;
    return 0;
}

static int is_power_of_two(size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

static size_t default_alignment(void) {
    return _Alignof(max_align_t);
}

static uintptr_t align_up_uintptr(uintptr_t value, size_t alignment) {
    uintptr_t mask = (uintptr_t)alignment - 1;
    return (value + mask) & ~mask;
}

static size_t align_up_size(size_t value, size_t alignment) {
    if (alignment == 0) {
        return value;
    }

    size_t rem = value % alignment;
    if (rem == 0) {
        return value;
    }
    if (value > SIZE_MAX - (alignment - rem)) {
        errno = ENOMEM;
        return 0;
    }
    return value + (alignment - rem);
}

static int parse_bool_env(const char* value) {
    if (!value || value[0] == '\0') {
        return 0;
    }

    return strcmp(value, "1") == 0 ||
           strcasecmp(value, "true") == 0 ||
           strcasecmp(value, "yes") == 0 ||
           strcasecmp(value, "on") == 0;
}

static int parse_size_env(const char* value, size_t* out) {
    char* end = NULL;
    unsigned long long number;
    unsigned long long multiplier = 1;

    if (!value || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    number = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        return -1;
    }

    while (*end && isspace((unsigned char)*end)) {
        end++;
    }

    if (*end) {
        switch (tolower((unsigned char)*end)) {
            case 'k':
                multiplier = 1024ULL;
                end++;
                break;
            case 'm':
                multiplier = 1024ULL * 1024ULL;
                end++;
                break;
            case 'g':
                multiplier = 1024ULL * 1024ULL * 1024ULL;
                end++;
                break;
            case 't':
                multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
                end++;
                break;
            default:
                return -1;
        }
        if (tolower((unsigned char)*end) == 'b') {
            end++;
        }
    }

    while (*end && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0') {
        return -1;
    }

    if (number > ULLONG_MAX / multiplier ||
        number * multiplier > (unsigned long long)SIZE_MAX) {
        return -1;
    }

    *out = (size_t)(number * multiplier);
    return 0;
}

static int parse_count_env(const char* value, size_t* out) {
    char* end = NULL;
    unsigned long long number;

    if (!value || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    number = strtoull(value, &end, 10);
    if (errno != 0 || end == value) {
        return -1;
    }
    while (*end && isspace((unsigned char)*end)) {
        end++;
    }
    if (*end != '\0' || number > (unsigned long long)SIZE_MAX) {
        return -1;
    }

    *out = (size_t)number;
    return 0;
}

static void* meta_alloc(size_t size) {
    size_t total;
    size_t mapped;
    MetaHeader* header;

    if (add_overflow(sizeof(*header), size, &total) != 0) {
        return NULL;
    }

    mapped = align_up_size(total, page_size);
    if (mapped == 0) {
        return NULL;
    }

    header = mmap(NULL, mapped, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (header == MAP_FAILED) {
        return NULL;
    }

    header->length = mapped;
    return (void*)(header + 1);
}

static void meta_free(void* ptr) {
    if (!ptr) {
        return;
    }

    MetaHeader* header = ((MetaHeader*)ptr) - 1;
    munmap(header, header->length);
}

static size_t hash_ptr(void* ptr) {
    uintptr_t value = (uintptr_t)ptr;
    value >>= 4;
    value ^= value >> 7;
    value ^= value >> 17;
    return (size_t)(value % MAI_TRACK_BUCKETS);
}

static size_t hash_profile_site(void* ptr) {
    uintptr_t value = (uintptr_t)ptr;
    value >>= 4;
    value ^= value >> 9;
    return (size_t)(value % MAI_PROFILE_BUCKETS);
}

static size_t sample_process_rss_bytes(void) {
    char buffer[128];
    int fd = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return 0;
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return 0;
    }
    buffer[bytes_read] = '\0';

    char* cursor = buffer;
    char* end = NULL;
    (void)strtoull(cursor, &end, 10);
    if (end == cursor) {
        return 0;
    }

    cursor = end;
    while (*cursor && isspace((unsigned char)*cursor)) {
        cursor++;
    }

    errno = 0;
    unsigned long long resident_pages = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || resident_pages == 0) {
        return 0;
    }
    if (resident_pages > (unsigned long long)(SIZE_MAX / page_size)) {
        return SIZE_MAX;
    }

    return (size_t)resident_pages * page_size;
}

static size_t update_observed_rss_locked(void) {
    size_t rss = sample_process_rss_bytes();
    if (rss == 0) {
        return 0;
    }

    stats_snapshot.current_rss_bytes = rss;
    if (rss > stats_snapshot.high_water_rss_bytes) {
        stats_snapshot.high_water_rss_bytes = rss;
    }

    return rss;
}

static int make_range(void* ptr, size_t length, uintptr_t* start, uintptr_t* end) {
    if (!ptr || length == 0) {
        return -1;
    }

    uintptr_t range_start = (uintptr_t)ptr;
    if (range_start > UINTPTR_MAX - length) {
        errno = EINVAL;
        return -1;
    }

    *start = range_start;
    *end = range_start + length;
    return 0;
}

static int ranges_overlap(uintptr_t a_start, uintptr_t a_end,
                          uintptr_t b_start, uintptr_t b_end) {
    return a_start < b_end && b_start < a_end;
}

static int add_exclusion_range_locked(void* ptr, size_t length, ExclusionKind kind,
                                      void* token) {
    uintptr_t start;
    uintptr_t end;
    if (make_range(ptr, length, &start, &end) != 0) {
        return -1;
    }

    ExclusionRange* range = meta_alloc(sizeof(*range));
    if (!range) {
        return -1;
    }

    range->start = start;
    range->end = end;
    range->kind = kind;
    range->token = token;
    range->next = exclusion_ranges;
    exclusion_ranges = range;

    stats_snapshot.excluded_ranges++;
    stats_snapshot.excluded_bytes += length;
    stats_snapshot.exclusion_events++;
    return 0;
}

static void remove_exclusion_node_locked(ExclusionRange* previous,
                                         ExclusionRange* range) {
    if (previous) {
        previous->next = range->next;
    } else {
        exclusion_ranges = range->next;
    }

    size_t length = (size_t)(range->end - range->start);
    if (stats_snapshot.excluded_ranges > 0) {
        stats_snapshot.excluded_ranges--;
    }
    if (stats_snapshot.excluded_bytes >= length) {
        stats_snapshot.excluded_bytes -= length;
    } else {
        stats_snapshot.excluded_bytes = 0;
    }
    stats_snapshot.exclusion_release_events++;
    meta_free(range);
}

static void remove_exclusion_range_locked(void* ptr, size_t length,
                                          ExclusionKind kind) {
    uintptr_t start;
    uintptr_t end;
    if (make_range(ptr, length, &start, &end) != 0) {
        return;
    }

    ExclusionRange* previous = NULL;
    ExclusionRange* range = exclusion_ranges;
    while (range) {
        ExclusionRange* next = range->next;
        if (range->kind != kind || !ranges_overlap(range->start, range->end, start, end)) {
            previous = range;
            range = next;
            continue;
        }

        if (start <= range->start && end >= range->end) {
            remove_exclusion_node_locked(previous, range);
            range = next;
            continue;
        }

        if (start <= range->start) {
            size_t old_length = (size_t)(range->end - range->start);
            range->start = end < range->end ? end : range->end;
            size_t new_length = (size_t)(range->end - range->start);
            stats_snapshot.excluded_bytes -= old_length - new_length;
            stats_snapshot.exclusion_release_events++;
            previous = range;
            range = next;
            continue;
        }

        if (end >= range->end) {
            size_t old_length = (size_t)(range->end - range->start);
            range->end = start > range->start ? start : range->start;
            size_t new_length = (size_t)(range->end - range->start);
            stats_snapshot.excluded_bytes -= old_length - new_length;
            stats_snapshot.exclusion_release_events++;
            previous = range;
            range = next;
            continue;
        }

        ExclusionRange* tail = meta_alloc(sizeof(*tail));
        if (tail) {
            tail->start = end;
            tail->end = range->end;
            tail->kind = range->kind;
            tail->token = range->token;
            tail->next = range->next;
            range->next = tail;
            range->end = start;
            stats_snapshot.excluded_ranges++;
            stats_snapshot.excluded_bytes -= (size_t)(end - start);
            stats_snapshot.exclusion_release_events++;
            previous = tail;
            range = next;
        } else {
            previous = range;
            range = next;
        }
    }
}

static void remove_exclusion_start_locked(void* ptr, ExclusionKind kind) {
    uintptr_t start = (uintptr_t)ptr;
    ExclusionRange* previous = NULL;
    ExclusionRange* range = exclusion_ranges;

    while (range) {
        ExclusionRange* next = range->next;
        if (range->kind == kind && range->start == start) {
            remove_exclusion_node_locked(previous, range);
            range = next;
            continue;
        }
        previous = range;
        range = next;
    }
}

static void remove_exclusion_token_locked(void* token, ExclusionKind kind) {
    ExclusionRange* previous = NULL;
    ExclusionRange* range = exclusion_ranges;

    while (range) {
        ExclusionRange* next = range->next;
        if (range->kind == kind && range->token == token) {
            remove_exclusion_node_locked(previous, range);
            range = next;
            continue;
        }
        previous = range;
        range = next;
    }
}

static int record_overlaps_exclusion_locked(AllocationRecord* record) {
    uintptr_t start;
    uintptr_t end;
    if (make_range(record->user_ptr, record->user_size, &start, &end) != 0) {
        return 0;
    }

    for (ExclusionRange* range = exclusion_ranges; range; range = range->next) {
        if (ranges_overlap(start, end, range->start, range->end)) {
            return 1;
        }
    }

    return 0;
}

static void mark_all_live_excluded_locked(ExclusionKind kind) {
    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        add_exclusion_range_locked(record->user_ptr, record->user_size, kind,
                                   record->user_ptr);
    }
}

static void remove_exclusions_by_kind_locked(ExclusionKind kind) {
    ExclusionRange* previous = NULL;
    ExclusionRange* range = exclusion_ranges;

    while (range) {
        ExclusionRange* next = range->next;
        if (range->kind == kind) {
            remove_exclusion_node_locked(previous, range);
            range = next;
            continue;
        }
        previous = range;
        range = next;
    }
}

static int remember_registration_locked(void* token, void* ptr, size_t length,
                                        ExclusionKind kind) {
    uintptr_t start;
    uintptr_t end;
    if (!token || make_range(ptr, length, &start, &end) != 0) {
        return -1;
    }

    RegistrationRecord* record = meta_alloc(sizeof(*record));
    if (!record) {
        return -1;
    }

    record->token = token;
    record->start = start;
    record->end = end;
    record->kind = kind;
    record->next = registration_records;
    registration_records = record;
    return 0;
}

static int registration_exists_locked(void* token, ExclusionKind kind) {
    for (RegistrationRecord* record = registration_records; record; record = record->next) {
        if (record->token == token && record->kind == kind) {
            return 1;
        }
    }

    return 0;
}

static RegistrationRecord* take_registration_locked(void* token, ExclusionKind kind) {
    RegistrationRecord* previous = NULL;
    RegistrationRecord* record = registration_records;

    while (record) {
        if (record->token == token && record->kind == kind) {
            if (previous) {
                previous->next = record->next;
            } else {
                registration_records = record->next;
            }
            return record;
        }
        previous = record;
        record = record->next;
    }

    return NULL;
}

static int sample_record_hotness_locked(AllocationRecord* record,
                                        size_t* sampled_pages_out,
                                        size_t* resident_pages_out,
                                        size_t* total_pages_out) {
    void* range_start = NULL;
    size_t range_length = record_page_range(record, &range_start);
    size_t total_pages;
    size_t sample_pages;
    size_t resident_pages = 0;
    int rc = 0;

    *sampled_pages_out = 0;
    *resident_pages_out = 0;
    *total_pages_out = 0;

    if (range_length == 0) {
        return 0;
    }

    total_pages = range_length / page_size;
    if (total_pages == 0) {
        return 0;
    }

    sample_pages = hotness_sample_pages;
    if (sample_pages == 0 || sample_pages > total_pages) {
        sample_pages = total_pages;
    }

    if (sample_pages == total_pages) {
        unsigned char* vec = meta_alloc(sample_pages);
        if (!vec) {
            return -1;
        }

        if (mincore(range_start, range_length, vec) != 0) {
            rc = -1;
        } else {
            for (size_t i = 0; i < sample_pages; i++) {
                if (vec[i] & 1) {
                    resident_pages++;
                }
            }
        }
        meta_free(vec);
    } else {
        uintptr_t start = (uintptr_t)range_start;
        for (size_t i = 0; i < sample_pages; i++) {
            size_t page_index = (i * total_pages) / sample_pages;
            unsigned char vec = 0;
            void* page = (void*)(start + page_index * page_size);
            if (mincore(page, page_size, &vec) != 0) {
                rc = -1;
                continue;
            }
            if (vec & 1) {
                resident_pages++;
            }
        }
    }

    if (rc == 0) {
        record->hotness_samples++;
        record->hotness_sampled_pages += sample_pages;
        record->hotness_resident_pages += resident_pages;
        stats_snapshot.hotness_samples++;
        stats_snapshot.hotness_sampled_pages += sample_pages;
        stats_snapshot.hotness_resident_pages += resident_pages;
    }

    *sampled_pages_out = sample_pages;
    *resident_pages_out = resident_pages;
    *total_pages_out = total_pages;
    return rc;
}

static int sample_all_hotness_locked(void) {
    int rc = 0;

    if (!hotness_enabled) {
        return 0;
    }

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        size_t sampled_pages = 0;
        size_t resident_pages = 0;
        size_t total_pages = 0;
        if (sample_record_hotness_locked(record, &sampled_pages, &resident_pages,
                                         &total_pages) != 0) {
            rc = -1;
        }
    }

    return rc;
}

static void resolve_original_allocators(void) {
    if (resolving_original_allocators) {
        return;
    }

    resolving_original_allocators = 1;
    if (!original_malloc) {
        original_malloc = __libc_malloc ? __libc_malloc :
            (void* (*)(size_t))dlsym(RTLD_NEXT, "malloc");
    }
    if (!original_free) {
        original_free = __libc_free ? __libc_free :
            (void (*)(void*))dlsym(RTLD_NEXT, "free");
    }
    if (!original_calloc) {
        original_calloc = __libc_calloc ? __libc_calloc :
            (void* (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    }
    if (!original_realloc) {
        original_realloc = __libc_realloc ? __libc_realloc :
            (void* (*)(void*, size_t))dlsym(RTLD_NEXT, "realloc");
    }
    if (!original_aligned_alloc) {
        original_aligned_alloc =
            (void* (*)(size_t, size_t))dlsym(RTLD_NEXT, "aligned_alloc");
    }
    if (!original_posix_memalign) {
        original_posix_memalign =
            (int (*)(void**, size_t, size_t))dlsym(RTLD_NEXT, "posix_memalign");
    }
    if (!original_memalign) {
        original_memalign = __libc_memalign ? __libc_memalign :
            (void* (*)(size_t, size_t))dlsym(RTLD_NEXT, "memalign");
    }
    if (!original_valloc) {
        original_valloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "valloc");
    }
    if (!original_pvalloc) {
        original_pvalloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "pvalloc");
    }
    if (!original_malloc_usable_size) {
        original_malloc_usable_size =
            (size_t (*)(void*))dlsym(RTLD_NEXT, "malloc_usable_size");
    }
    resolving_original_allocators = 0;
}

static void resolve_original_safety_functions(void) {
    if (!original_mlock) {
        original_mlock = (int (*)(const void*, size_t))dlsym(RTLD_NEXT, "mlock");
    }
    if (!original_mlock2) {
        original_mlock2 =
            (int (*)(const void*, size_t, unsigned int))dlsym(RTLD_NEXT, "mlock2");
    }
    if (!original_mlockall) {
        original_mlockall = (int (*)(int))dlsym(RTLD_NEXT, "mlockall");
    }
    if (!original_munlock) {
        original_munlock = (int (*)(const void*, size_t))dlsym(RTLD_NEXT, "munlock");
    }
    if (!original_munlockall) {
        original_munlockall = (int (*)(void))dlsym(RTLD_NEXT, "munlockall");
    }
    if (!original_cudaHostAlloc) {
        original_cudaHostAlloc =
            (int (*)(void**, size_t, unsigned int))dlsym(RTLD_NEXT, "cudaHostAlloc");
    }
    if (!original_cudaMallocHost) {
        original_cudaMallocHost =
            (int (*)(void**, size_t))dlsym(RTLD_NEXT, "cudaMallocHost");
    }
    if (!original_cudaHostRegister) {
        original_cudaHostRegister =
            (int (*)(void*, size_t, unsigned int))dlsym(RTLD_NEXT, "cudaHostRegister");
    }
    if (!original_cudaHostUnregister) {
        original_cudaHostUnregister =
            (int (*)(void*))dlsym(RTLD_NEXT, "cudaHostUnregister");
    }
    if (!original_cudaFreeHost) {
        original_cudaFreeHost = (int (*)(void*))dlsym(RTLD_NEXT, "cudaFreeHost");
    }
    if (!original_cudaMallocManaged) {
        original_cudaMallocManaged =
            (int (*)(void**, size_t, unsigned int))dlsym(RTLD_NEXT, "cudaMallocManaged");
    }
    if (!original_cudaFree) {
        original_cudaFree = (int (*)(void*))dlsym(RTLD_NEXT, "cudaFree");
    }
    if (!original_hipHostMalloc) {
        original_hipHostMalloc =
            (int (*)(void**, size_t, unsigned int))dlsym(RTLD_NEXT, "hipHostMalloc");
    }
    if (!original_hipHostRegister) {
        original_hipHostRegister =
            (int (*)(void*, size_t, unsigned int))dlsym(RTLD_NEXT, "hipHostRegister");
    }
    if (!original_hipHostUnregister) {
        original_hipHostUnregister =
            (int (*)(void*))dlsym(RTLD_NEXT, "hipHostUnregister");
    }
    if (!original_hipHostFree) {
        original_hipHostFree = (int (*)(void*))dlsym(RTLD_NEXT, "hipHostFree");
    }
    if (!original_hipMallocManaged) {
        original_hipMallocManaged =
            (int (*)(void**, size_t, unsigned int))dlsym(RTLD_NEXT, "hipMallocManaged");
    }
    if (!original_hipFree) {
        original_hipFree = (int (*)(void*))dlsym(RTLD_NEXT, "hipFree");
    }
    if (!original_MPI_Alloc_mem) {
        original_MPI_Alloc_mem =
            (int (*)(intptr_t, void*, void*))dlsym(RTLD_NEXT, "MPI_Alloc_mem");
    }
    if (!original_MPI_Free_mem) {
        original_MPI_Free_mem = (int (*)(void*))dlsym(RTLD_NEXT, "MPI_Free_mem");
    }
    if (!original_ibv_reg_mr) {
        original_ibv_reg_mr =
            (void* (*)(void*, void*, size_t, int))dlsym(RTLD_NEXT, "ibv_reg_mr");
    }
    if (!original_ibv_reg_mr_iova) {
        original_ibv_reg_mr_iova =
            (void* (*)(void*, void*, size_t, uint64_t, int))dlsym(RTLD_NEXT,
                                                                  "ibv_reg_mr_iova");
    }
    if (!original_ibv_rereg_mr) {
        original_ibv_rereg_mr =
            (int (*)(void*, int, void*, void*, size_t, int))dlsym(RTLD_NEXT,
                                                                  "ibv_rereg_mr");
    }
    if (!original_ibv_dereg_mr) {
        original_ibv_dereg_mr = (int (*)(void*))dlsym(RTLD_NEXT, "ibv_dereg_mr");
    }
    if (!original_rdma_reg_msgs) {
        original_rdma_reg_msgs =
            (void* (*)(void*, void*, size_t))dlsym(RTLD_NEXT, "rdma_reg_msgs");
    }
    if (!original_rdma_reg_read) {
        original_rdma_reg_read =
            (void* (*)(void*, void*, size_t))dlsym(RTLD_NEXT, "rdma_reg_read");
    }
    if (!original_rdma_reg_write) {
        original_rdma_reg_write =
            (void* (*)(void*, void*, size_t))dlsym(RTLD_NEXT, "rdma_reg_write");
    }
    if (!original_rdma_dereg_mr) {
        original_rdma_dereg_mr = (int (*)(void*))dlsym(RTLD_NEXT, "rdma_dereg_mr");
    }
}

static void* fallback_malloc(size_t size) {
    if (__libc_malloc) {
        return __libc_malloc(size);
    }
    void* ptr = mmap(NULL, align_up_size(max_size(size, 1), page_size),
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return ptr == MAP_FAILED ? NULL : ptr;
}

static void fallback_free(void* ptr) {
    if (__libc_free) {
        __libc_free(ptr);
    }
}

static void* fallback_calloc(size_t nmemb, size_t size) {
    if (__libc_calloc) {
        return __libc_calloc(nmemb, size);
    }

    size_t total = 0;
    if (mul_overflow(nmemb, size, &total) != 0) {
        return NULL;
    }
    void* ptr = fallback_malloc(total);
    if (ptr && ptr != MAP_FAILED) {
        memset(ptr, 0, total);
    }
    return ptr == MAP_FAILED ? NULL : ptr;
}

static void* fallback_realloc(void* ptr, size_t size) {
    if (__libc_realloc) {
        return __libc_realloc(ptr, size);
    }
    if (!ptr) {
        return fallback_malloc(size);
    }
    return NULL;
}

static void* fallback_memalign(size_t alignment, size_t size) {
    if (__libc_memalign) {
        return __libc_memalign(alignment, size);
    }
    return NULL;
}

static void* call_libc_malloc(size_t size) {
    if (!original_malloc) {
        resolve_original_allocators();
    }
    return original_malloc ? original_malloc(size) : fallback_malloc(size);
}

static void* direct_libc_malloc(size_t size) {
    return __libc_malloc ? __libc_malloc(size) : call_libc_malloc(size);
}

static void call_libc_free(void* ptr) {
    if (!original_free) {
        resolve_original_allocators();
    }
    if (original_free) {
        original_free(ptr);
    } else {
        fallback_free(ptr);
    }
}

static void direct_libc_free(void* ptr) {
    if (__libc_free) {
        __libc_free(ptr);
    } else {
        call_libc_free(ptr);
    }
}

static void* call_libc_calloc(size_t nmemb, size_t size) {
    if (!original_calloc) {
        resolve_original_allocators();
    }
    return original_calloc ? original_calloc(nmemb, size) : fallback_calloc(nmemb, size);
}

static void* direct_libc_calloc(size_t nmemb, size_t size) {
    return __libc_calloc ? __libc_calloc(nmemb, size) : call_libc_calloc(nmemb, size);
}

static void* call_libc_realloc(void* ptr, size_t size) {
    if (!original_realloc) {
        resolve_original_allocators();
    }
    return original_realloc ? original_realloc(ptr, size) : fallback_realloc(ptr, size);
}

static void* direct_libc_realloc(void* ptr, size_t size) {
    return __libc_realloc ? __libc_realloc(ptr, size) : call_libc_realloc(ptr, size);
}

static size_t call_libc_malloc_usable_size(void* ptr) {
    if (!original_malloc_usable_size) {
        resolve_original_allocators();
    }
    return original_malloc_usable_size ? original_malloc_usable_size(ptr) : 0;
}

static DynamicReplacement* current_dynamic_replacement(HookKind kind) {
    if (!atomic_load_explicit(&dynamic_replacements_active, memory_order_relaxed)) {
        return NULL;
    }

    GumInvocationContext* context = gum_interceptor_get_current_invocation();
    if (!context) {
        return NULL;
    }

    DynamicReplacement* replacement =
        (DynamicReplacement*)gum_invocation_context_get_replacement_data(context);
    if (!replacement || replacement->kind != kind || !replacement->original) {
        return NULL;
    }

    return replacement;
}

static void* pass_through_malloc(size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MALLOC);
    if (replacement) {
        return ((void* (*)(size_t))replacement->original)(size);
    }
    if (!original_malloc) {
        resolve_original_allocators();
    }
    return original_malloc ? original_malloc(size) : fallback_malloc(size);
}

static void pass_through_free(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_FREE);
    if (replacement) {
        ((void (*)(void*))replacement->original)(ptr);
        return;
    }
    if (original_free) {
        original_free(ptr);
    } else {
        resolve_original_allocators();
        if (original_free) {
            original_free(ptr);
        } else {
            fallback_free(ptr);
        }
    }
}

static void* pass_through_calloc(size_t nmemb, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CALLOC);
    if (replacement) {
        return ((void* (*)(size_t, size_t))replacement->original)(nmemb, size);
    }
    if (!original_calloc) {
        resolve_original_allocators();
    }
    return original_calloc ? original_calloc(nmemb, size) : fallback_calloc(nmemb, size);
}

static void* pass_through_realloc(void* ptr, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_REALLOC);
    if (replacement) {
        return ((void* (*)(void*, size_t))replacement->original)(ptr, size);
    }
    if (!original_realloc) {
        resolve_original_allocators();
    }
    return original_realloc ? original_realloc(ptr, size) : fallback_realloc(ptr, size);
}

static void* pass_through_aligned_alloc(size_t alignment, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_ALIGNED_ALLOC);
    if (replacement) {
        return ((void* (*)(size_t, size_t))replacement->original)(alignment, size);
    }
    if (!original_aligned_alloc) {
        resolve_original_allocators();
    }
    if (original_aligned_alloc) {
        return original_aligned_alloc(alignment, size);
    }
    if (size % alignment != 0) {
        errno = EINVAL;
        return NULL;
    }
    return fallback_memalign(alignment, size);
}

static int pass_through_posix_memalign(void** memptr, size_t alignment, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_POSIX_MEMALIGN);
    if (replacement) {
        return ((int (*)(void**, size_t, size_t))replacement->original)(memptr, alignment, size);
    }
    if (!original_posix_memalign) {
        resolve_original_allocators();
    }
    if (original_posix_memalign) {
        return original_posix_memalign(memptr, alignment, size);
    }
    void* ptr = fallback_memalign(alignment, size);
    if (!ptr) {
        return ENOMEM;
    }
    *memptr = ptr;
    return 0;
}

static void* pass_through_memalign(size_t alignment, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MEMALIGN);
    if (replacement) {
        return ((void* (*)(size_t, size_t))replacement->original)(alignment, size);
    }
    if (!original_memalign) {
        resolve_original_allocators();
    }
    return original_memalign ? original_memalign(alignment, size) :
        fallback_memalign(alignment, size);
}

static size_t pass_through_malloc_usable_size(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MALLOC_USABLE_SIZE);
    if (replacement) {
        return ((size_t (*)(void*))replacement->original)(ptr);
    }
    if (!original_malloc_usable_size) {
        resolve_original_allocators();
    }
    return original_malloc_usable_size ? original_malloc_usable_size(ptr) : 0;
}

static void note_profile_locked(void* call_site, size_t size) {
    if (!profile_enabled || !call_site) {
        return;
    }

    size_t bucket = hash_profile_site(call_site);
    for (ProfileRecord* record = profile_buckets[bucket]; record; record = record->next) {
        if (record->call_site == call_site) {
            record->allocations++;
            record->bytes += size;
            return;
        }
    }

    ProfileRecord* record = meta_alloc(sizeof(*record));
    if (!record) {
        return;
    }

    record->call_site = call_site;
    record->allocations = 1;
    record->bytes = size;
    record->next = profile_buckets[bucket];
    profile_buckets[bucket] = record;
    stats_snapshot.profile_sites++;
}

static void stats_note_managed_alloc(size_t size) {
    stats_snapshot.managed_allocations++;
    stats_snapshot.managed_bytes_total += size;
    stats_snapshot.live_managed_bytes += size;
    if (stats_snapshot.live_managed_bytes > stats_snapshot.high_water_managed_bytes) {
        stats_snapshot.high_water_managed_bytes = stats_snapshot.live_managed_bytes;
    }
}

static void stats_note_managed_free(size_t size) {
    stats_snapshot.managed_frees++;
    if (stats_snapshot.live_managed_bytes >= size) {
        stats_snapshot.live_managed_bytes -= size;
    } else {
        stats_snapshot.live_managed_bytes = 0;
    }
}

static void stats_reduce_live_managed(size_t size) {
    if (stats_snapshot.live_managed_bytes >= size) {
        stats_snapshot.live_managed_bytes -= size;
    } else {
        stats_snapshot.live_managed_bytes = 0;
    }
}

static void flush_pass_through_counter(PassThroughCounter* counter) {
    if (!counter) {
        return;
    }

    size_t allocations = counter->pending_allocations;
    size_t bytes = counter->pending_bytes;
    size_t preload_calls = counter->pending_preload_allocator_calls;
    size_t frida_calls = counter->pending_frida_allocator_calls;
    if (allocations == 0 && bytes == 0 && preload_calls == 0 && frida_calls == 0) {
        return;
    }

    counter->pending_allocations = 0;
    counter->pending_bytes = 0;
    counter->pending_preload_allocator_calls = 0;
    counter->pending_frida_allocator_calls = 0;
    atomic_fetch_add_explicit(&counter->flushed_allocations, allocations,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&counter->flushed_bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&counter->flushed_preload_allocator_calls, preload_calls,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&counter->flushed_frida_allocator_calls, frida_calls,
                              memory_order_relaxed);
}

static void pass_through_counter_destructor(void* value) {
    PassThroughCounter* counter = (PassThroughCounter*)value;
    flush_pass_through_counter(counter);
    if (tls_pass_through_counter == counter) {
        tls_pass_through_counter = NULL;
    }
}

static void init_pass_through_counter_key(void) {
    if (pthread_key_create(&pass_through_counter_key,
                           pass_through_counter_destructor) == 0) {
        pass_through_counter_key_ready = 1;
    }
}

static PassThroughCounter* get_pass_through_counter(void) {
    if (tls_pass_through_counter &&
        tls_pass_through_counter->generation == pass_through_counter_generation) {
        return tls_pass_through_counter;
    }

    (void)pthread_once(&pass_through_counter_key_once, init_pass_through_counter_key);

    PassThroughCounter* counter = meta_alloc(sizeof(*counter));
    if (!counter) {
        return NULL;
    }
    memset(counter, 0, sizeof(*counter));
    atomic_init(&counter->flushed_allocations, 0);
    atomic_init(&counter->flushed_bytes, 0);
    atomic_init(&counter->flushed_preload_allocator_calls, 0);
    atomic_init(&counter->flushed_frida_allocator_calls, 0);
    counter->generation = pass_through_counter_generation;

    pthread_mutex_lock(&runtime_lock);
    counter->next = pass_through_counters;
    pass_through_counters = counter;
    pthread_mutex_unlock(&runtime_lock);

    tls_pass_through_counter = counter;
    if (pass_through_counter_key_ready) {
        (void)pthread_setspecific(pass_through_counter_key, counter);
    }

    return counter;
}

static void flush_current_pass_through_counter(void) {
    if (tls_pass_through_counter &&
        tls_pass_through_counter->generation == pass_through_counter_generation) {
        flush_pass_through_counter(tls_pass_through_counter);
    }
}

static void snapshot_pass_through_counters_locked(size_t* allocations, size_t* bytes,
                                                  size_t* preload_calls,
                                                  size_t* frida_calls) {
    size_t total_allocations = atomic_load_explicit(
        &pass_through_fallback_allocations_counter, memory_order_relaxed);
    size_t total_bytes = atomic_load_explicit(
        &pass_through_fallback_bytes_counter, memory_order_relaxed);
    size_t total_preload_calls = 0;
    size_t total_frida_calls = 0;

    for (PassThroughCounter* counter = pass_through_counters;
         counter;
         counter = counter->next) {
        total_allocations += atomic_load_explicit(&counter->flushed_allocations,
                                                  memory_order_relaxed);
        total_bytes += atomic_load_explicit(&counter->flushed_bytes,
                                            memory_order_relaxed);
        total_preload_calls += atomic_load_explicit(
            &counter->flushed_preload_allocator_calls, memory_order_relaxed);
        total_frida_calls += atomic_load_explicit(
            &counter->flushed_frida_allocator_calls, memory_order_relaxed);
    }

    *allocations = total_allocations;
    *bytes = total_bytes;
    *preload_calls = total_preload_calls;
    *frida_calls = total_frida_calls;
}

static void stats_note_pass_through(size_t size) {
    PassThroughCounter* counter = get_pass_through_counter();
    if (!counter) {
        atomic_fetch_add_explicit(&pass_through_fallback_allocations_counter, 1,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&pass_through_fallback_bytes_counter, size,
                                  memory_order_relaxed);
        return;
    }

    if (counter->pending_bytes > SIZE_MAX - size) {
        flush_pass_through_counter(counter);
    }
    counter->pending_allocations++;
    counter->pending_bytes += size;

    if (counter->pending_allocations >= MAI_PASS_THROUGH_FLUSH_INTERVAL) {
        flush_pass_through_counter(counter);
    }
}

static void stats_note_pass_through_threadsafe(size_t size) {
    if (!stats_logging) {
        return;
    }
    stats_note_pass_through(size);
}

static void stats_note_allocator_path(int preload_path) {
    if (!path_stats_enabled || !runtime_configured || cleanup_in_progress) {
        return;
    }

    PassThroughCounter* counter = get_pass_through_counter();
    if (!counter) {
        return;
    }

    if (preload_path) {
        counter->pending_preload_allocator_calls++;
    } else {
        counter->pending_frida_allocator_calls++;
    }

    if (counter->pending_preload_allocator_calls +
            counter->pending_frida_allocator_calls >= MAI_PASS_THROUGH_FLUSH_INTERVAL) {
        flush_pass_through_counter(counter);
    }
}

static void stats_note_preload_allocator_path(void) {
    stats_note_allocator_path(1);
}

static void stats_note_frida_allocator_path(void) {
    stats_note_allocator_path(0);
}

#define NOTE_PRELOAD_ALLOCATOR_PATH() \
    do { \
        if (MAI_UNLIKELY(path_stats_enabled)) { \
            stats_note_preload_allocator_path(); \
        } \
    } while (0)

#define NOTE_FRIDA_ALLOCATOR_PATH() \
    do { \
        if (MAI_UNLIKELY(path_stats_enabled)) { \
            stats_note_frida_allocator_path(); \
        } \
    } while (0)

static void* fast_pass_through_malloc(size_t size) {
    void* ptr = pass_through_malloc(size);
    if (ptr && stats_logging) {
        stats_note_pass_through_threadsafe(size);
    }
    return ptr;
}

static void* fast_pass_through_calloc(size_t nmemb, size_t size, size_t total) {
    void* ptr = pass_through_calloc(nmemb, size);
    if (ptr && stats_logging) {
        stats_note_pass_through_threadsafe(total);
    }
    return ptr;
}

static void insert_record_locked(AllocationRecord* record) {
    size_t bucket = hash_ptr(record->user_ptr);

    record->hash_next = allocation_buckets[bucket];
    allocation_buckets[bucket] = record;

    record->live_prev = NULL;
    record->live_next = live_head;
    if (live_head) {
        live_head->live_prev = record;
    }
    live_head = record;
}

static AllocationRecord* find_record_locked(void* ptr) {
    for (AllocationRecord* record = allocation_buckets[hash_ptr(ptr)];
         record;
         record = record->hash_next) {
        if (record->user_ptr == ptr) {
            return record;
        }
    }

    return NULL;
}

static AllocationRecord* take_record_locked(void* ptr) {
    size_t bucket = hash_ptr(ptr);
    AllocationRecord* previous = NULL;

    for (AllocationRecord* record = allocation_buckets[bucket];
         record;
         record = record->hash_next) {
        if (record->user_ptr != ptr) {
            previous = record;
            continue;
        }

        if (previous) {
            previous->hash_next = record->hash_next;
        } else {
            allocation_buckets[bucket] = record->hash_next;
        }

        if (record->live_prev) {
            record->live_prev->live_next = record->live_next;
        } else {
            live_head = record->live_next;
        }
        if (record->live_next) {
            record->live_next->live_prev = record->live_prev;
        }

        record->hash_next = NULL;
        record->live_prev = NULL;
        record->live_next = NULL;
        return record;
    }

    return NULL;
}

static void update_managed_range(void* base, size_t length) {
    uintptr_t start = (uintptr_t)base;
    uintptr_t end = start + length;
    if (end < start) {
        end = UINTPTR_MAX;
    }

    uintptr_t low = atomic_load_explicit(&managed_range_low, memory_order_relaxed);
    while ((low == 0 || start < low) &&
           !atomic_compare_exchange_weak_explicit(&managed_range_low, &low, start,
                                                  memory_order_release,
                                                  memory_order_relaxed)) {
    }

    uintptr_t high = atomic_load_explicit(&managed_range_high, memory_order_relaxed);
    while (end > high &&
           !atomic_compare_exchange_weak_explicit(&managed_range_high, &high, end,
                                                  memory_order_release,
                                                  memory_order_relaxed)) {
    }
}

static int pointer_may_be_managed(void* ptr) {
    uintptr_t value = (uintptr_t)ptr;
    uintptr_t high = atomic_load_explicit(&managed_range_high, memory_order_acquire);
    if (high == 0) {
        return 0;
    }
    uintptr_t low = atomic_load_explicit(&managed_range_low, memory_order_acquire);

    return low != 0 && value >= low && value < high;
}

static int build_arena_template(char* buffer, size_t buffer_size) {
    size_t path_len = strlen(mai_path);
    const char* slash = path_len > 0 && mai_path[path_len - 1] == '/' ? "" : "/";
    int written = snprintf(buffer, buffer_size, "%s%s%s", mai_path, slash, MAI_FILE_TEMPLATE);

    if (written < 0 || (size_t)written >= buffer_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static ArenaSegment* create_segment_locked(size_t minimum_size) {
    char filename[PATH_MAX];
    int fd = -1;
    int saved_errno;
    size_t length = max_size(arena_size_bytes, minimum_size);
    ArenaSegment* segment = NULL;
    ArenaBlock* block = NULL;
    void* base;

    length = align_up_size(length, page_size);
    if (length == 0 || build_arena_template(filename, sizeof(filename)) != 0) {
        return NULL;
    }

    fd = mkstemp(filename);
    if (fd == -1) {
        return NULL;
    }

    if (unlink(filename) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    if (ftruncate(fd, (off_t)length) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    base = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    saved_errno = errno;
    close(fd);
    if (base == MAP_FAILED) {
        errno = saved_errno;
        return NULL;
    }

    segment = meta_alloc(sizeof(*segment));
    block = meta_alloc(sizeof(*block));
    if (!segment || !block) {
        meta_free(segment);
        meta_free(block);
        munmap(base, length);
        errno = ENOMEM;
        return NULL;
    }

    segment->base = base;
    segment->length = length;
    segment->id = next_segment_id++;
    segment->next = arena_segments;
    segment->blocks = block;
    arena_segments = segment;

    block->offset = 0;
    block->size = length;
    block->free = 1;
    block->segment = segment;
    block->prev = NULL;
    block->next = NULL;

    stats_snapshot.arena_segments++;
    stats_snapshot.arena_bytes += length;
    update_managed_range(base, length);

    return segment;
}

static void insert_block_before(ArenaBlock* block, ArenaBlock* new_block) {
    new_block->segment = block->segment;
    new_block->prev = block->prev;
    new_block->next = block;
    if (block->prev) {
        block->prev->next = new_block;
    } else {
        block->segment->blocks = new_block;
    }
    block->prev = new_block;
}

static void insert_block_after(ArenaBlock* block, ArenaBlock* new_block) {
    new_block->segment = block->segment;
    new_block->prev = block;
    new_block->next = block->next;
    if (block->next) {
        block->next->prev = new_block;
    }
    block->next = new_block;
}

static AllocationRecord* carve_block_locked(ArenaBlock* block, size_t user_size,
                                            size_t block_size, size_t alignment,
                                            void* call_site) {
    uintptr_t segment_base = (uintptr_t)block->segment->base;
    uintptr_t block_start = segment_base + block->offset;
    uintptr_t aligned_start = align_up_uintptr(block_start, alignment);
    size_t aligned_offset = (size_t)(aligned_start - segment_base);
    size_t prefix = aligned_offset - block->offset;
    size_t suffix;
    ArenaBlock* prefix_block = NULL;
    ArenaBlock* suffix_block = NULL;
    AllocationRecord* record = NULL;

    if (prefix > block->size || block_size > block->size - prefix) {
        return NULL;
    }
    suffix = block->size - prefix - block_size;

    if (prefix > 0) {
        prefix_block = meta_alloc(sizeof(*prefix_block));
        if (!prefix_block) {
            return NULL;
        }
    }
    if (suffix > 0) {
        suffix_block = meta_alloc(sizeof(*suffix_block));
        if (!suffix_block) {
            meta_free(prefix_block);
            return NULL;
        }
    }

    record = meta_alloc(sizeof(*record));
    if (!record) {
        meta_free(prefix_block);
        meta_free(suffix_block);
        return NULL;
    }

    if (prefix_block) {
        prefix_block->offset = block->offset;
        prefix_block->size = prefix;
        prefix_block->free = 1;
        insert_block_before(block, prefix_block);
    }

    block->offset = aligned_offset;
    block->size = block_size;
    block->free = 0;

    if (suffix_block) {
        suffix_block->offset = aligned_offset + block_size;
        suffix_block->size = suffix;
        suffix_block->free = 1;
        insert_block_after(block, suffix_block);
    }

    record->user_ptr = (void*)aligned_start;
    record->base_ptr = block->segment->base;
    record->user_size = user_size;
    record->mapped_length = block->segment->length;
    record->alignment = alignment;
    record->backend = BACKEND_ARENA;
    record->call_site = call_site;
    record->allocation_seq = ++allocation_sequence;
    record->reclaim_epoch = 0;
    record->hotness_samples = 0;
    record->hotness_sampled_pages = 0;
    record->hotness_resident_pages = 0;
    record->segment = block->segment;
    record->block = block;
    record->hash_next = NULL;
    record->live_prev = NULL;
    record->live_next = NULL;

    insert_record_locked(record);
    stats_note_managed_alloc(user_size);
    note_profile_locked(call_site, user_size);

    return record;
}

static AllocationRecord* managed_alloc_locked(size_t size, size_t alignment, void* call_site) {
    size_t block_size;
    size_t needed;

    if (size == 0 || !is_power_of_two(alignment)) {
        return NULL;
    }

    if (alignment < default_alignment()) {
        alignment = default_alignment();
    }
    if (alignment < page_size) {
        alignment = page_size;
    }

    block_size = align_up_size(size, page_size);
    if (block_size == 0) {
        return NULL;
    }

    if (add_overflow(block_size, alignment - 1, &needed) != 0) {
        return NULL;
    }

    for (;;) {
        for (ArenaSegment* segment = arena_segments; segment; segment = segment->next) {
            for (ArenaBlock* block = segment->blocks; block; block = block->next) {
                if (!block->free || block->size < block_size) {
                    continue;
                }

                uintptr_t base = (uintptr_t)segment->base;
                uintptr_t block_start = base + block->offset;
                uintptr_t aligned_start = align_up_uintptr(block_start, alignment);
                size_t aligned_offset = (size_t)(aligned_start - base);
                size_t prefix = aligned_offset - block->offset;
                if (prefix <= block->size && block_size <= block->size - prefix) {
                    return carve_block_locked(block, size, block_size, alignment, call_site);
                }
            }
        }

        if (!create_segment_locked(needed)) {
            return NULL;
        }
    }
}

static void coalesce_block_locked(ArenaBlock* block) {
    if (block->prev && block->prev->free) {
        ArenaBlock* previous = block->prev;
        previous->size += block->size;
        previous->next = block->next;
        if (block->next) {
            block->next->prev = previous;
        }
        meta_free(block);
        block = previous;
    }

    if (block->next && block->next->free) {
        ArenaBlock* next = block->next;
        block->size += next->size;
        block->next = next->next;
        if (next->next) {
            next->next->prev = block;
        }
        meta_free(next);
    }
}

static void managed_free_record_locked(AllocationRecord* record) {
    ArenaBlock* block = record->block;
    block->free = 1;
    stats_note_managed_free(record->user_size);
    coalesce_block_locked(block);
}

static AllocationRecord* free_managed_pointer_locked(void* ptr) {
    AllocationRecord* record = take_record_locked(ptr);
    if (record) {
        managed_free_record_locked(record);
    }
    return record;
}

static int should_manage(size_t size) {
    return runtime_enabled && runtime_configured && !mlockall_future_active &&
           size >= threshold_bytes && size > 0;
}

static int reclaim_record_locked(AllocationRecord* record) {
    void* range_start = NULL;
    size_t range_length = record_page_range(record, &range_start);
    int rc = 0;

    if (record_overlaps_exclusion_locked(record)) {
        stats_snapshot.reclaim_skipped_excluded++;
        stats_snapshot.reclaim_skipped_excluded_bytes += record->user_size;
        return 0;
    }

    if (range_length == 0) {
        return 0;
    }

    if (msync(range_start, range_length, MS_SYNC) != 0) {
        return -1;
    }

    int advice = MADV_DONTNEED;
#ifdef MADV_PAGEOUT
    if (reclaim_policy == RECLAIM_PAGEOUT) {
        advice = MADV_PAGEOUT;
    }
#endif
    if (madvise(range_start, range_length, advice) != 0) {
#ifdef MADV_PAGEOUT
        if (advice == MADV_PAGEOUT && errno == EINVAL &&
            madvise(range_start, range_length, MADV_DONTNEED) == 0) {
            record->reclaim_epoch = reclaim_epoch;
            stats_snapshot.reclaimed_bytes += record->user_size;
            return rc;
        }
#endif
        rc = -1;
    }

    if (rc != 0) {
        return rc;
    }

    record->reclaim_epoch = reclaim_epoch;
    stats_snapshot.reclaimed_bytes += record->user_size;
    return 0;
}

static size_t estimate_resident_bytes(size_t sampled_pages, size_t resident_pages,
                                      size_t total_pages, size_t max_bytes) {
    if (sampled_pages == 0 || resident_pages == 0 || total_pages == 0) {
        return 0;
    }

    if (resident_pages > SIZE_MAX / total_pages) {
        return max_bytes;
    }

    size_t estimated_pages = (resident_pages * total_pages + sampled_pages - 1) /
        sampled_pages;
    if (estimated_pages == 0) {
        estimated_pages = 1;
    }
    if (estimated_pages > total_pages) {
        estimated_pages = total_pages;
    }
    if (estimated_pages > SIZE_MAX / page_size) {
        return max_bytes;
    }

    size_t bytes = estimated_pages * page_size;
    return bytes > max_bytes ? max_bytes : bytes;
}

static AllocationRecord* select_reclaim_candidate_locked(size_t* estimated_bytes_out) {
    AllocationRecord* selected = NULL;
    size_t selected_estimated_bytes = 0;
    size_t selected_fallback_size = 0;

    *estimated_bytes_out = 0;

    if (reclaim_selection == RECLAIM_SELECT_ALL) {
        for (AllocationRecord* record = live_head; record; record = record->live_next) {
            if (record->reclaim_epoch != reclaim_epoch &&
                !record_overlaps_exclusion_locked(record)) {
                *estimated_bytes_out = record->user_size;
                return record;
            }
        }
        return NULL;
    }

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        if (record->reclaim_epoch == reclaim_epoch) {
            continue;
        }
        if (record_overlaps_exclusion_locked(record)) {
            continue;
        }

        if (reclaim_selection == RECLAIM_SELECT_ADAPTIVE) {
            size_t sampled_pages = 0;
            size_t resident_pages = 0;
            size_t total_pages = 0;
            size_t estimated_bytes = 0;
            if (sample_record_hotness_locked(record, &sampled_pages, &resident_pages,
                                             &total_pages) == 0) {
                estimated_bytes = estimate_resident_bytes(sampled_pages, resident_pages,
                                                          total_pages,
                                                          record->user_size);
            }

            if (!selected ||
                estimated_bytes > selected_estimated_bytes ||
                (estimated_bytes == selected_estimated_bytes &&
                 record->user_size > selected_fallback_size) ||
                (estimated_bytes == selected_estimated_bytes &&
                 record->user_size == selected_fallback_size &&
                 record->allocation_seq < selected->allocation_seq)) {
                selected = record;
                selected_estimated_bytes = estimated_bytes;
                selected_fallback_size = record->user_size;
            }
            continue;
        }

        if (!selected) {
            selected = record;
            selected_estimated_bytes = record->user_size;
            selected_fallback_size = record->user_size;
            continue;
        }

        if (reclaim_selection == RECLAIM_SELECT_LARGEST) {
            if (record->user_size > selected->user_size) {
                selected = record;
                selected_estimated_bytes = record->user_size;
                selected_fallback_size = record->user_size;
            }
        } else if (record->allocation_seq < selected->allocation_seq) {
            selected = record;
            selected_estimated_bytes = record->user_size;
            selected_fallback_size = record->user_size;
        }
    }

    if (selected) {
        if (reclaim_selection == RECLAIM_SELECT_ADAPTIVE) {
            *estimated_bytes_out = selected_estimated_bytes;
        } else {
            *estimated_bytes_out = selected->user_size;
        }
    }
    return selected;
}

static void maybe_policy_reclaim_locked(void) {
    size_t current_rss = update_observed_rss_locked();

    if (target_rss_bytes == 0 ||
        reclaim_policy == RECLAIM_NONE ||
        current_rss == 0 ||
        current_rss <= target_rss_bytes) {
        return;
    }

    size_t needed = current_rss - target_rss_bytes;
    size_t attempted = 0;
    reclaim_epoch++;
    stats_snapshot.policy_reclaim_calls++;

    while (attempted < needed) {
        size_t estimated_bytes = 0;
        AllocationRecord* candidate = select_reclaim_candidate_locked(&estimated_bytes);
        if (!candidate) {
            break;
        }

        int rc = reclaim_record_locked(candidate);
        if (estimated_bytes > 0) {
            attempted += estimated_bytes;
        } else if (rc == 0) {
            attempted += page_size;
        } else {
            attempted += candidate->user_size;
        }

        if (reclaim_selection == RECLAIM_SELECT_ALL) {
            continue;
        }
    }

    update_observed_rss_locked();
}

static void* allocate_by_policy(size_t size, size_t alignment, int zero_fill, int* managed,
                                void* call_site) {
    void* ptr = NULL;

    *managed = 0;
    if (should_manage(size)) {
        pthread_mutex_lock(&runtime_lock);
        AllocationRecord* record = managed_alloc_locked(size, alignment, call_site);
        if (record) {
            ptr = record->user_ptr;
            *managed = 1;
        }
        pthread_mutex_unlock(&runtime_lock);

        if (ptr) {
            if (zero_fill) {
                memset(ptr, 0, size);
            }
            pthread_mutex_lock(&runtime_lock);
            maybe_policy_reclaim_locked();
            pthread_mutex_unlock(&runtime_lock);
            return ptr;
        }

        errno = ENOMEM;
        return NULL;
    }

    if (zero_fill) {
        ptr = pass_through_calloc(1, size);
    } else if (alignment == default_alignment()) {
        ptr = pass_through_malloc(size);
    } else {
        if (pass_through_posix_memalign(&ptr, alignment, size) != 0) {
            ptr = NULL;
        }
    }

    if (ptr && stats_logging) {
        stats_note_pass_through_threadsafe(size);
    }

    return ptr;
}

static size_t record_page_range(AllocationRecord* record, void** range_start) {
    uintptr_t start = (uintptr_t)record->user_ptr;
    uintptr_t end = start + record->user_size;
    uintptr_t page_mask = (uintptr_t)page_size - 1;
    uintptr_t aligned_start = start & ~page_mask;
    uintptr_t aligned_end = (end + page_mask) & ~page_mask;

    if (aligned_end < aligned_start) {
        return 0;
    }

    *range_start = (void*)aligned_start;
    return (size_t)(aligned_end - aligned_start);
}

int mai_reclaim_all(void) {
    int rc = 0;

    pthread_mutex_lock(&runtime_lock);

    stats_snapshot.reclaim_calls++;
    reclaim_epoch++;

    if (reclaim_policy == RECLAIM_NONE) {
        pthread_mutex_unlock(&runtime_lock);
        return 0;
    }

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        if (reclaim_record_locked(record) != 0) {
            rc = -1;
        }
    }

    update_observed_rss_locked();
    pthread_mutex_unlock(&runtime_lock);
    return rc;
}

int mai_sample_hotness(void) {
    int rc;
    int saved_hook_depth = in_mai_hook;

    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    rc = sample_all_hotness_locked();
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;

    return rc;
}

int mai_get_stats(MaiStats* out) {
    if (!out) {
        errno = EINVAL;
        return -1;
    }

    flush_current_pass_through_counter();

    pthread_mutex_lock(&runtime_lock);
    update_observed_rss_locked();
    *out = stats_snapshot;
    snapshot_pass_through_counters_locked(&out->pass_through_allocations,
                                          &out->pass_through_bytes_total,
                                          &out->allocator_preload_calls,
                                          &out->allocator_frida_calls);
    out->enabled = runtime_enabled;
    out->configured = runtime_configured;
    out->config_error = runtime_config_error;
    out->threshold = threshold_bytes;
    out->arena_size = arena_size_bytes;
    out->target_rss = target_rss_bytes;
    pthread_mutex_unlock(&runtime_lock);

    return 0;
}

static void print_stats(void) {
    MaiStats stats;

    if (mai_get_stats(&stats) != 0) {
        return;
    }

    fprintf(stderr,
            "MAI stats: enabled=%d configured=%d config_error=%d threshold=%zu arena_size=%zu "
            "target_rss=%zu current_rss=%zu high_water_rss=%zu "
            "segments=%zu arena_bytes=%zu managed_total=%zu pass_through_total=%zu "
            "live_managed=%zu high_water=%zu managed_allocs=%zu pass_through_allocs=%zu "
            "managed_frees=%zu reclaim_calls=%zu policy_reclaim_calls=%zu reclaimed_bytes=%zu "
            "mmap_calls=%zu munmap_calls=%zu mremap_calls=%zu brk_calls=%zu sbrk_calls=%zu "
            "profile_sites=%zu hotness_samples=%zu hotness_sampled_pages=%zu "
            "hotness_resident_pages=%zu allocator_hook_mode=%zu allocator_libc_patches=%zu "
            "allocator_preload_calls=%zu allocator_frida_calls=%zu excluded_ranges=%zu "
            "excluded_bytes=%zu exclusion_events=%zu exclusion_release_events=%zu "
            "reclaim_skipped_excluded=%zu reclaim_skipped_excluded_bytes=%zu "
            "safety_hook_patches=%zu\n",
            stats.enabled, stats.configured, stats.config_error, stats.threshold,
            stats.arena_size, stats.target_rss, stats.current_rss_bytes,
            stats.high_water_rss_bytes, stats.arena_segments, stats.arena_bytes,
            stats.managed_bytes_total, stats.pass_through_bytes_total,
            stats.live_managed_bytes, stats.high_water_managed_bytes,
            stats.managed_allocations, stats.pass_through_allocations,
            stats.managed_frees, stats.reclaim_calls, stats.policy_reclaim_calls,
            stats.reclaimed_bytes, stats.mmap_calls, stats.munmap_calls,
            stats.mremap_calls, stats.brk_calls, stats.sbrk_calls,
            stats.profile_sites, stats.hotness_samples, stats.hotness_sampled_pages,
            stats.hotness_resident_pages, stats.allocator_hook_mode,
            stats.allocator_libc_patches, stats.allocator_preload_calls,
            stats.allocator_frida_calls, stats.excluded_ranges, stats.excluded_bytes,
            stats.exclusion_events, stats.exclusion_release_events,
            stats.reclaim_skipped_excluded, stats.reclaim_skipped_excluded_bytes,
            stats.safety_hook_patches);
}

static void print_profile_report(void) {
    if (!profile_enabled) {
        return;
    }

    fprintf(stderr, "MAI allocation profile:\n");
    for (size_t i = 0; i < MAI_PROFILE_BUCKETS; i++) {
        for (ProfileRecord* record = profile_buckets[i]; record; record = record->next) {
            Dl_info info;
            const char* symbol = NULL;
            const char* object = NULL;

            if (dladdr(record->call_site, &info) != 0) {
                symbol = info.dli_sname;
                object = info.dli_fname;
            }

            fprintf(stderr,
                    "  call_site=%p symbol=%s object=%s allocations=%zu bytes=%zu\n",
                    record->call_site,
                    symbol ? symbol : "?",
                    object ? object : "?",
                    record->allocations,
                    record->bytes);
        }
    }
}

static void print_hotness_report(void) {
    if (!hotness_enabled) {
        return;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    fprintf(stderr, "MAI hotness report: sample_pages=%zu\n", hotness_sample_pages);
    if (!live_head) {
        fprintf(stderr, "  no live managed allocations\n");
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        return;
    }

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        size_t sampled_pages = 0;
        size_t resident_pages = 0;
        size_t total_pages = 0;
        Dl_info info;
        const char* symbol = NULL;
        const char* object = NULL;

        (void)sample_record_hotness_locked(record, &sampled_pages, &resident_pages,
                                           &total_pages);

        if (dladdr(record->call_site, &info) != 0) {
            symbol = info.dli_sname;
            object = info.dli_fname;
        }

        fprintf(stderr,
                "  seq=%zu ptr=%p size=%zu pages=%zu sampled=%zu resident=%zu "
                "call_site=%p symbol=%s object=%s\n",
                record->allocation_seq,
                record->user_ptr,
                record->user_size,
                total_pages,
                sampled_pages,
                resident_pages,
                record->call_site,
                symbol ? symbol : "?",
                object ? object : "?");
    }

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
}

static int validate_directory(const char* path) {
    struct stat st;

    if (!path || path[0] == '\0') {
        return -1;
    }
    if (strlen(path) >= sizeof(mai_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    if (access(path, R_OK | W_OK | X_OK) != 0) {
        return -1;
    }

    return 0;
}

static const char* discover_backing_path(void) {
    static const char* env_names[] = {
        "SLURM_TMPDIR",
        "PBS_JOBFS",
        "TMPDIR",
        "LOCAL_SCRATCH",
        "SCRATCH",
        "JOBSCRATCH",
        NULL
    };
    const char* explicit_path = getenv("MAI_PATH");

    if (explicit_path && explicit_path[0] != '\0') {
        return validate_directory(explicit_path) == 0 ? explicit_path : NULL;
    }

    for (size_t i = 0; env_names[i]; i++) {
        const char* value = getenv(env_names[i]);
        if (validate_directory(value) == 0) {
            return value;
        }
    }

    return NULL;
}

static int configure_runtime(void) {
    const char* enable = getenv("MAI_ENABLE");
    const char* threshold = getenv("MAI_THRESHOLD");
    const char* arena_size = getenv("MAI_ARENA_SIZE");
    const char* target_rss = getenv("MAI_TARGET_RSS");
    const char* reclaim = getenv("MAI_RECLAIM_POLICY");
    const char* reclaim_select = getenv("MAI_RECLAIM_SELECTION");
    const char* hotness_sample = getenv("MAI_HOTNESS_SAMPLE_PAGES");
    const char* backing_path;

    runtime_enabled = parse_bool_env(enable);
    runtime_configured = 0;
    runtime_config_error = 0;
    verbose_logging = parse_bool_env(getenv("MAI_VERBOSE"));
    stats_logging = parse_bool_env(getenv("MAI_STATS"));
    path_stats_enabled = parse_bool_env(getenv("MAI_PATH_STATS"));
    profile_enabled = parse_bool_env(getenv("MAI_PROFILE"));
    hotness_enabled = parse_bool_env(getenv("MAI_HOTNESS"));
    reclaim_policy = RECLAIM_NONE;
    reclaim_selection = RECLAIM_SELECT_OLDEST;

    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        page_size = 4096;
    }

    threshold_bytes = MAI_DEFAULT_THRESHOLD;
    arena_size_bytes = MAI_DEFAULT_ARENA_SIZE;
    target_rss_bytes = 0;
    hotness_sample_pages = MAI_DEFAULT_HOTNESS_SAMPLE_PAGES;

    memset(&stats_snapshot, 0, sizeof(stats_snapshot));
    pass_through_counter_generation++;
    if (pass_through_counter_generation == 0) {
        pass_through_counter_generation = 1;
    }
    pass_through_counters = NULL;
    atomic_store_explicit(&pass_through_fallback_allocations_counter, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&pass_through_fallback_bytes_counter, 0, memory_order_relaxed);
    memset(allocation_buckets, 0, sizeof(allocation_buckets));
    memset(profile_buckets, 0, sizeof(profile_buckets));
    live_head = NULL;
    arena_segments = NULL;
    dynamic_replacements = NULL;
    exclusion_ranges = NULL;
    registration_records = NULL;
    mlockall_future_active = 0;
    atomic_store_explicit(&dynamic_replacements_active, 0, memory_order_relaxed);
    atomic_store_explicit(&managed_range_low, 0, memory_order_relaxed);
    atomic_store_explicit(&managed_range_high, 0, memory_order_relaxed);
    next_segment_id = 0;
    allocation_sequence = 0;
    reclaim_epoch = 0;

    if (!runtime_enabled) {
        return 0;
    }

    if (threshold && parse_size_env(threshold, &threshold_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (arena_size && parse_size_env(arena_size, &arena_size_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (target_rss && parse_size_env(target_rss, &target_rss_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (hotness_sample && parse_count_env(hotness_sample, &hotness_sample_pages) != 0) {
        runtime_config_error = 1;
        return -1;
    }

    if (threshold_bytes == 0) {
        threshold_bytes = 1;
    }
    if (arena_size_bytes < MAI_MIN_ARENA_SIZE) {
        arena_size_bytes = MAI_MIN_ARENA_SIZE;
    }
    if (hotness_sample_pages == 0) {
        hotness_sample_pages = 1;
    }
    if (hotness_sample_pages > MAI_MAX_HOTNESS_SAMPLE_PAGES) {
        hotness_sample_pages = MAI_MAX_HOTNESS_SAMPLE_PAGES;
    }

    if (reclaim) {
        if (strcmp(reclaim, "none") == 0) {
            reclaim_policy = RECLAIM_NONE;
        } else if (strcmp(reclaim, "donthneed") == 0) {
            reclaim_policy = RECLAIM_DONTNEED;
        } else if (strcmp(reclaim, "pageout") == 0) {
#ifdef MADV_PAGEOUT
            reclaim_policy = RECLAIM_PAGEOUT;
#else
            reclaim_policy = RECLAIM_DONTNEED;
#endif
        } else {
            runtime_config_error = 1;
            return -1;
        }
    }
    if (reclaim_select) {
        if (strcmp(reclaim_select, "oldest") == 0) {
            reclaim_selection = RECLAIM_SELECT_OLDEST;
        } else if (strcmp(reclaim_select, "largest") == 0) {
            reclaim_selection = RECLAIM_SELECT_LARGEST;
        } else if (strcmp(reclaim_select, "all") == 0) {
            reclaim_selection = RECLAIM_SELECT_ALL;
        } else if (strcmp(reclaim_select, "adaptive") == 0) {
            reclaim_selection = RECLAIM_SELECT_ADAPTIVE;
        } else {
            runtime_config_error = 1;
            return -1;
        }
    }

    backing_path = discover_backing_path();
    if (!backing_path) {
        runtime_config_error = 1;
        return -1;
    }

    snprintf(mai_path, sizeof(mai_path), "%s", backing_path);
    runtime_configured = 1;
    return 0;
}

static void* custom_malloc_from_site(size_t size, void* call_site) {
    if (in_mai_hook || cleanup_in_progress || !runtime_configured) {
        return pass_through_malloc(size);
    }

    if (!should_manage(size)) {
        return fast_pass_through_malloc(size);
    }

    in_mai_hook++;
    int managed = 0;
    void* ptr = allocate_by_policy(size, default_alignment(), 0, &managed, call_site);
    in_mai_hook--;

    (void)managed;
    return ptr;
}

static void* custom_malloc(size_t size) {
    return custom_malloc_from_site(size, __builtin_return_address(0));
}

static void custom_free(void* ptr) {
    int saved_errno = errno;

    if (!ptr) {
        return;
    }

    if (in_mai_hook || cleanup_in_progress || !runtime_configured) {
        pass_through_free(ptr);
        errno = saved_errno;
        return;
    }

    if (!pointer_may_be_managed(ptr)) {
        pass_through_free(ptr);
        errno = saved_errno;
        return;
    }

    in_mai_hook++;

    pthread_mutex_lock(&runtime_lock);
    AllocationRecord* record = free_managed_pointer_locked(ptr);
    pthread_mutex_unlock(&runtime_lock);

    if (record) {
        meta_free(record);
    } else {
        pass_through_free(ptr);
    }

    in_mai_hook--;
    errno = saved_errno;
}

static void* custom_calloc_from_site(size_t nmemb, size_t size, void* call_site) {
    size_t total;

    if (mul_overflow(nmemb, size, &total) != 0) {
        return NULL;
    }

    if (in_mai_hook || cleanup_in_progress || !runtime_configured) {
        return pass_through_calloc(nmemb, size);
    }

    if (!should_manage(total)) {
        return fast_pass_through_calloc(nmemb, size, total);
    }

    in_mai_hook++;
    int managed = 0;
    void* ptr = allocate_by_policy(total, default_alignment(), 1, &managed, call_site);
    in_mai_hook--;

    (void)managed;
    return ptr;
}

static void* custom_calloc(size_t nmemb, size_t size) {
    return custom_calloc_from_site(nmemb, size, __builtin_return_address(0));
}

static void* custom_realloc_from_site(void* ptr, size_t size, void* call_site) {
    if (!ptr) {
        return custom_malloc_from_site(size, call_site);
    }
    if (size == 0) {
        custom_free(ptr);
        return NULL;
    }

    if (in_mai_hook || cleanup_in_progress || !runtime_configured) {
        return pass_through_realloc(ptr, size);
    }

    in_mai_hook++;

    if (!pointer_may_be_managed(ptr)) {
        if (should_manage(size)) {
            size_t old_size = pass_through_malloc_usable_size(ptr);
            int managed = 0;
            void* new_ptr = allocate_by_policy(size, default_alignment(), 0, &managed,
                                               call_site);
            if (new_ptr) {
                memcpy(new_ptr, ptr, old_size < size ? old_size : size);
                pass_through_free(ptr);
                in_mai_hook--;
                return new_ptr;
            }
            in_mai_hook--;
            return NULL;
        }

        void* result = pass_through_realloc(ptr, size);
        if (result && stats_logging) {
            stats_note_pass_through_threadsafe(size);
        }
        in_mai_hook--;
        return result;
    }

    pthread_mutex_lock(&runtime_lock);
    AllocationRecord* record = find_record_locked(ptr);
    if (record) {
        size_t old_size = record->user_size;
        if (size <= old_size) {
            stats_reduce_live_managed(old_size - size);
            record->user_size = size;
            pthread_mutex_unlock(&runtime_lock);
            in_mai_hook--;
            return ptr;
        }
    }
    pthread_mutex_unlock(&runtime_lock);

    if (record) {
        int managed = 0;
        void* new_ptr = allocate_by_policy(size, default_alignment(), 0, &managed,
                                           call_site);
        if (!new_ptr) {
            in_mai_hook--;
            return NULL;
        }

        memcpy(new_ptr, ptr, record->user_size);
        pthread_mutex_lock(&runtime_lock);
        AllocationRecord* old_record = free_managed_pointer_locked(ptr);
        pthread_mutex_unlock(&runtime_lock);
        meta_free(old_record);
        in_mai_hook--;
        return new_ptr;
    }

    if (should_manage(size)) {
        size_t old_size = pass_through_malloc_usable_size(ptr);
        int managed = 0;
        void* new_ptr = allocate_by_policy(size, default_alignment(), 0, &managed,
                                           call_site);
        if (new_ptr) {
            memcpy(new_ptr, ptr, old_size < size ? old_size : size);
            pass_through_free(ptr);
            in_mai_hook--;
            return new_ptr;
        }
        in_mai_hook--;
        return NULL;
    }

    void* result = pass_through_realloc(ptr, size);
    if (result && stats_logging) {
        stats_note_pass_through_threadsafe(size);
    }

    in_mai_hook--;
    return result;
}

static void* custom_realloc(void* ptr, size_t size) {
    return custom_realloc_from_site(ptr, size, __builtin_return_address(0));
}

static void* custom_aligned_alloc_from_site(size_t alignment, size_t size, void* call_site) {
    if (in_mai_hook || cleanup_in_progress || !runtime_configured || !should_manage(size)) {
        void* ptr = pass_through_aligned_alloc(alignment, size);
        if (ptr && stats_logging && !in_mai_hook && !cleanup_in_progress &&
            runtime_configured) {
            stats_note_pass_through_threadsafe(size);
        }
        return ptr;
    }

    if (!is_power_of_two(alignment) || size % alignment != 0) {
        errno = EINVAL;
        return NULL;
    }

    in_mai_hook++;
    int managed = 0;
    void* ptr = allocate_by_policy(size, alignment, 0, &managed, call_site);
    in_mai_hook--;

    (void)managed;
    return ptr;
}

static void* custom_aligned_alloc(size_t alignment, size_t size) {
    return custom_aligned_alloc_from_site(alignment, size, __builtin_return_address(0));
}

static int custom_posix_memalign_from_site(void** memptr, size_t alignment, size_t size,
                                           void* call_site) {
    if (!memptr || !is_power_of_two(alignment) || alignment % sizeof(void*) != 0) {
        return EINVAL;
    }

    if (in_mai_hook || cleanup_in_progress || !runtime_configured) {
        return pass_through_posix_memalign(memptr, alignment, size);
    }

    in_mai_hook++;

    if (should_manage(size)) {
        pthread_mutex_lock(&runtime_lock);
        AllocationRecord* record = managed_alloc_locked(size, alignment, call_site);
        if (record) {
            *memptr = record->user_ptr;
        }
        pthread_mutex_unlock(&runtime_lock);
        if (record) {
            pthread_mutex_lock(&runtime_lock);
            maybe_policy_reclaim_locked();
            pthread_mutex_unlock(&runtime_lock);
            in_mai_hook--;
            return 0;
        }

        in_mai_hook--;
        return ENOMEM;
    }

    int ret = pass_through_posix_memalign(memptr, alignment, size);
    if (ret == 0 && stats_logging) {
        stats_note_pass_through_threadsafe(size);
    }

    in_mai_hook--;
    return ret;
}

static int custom_posix_memalign(void** memptr, size_t alignment, size_t size) {
    return custom_posix_memalign_from_site(memptr, alignment, size,
                                           __builtin_return_address(0));
}

static void* custom_memalign_from_site(size_t alignment, size_t size, void* call_site) {
    if (in_mai_hook || cleanup_in_progress || !runtime_configured || !should_manage(size)) {
        void* ptr = pass_through_memalign(alignment, size);
        if (ptr && stats_logging && !in_mai_hook && !cleanup_in_progress &&
            runtime_configured) {
            stats_note_pass_through_threadsafe(size);
        }
        return ptr;
    }

    if (!is_power_of_two(alignment)) {
        errno = EINVAL;
        return NULL;
    }

    in_mai_hook++;
    int managed = 0;
    void* ptr = allocate_by_policy(size, alignment, 0, &managed, call_site);
    in_mai_hook--;

    (void)managed;
    return ptr;
}

static void* custom_memalign(size_t alignment, size_t size) {
    return custom_memalign_from_site(alignment, size, __builtin_return_address(0));
}

static void* custom_valloc(size_t size) {
    return custom_memalign(page_size, size);
}

static void* custom_pvalloc(size_t size) {
    size_t rounded = align_up_size(size, page_size);
    if (rounded == 0) {
        return NULL;
    }
    return custom_memalign(page_size, rounded);
}

static size_t custom_malloc_usable_size(void* ptr) {
    if (!ptr || cleanup_in_progress || !runtime_configured) {
        return pass_through_malloc_usable_size(ptr);
    }

    if (!pointer_may_be_managed(ptr)) {
        return pass_through_malloc_usable_size(ptr);
    }

    pthread_mutex_lock(&runtime_lock);
    AllocationRecord* record = find_record_locked(ptr);
    size_t usable_size = record ? record->user_size : 0;
    pthread_mutex_unlock(&runtime_lock);

    if (record) {
        return usable_size;
    }

    return pass_through_malloc_usable_size(ptr);
}

__attribute__((visibility("default")))
void* malloc(size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return direct_libc_malloc(size);
    }
    if (MAI_UNLIKELY(resolving_original_allocators)) {
        return fallback_malloc(size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    if (MAI_UNLIKELY(in_mai_hook || cleanup_in_progress)) {
        return call_libc_malloc(size);
    }
    if (MAI_LIKELY(size < threshold_bytes || size == 0)) {
        void* ptr = call_libc_malloc(size);
        if (ptr && MAI_UNLIKELY(stats_logging)) {
            stats_note_pass_through_threadsafe(size);
        }
        return ptr;
    }
    return custom_malloc_from_site(size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
void free(void* ptr) {
    if (MAI_UNLIKELY(!ptr)) {
        return;
    }
    if (MAI_UNLIKELY(!runtime_configured)) {
        int saved_errno = errno;
        direct_libc_free(ptr);
        errno = saved_errno;
        return;
    }
    if (MAI_UNLIKELY(resolving_original_allocators)) {
        fallback_free(ptr);
        return;
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    if (MAI_UNLIKELY(in_mai_hook || cleanup_in_progress)) {
        int saved_errno = errno;
        call_libc_free(ptr);
        errno = saved_errno;
        return;
    }
    if (MAI_LIKELY(!pointer_may_be_managed(ptr))) {
        int saved_errno = errno;
        call_libc_free(ptr);
        errno = saved_errno;
        return;
    }
    custom_free(ptr);
}

__attribute__((visibility("default")))
void* calloc(size_t nmemb, size_t size) {
    size_t total = 0;
    if (MAI_UNLIKELY(mul_overflow(nmemb, size, &total) != 0)) {
        return NULL;
    }
    if (MAI_UNLIKELY(!runtime_configured)) {
        return direct_libc_calloc(nmemb, size);
    }
    if (MAI_UNLIKELY(resolving_original_allocators)) {
        return fallback_calloc(nmemb, size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    if (MAI_UNLIKELY(in_mai_hook || cleanup_in_progress)) {
        return call_libc_calloc(nmemb, size);
    }
    if (MAI_LIKELY(total < threshold_bytes || total == 0)) {
        void* ptr = call_libc_calloc(nmemb, size);
        if (ptr && MAI_UNLIKELY(stats_logging)) {
            stats_note_pass_through_threadsafe(total);
        }
        return ptr;
    }
    return custom_calloc_from_site(nmemb, size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
void* realloc(void* ptr, size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return direct_libc_realloc(ptr, size);
    }
    if (MAI_UNLIKELY(resolving_original_allocators)) {
        return fallback_realloc(ptr, size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    if (MAI_UNLIKELY(!ptr)) {
        return malloc(size);
    }
    if (MAI_UNLIKELY(size == 0)) {
        free(ptr);
        return NULL;
    }
    if (MAI_UNLIKELY(in_mai_hook || cleanup_in_progress)) {
        void* result = call_libc_realloc(ptr, size);
        if (result && MAI_UNLIKELY(stats_logging) && runtime_configured &&
            !in_mai_hook && !cleanup_in_progress) {
            stats_note_pass_through_threadsafe(size);
        }
        return result;
    }
    if (MAI_LIKELY(!pointer_may_be_managed(ptr) &&
                   (size < threshold_bytes || size == 0))) {
        void* result = call_libc_realloc(ptr, size);
        if (result && MAI_UNLIKELY(stats_logging)) {
            stats_note_pass_through_threadsafe(size);
        }
        return result;
    }
    return custom_realloc_from_site(ptr, size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
void* aligned_alloc(size_t alignment, size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return pass_through_aligned_alloc(alignment, size);
    }
    if (resolving_original_allocators) {
        return fallback_memalign(alignment, size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    return custom_aligned_alloc_from_site(alignment, size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
int posix_memalign(void** memptr, size_t alignment, size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return pass_through_posix_memalign(memptr, alignment, size);
    }
    if (resolving_original_allocators) {
        void* ptr = fallback_memalign(alignment, size);
        if (!ptr) {
            return ENOMEM;
        }
        *memptr = ptr;
        return 0;
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    return custom_posix_memalign_from_site(memptr, alignment, size,
                                           __builtin_return_address(0));
}

__attribute__((visibility("default")))
void* memalign(size_t alignment, size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return pass_through_memalign(alignment, size);
    }
    if (resolving_original_allocators) {
        return fallback_memalign(alignment, size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    return custom_memalign_from_site(alignment, size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
void* valloc(size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        if (!original_valloc) {
            resolve_original_allocators();
        }
        return original_valloc ? original_valloc(size) : pass_through_memalign(page_size, size);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    return custom_memalign_from_site(page_size, size, __builtin_return_address(0));
}

__attribute__((visibility("default")))
void* pvalloc(size_t size) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        if (!original_pvalloc) {
            resolve_original_allocators();
        }
        if (original_pvalloc) {
            return original_pvalloc(size);
        }
        size_t rounded = align_up_size(size, page_size);
        return rounded == 0 ? NULL : pass_through_memalign(page_size, rounded);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    size_t rounded = align_up_size(size, page_size);
    if (rounded == 0) {
        return NULL;
    }
    return custom_memalign_from_site(page_size, rounded, __builtin_return_address(0));
}

__attribute__((visibility("default")))
size_t malloc_usable_size(void* ptr) {
    if (MAI_UNLIKELY(!runtime_configured)) {
        return call_libc_malloc_usable_size(ptr);
    }
    NOTE_PRELOAD_ALLOCATOR_PATH();
    if (!ptr || resolving_original_allocators || cleanup_in_progress ||
        !pointer_may_be_managed(ptr)) {
        return call_libc_malloc_usable_size(ptr);
    }
    return custom_malloc_usable_size(ptr);
}

__attribute__((visibility("default")))
int mlock(const void* addr, size_t len) {
    return custom_mlock(addr, len);
}

__attribute__((visibility("default")))
int mlock2(const void* addr, size_t len, unsigned int flags) {
    return custom_mlock2(addr, len, flags);
}

__attribute__((visibility("default")))
int mlockall(int flags) {
    return custom_mlockall(flags);
}

__attribute__((visibility("default")))
int munlock(const void* addr, size_t len) {
    return custom_munlock(addr, len);
}

__attribute__((visibility("default")))
int munlockall(void) {
    return custom_munlockall();
}

__attribute__((visibility("default")))
int cudaHostAlloc(void** ptr, size_t size, unsigned int flags) {
    return custom_cudaHostAlloc(ptr, size, flags);
}

__attribute__((visibility("default")))
int cudaMallocHost(void** ptr, size_t size) {
    return custom_cudaMallocHost(ptr, size);
}

__attribute__((visibility("default")))
int cudaHostRegister(void* ptr, size_t size, unsigned int flags) {
    return custom_cudaHostRegister(ptr, size, flags);
}

__attribute__((visibility("default")))
int cudaHostUnregister(void* ptr) {
    return custom_cudaHostUnregister(ptr);
}

__attribute__((visibility("default")))
int cudaFreeHost(void* ptr) {
    return custom_cudaFreeHost(ptr);
}

__attribute__((visibility("default")))
int cudaMallocManaged(void** ptr, size_t size, unsigned int flags) {
    return custom_cudaMallocManaged(ptr, size, flags);
}

__attribute__((visibility("default")))
int cudaFree(void* ptr) {
    return custom_cudaFree(ptr);
}

__attribute__((visibility("default")))
int hipHostMalloc(void** ptr, size_t size, unsigned int flags) {
    return custom_hipHostMalloc(ptr, size, flags);
}

__attribute__((visibility("default")))
int hipHostRegister(void* ptr, size_t size, unsigned int flags) {
    return custom_hipHostRegister(ptr, size, flags);
}

__attribute__((visibility("default")))
int hipHostUnregister(void* ptr) {
    return custom_hipHostUnregister(ptr);
}

__attribute__((visibility("default")))
int hipHostFree(void* ptr) {
    return custom_hipHostFree(ptr);
}

__attribute__((visibility("default")))
int hipMallocManaged(void** ptr, size_t size, unsigned int flags) {
    return custom_hipMallocManaged(ptr, size, flags);
}

__attribute__((visibility("default")))
int hipFree(void* ptr) {
    return custom_hipFree(ptr);
}

__attribute__((visibility("default")))
int MPI_Alloc_mem(intptr_t size, void* info, void* baseptr) {
    return custom_MPI_Alloc_mem(size, info, baseptr);
}

__attribute__((visibility("default")))
int MPI_Free_mem(void* base) {
    return custom_MPI_Free_mem(base);
}

__attribute__((visibility("default")))
void* ibv_reg_mr(void* pd, void* addr, size_t length, int access) {
    return custom_ibv_reg_mr(pd, addr, length, access);
}

__attribute__((visibility("default")))
void* ibv_reg_mr_iova(void* pd, void* addr, size_t length, uint64_t iova, int access) {
    return custom_ibv_reg_mr_iova(pd, addr, length, iova, access);
}

__attribute__((visibility("default")))
int ibv_rereg_mr(void* mr, int flags, void* pd, void* addr, size_t length, int access) {
    return custom_ibv_rereg_mr(mr, flags, pd, addr, length, access);
}

__attribute__((visibility("default")))
int ibv_dereg_mr(void* mr) {
    return custom_ibv_dereg_mr(mr);
}

__attribute__((visibility("default")))
void* rdma_reg_msgs(void* id, void* addr, size_t length) {
    return custom_rdma_reg_msgs(id, addr, length);
}

__attribute__((visibility("default")))
void* rdma_reg_read(void* id, void* addr, size_t length) {
    return custom_rdma_reg_read(id, addr, length);
}

__attribute__((visibility("default")))
void* rdma_reg_write(void* id, void* addr, size_t length) {
    return custom_rdma_reg_write(id, addr, length);
}

__attribute__((visibility("default")))
int rdma_dereg_mr(void* mr) {
    return custom_rdma_dereg_mr(mr);
}

void* mai_operator_new_allocate(size_t size) {
    if (size == 0) {
        size = 1;
    }
    return custom_malloc(size);
}

void* mai_operator_new_aligned_allocate(size_t size, size_t alignment) {
    void* ptr = NULL;

    if (size == 0) {
        size = 1;
    }
    if (!is_power_of_two(alignment) || alignment < sizeof(void*)) {
        errno = EINVAL;
        return NULL;
    }

    if (custom_posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }

    return ptr;
}

void mai_operator_delete_free(void* ptr) {
    custom_free(ptr);
}

static void note_diagnostic_counter(size_t* counter) {
    if (in_mai_hook || !runtime_configured) {
        return;
    }

    pthread_mutex_lock(&runtime_lock);
    (*counter)++;
    pthread_mutex_unlock(&runtime_lock);
}

static void* custom_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    note_diagnostic_counter(&stats_snapshot.mmap_calls);
    return original_mmap(addr, length, prot, flags, fd, offset);
}

static int custom_munmap(void* addr, size_t length) {
    note_diagnostic_counter(&stats_snapshot.munmap_calls);
    return original_munmap(addr, length);
}

static void* custom_mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) {
    note_diagnostic_counter(&stats_snapshot.mremap_calls);
#ifdef MREMAP_FIXED
    if (flags & MREMAP_FIXED) {
        return original_mremap(old_address, old_size, new_size, flags, new_address);
    }
#endif
    return original_mremap(old_address, old_size, new_size, flags);
}

static int custom_brk(void* addr) {
    note_diagnostic_counter(&stats_snapshot.brk_calls);
    return original_brk(addr);
}

static void* custom_sbrk(intptr_t increment) {
    note_diagnostic_counter(&stats_snapshot.sbrk_calls);
    return original_sbrk(increment);
}

static void note_exclusion(void* ptr, size_t length, ExclusionKind kind, void* token) {
    if (!runtime_configured || cleanup_in_progress || !ptr || length == 0) {
        return;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    add_exclusion_range_locked(ptr, length, kind, token ? token : ptr);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
}

static void release_exclusion_range(void* ptr, size_t length, ExclusionKind kind) {
    if (!runtime_configured || cleanup_in_progress || !ptr || length == 0) {
        return;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    remove_exclusion_range_locked(ptr, length, kind);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
}

static void release_exclusion_start(void* ptr, ExclusionKind kind) {
    if (!runtime_configured || cleanup_in_progress || !ptr) {
        return;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    remove_exclusion_start_locked(ptr, kind);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
}

static int missing_status_symbol(void) {
    errno = ENOSYS;
    return -1;
}

static int missing_runtime_status(void) {
    return 1;
}

static int custom_mlock(const void* addr, size_t len) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MLOCK);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(const void*, size_t))replacement->original)(addr, len);
    } else {
        rc = (int)syscall(SYS_mlock, addr, len);
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        note_exclusion((void*)addr, len, EXCLUSION_MLOCK, (void*)addr);
    }
    return rc;
}

static int custom_mlock2(const void* addr, size_t len, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MLOCK2);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(const void*, size_t, unsigned int))replacement->original)(addr,
                                                                                 len,
                                                                                 flags);
    } else {
#ifdef SYS_mlock2
        rc = (int)syscall(SYS_mlock2, addr, len, flags);
#else
        rc = flags == 0 ? (int)syscall(SYS_mlock, addr, len) : missing_status_symbol();
#endif
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        note_exclusion((void*)addr, len, EXCLUSION_MLOCK, (void*)addr);
    }
    return rc;
}

static int custom_mlockall(int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MLOCKALL);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(int))replacement->original)(flags);
    } else {
        rc = (int)syscall(SYS_mlockall, flags);
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && runtime_configured && !cleanup_in_progress) {
        int saved_internal_depth = in_mai_hook;
        in_mai_hook++;
        pthread_mutex_lock(&runtime_lock);
#ifdef MCL_CURRENT
        if (flags & MCL_CURRENT) {
            mark_all_live_excluded_locked(EXCLUSION_MLOCKALL);
        }
#endif
#ifdef MCL_FUTURE
        if (flags & MCL_FUTURE) {
            mlockall_future_active = 1;
        }
#endif
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_internal_depth;
    }
    return rc;
}

static int custom_munlock(const void* addr, size_t len) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MUNLOCK);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(const void*, size_t))replacement->original)(addr, len);
    } else {
        rc = (int)syscall(SYS_munlock, addr, len);
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_range((void*)addr, len, EXCLUSION_MLOCK);
    }
    return rc;
}

static int custom_munlockall(void) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MUNLOCKALL);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void))replacement->original)();
    } else {
        rc = (int)syscall(SYS_munlockall);
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && runtime_configured && !cleanup_in_progress) {
        int saved_internal_depth = in_mai_hook;
        in_mai_hook++;
        pthread_mutex_lock(&runtime_lock);
        remove_exclusions_by_kind_locked(EXCLUSION_MLOCK);
        remove_exclusions_by_kind_locked(EXCLUSION_MLOCKALL);
        mlockall_future_active = 0;
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_internal_depth;
    }
    return rc;
}

static int custom_cudaHostAlloc(void** ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_HOST_ALLOC);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void**, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_cudaHostAlloc) {
            resolve_original_safety_functions();
        }
        rc = original_cudaHostAlloc ?
            original_cudaHostAlloc(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && ptr && *ptr) {
        note_exclusion(*ptr, size, EXCLUSION_CUDA_HOST, *ptr);
    }
    return rc;
}

static int custom_cudaMallocHost(void** ptr, size_t size) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_MALLOC_HOST);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void**, size_t))replacement->original)(ptr, size);
    } else {
        if (!original_cudaMallocHost) {
            resolve_original_safety_functions();
        }
        rc = original_cudaMallocHost ?
            original_cudaMallocHost(ptr, size) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && ptr && *ptr) {
        note_exclusion(*ptr, size, EXCLUSION_CUDA_HOST, *ptr);
    }
    return rc;
}

static int custom_cudaHostRegister(void* ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_HOST_REGISTER);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_cudaHostRegister) {
            resolve_original_safety_functions();
        }
        rc = original_cudaHostRegister ?
            original_cudaHostRegister(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        note_exclusion(ptr, size, EXCLUSION_CUDA_HOST, ptr);
    }
    return rc;
}

static int custom_cudaHostUnregister(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_HOST_UNREGISTER);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_cudaHostUnregister) {
            resolve_original_safety_functions();
        }
        rc = original_cudaHostUnregister ?
            original_cudaHostUnregister(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_CUDA_HOST);
    }
    return rc;
}

static int custom_cudaFreeHost(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_FREE_HOST);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_cudaFreeHost) {
            resolve_original_safety_functions();
        }
        rc = original_cudaFreeHost ? original_cudaFreeHost(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_CUDA_HOST);
    }
    return rc;
}

static int custom_cudaMallocManaged(void** ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_MALLOC_MANAGED);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void**, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_cudaMallocManaged) {
            resolve_original_safety_functions();
        }
        rc = original_cudaMallocManaged ?
            original_cudaMallocManaged(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && ptr && *ptr) {
        note_exclusion(*ptr, size, EXCLUSION_CUDA_MANAGED, *ptr);
    }
    return rc;
}

static int custom_cudaFree(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_CUDA_FREE);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_cudaFree) {
            resolve_original_safety_functions();
        }
        rc = original_cudaFree ? original_cudaFree(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_CUDA_MANAGED);
    }
    return rc;
}

static int custom_hipHostMalloc(void** ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_HOST_MALLOC);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void**, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_hipHostMalloc) {
            resolve_original_safety_functions();
        }
        rc = original_hipHostMalloc ?
            original_hipHostMalloc(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && ptr && *ptr) {
        note_exclusion(*ptr, size, EXCLUSION_HIP_HOST, *ptr);
    }
    return rc;
}

static int custom_hipHostRegister(void* ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_HOST_REGISTER);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_hipHostRegister) {
            resolve_original_safety_functions();
        }
        rc = original_hipHostRegister ?
            original_hipHostRegister(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        note_exclusion(ptr, size, EXCLUSION_HIP_HOST, ptr);
    }
    return rc;
}

static int custom_hipHostUnregister(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_HOST_UNREGISTER);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_hipHostUnregister) {
            resolve_original_safety_functions();
        }
        rc = original_hipHostUnregister ?
            original_hipHostUnregister(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_HIP_HOST);
    }
    return rc;
}

static int custom_hipHostFree(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_HOST_FREE);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_hipHostFree) {
            resolve_original_safety_functions();
        }
        rc = original_hipHostFree ? original_hipHostFree(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_HIP_HOST);
    }
    return rc;
}

static int custom_hipMallocManaged(void** ptr, size_t size, unsigned int flags) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_MALLOC_MANAGED);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void**, size_t, unsigned int))replacement->original)(ptr, size, flags);
    } else {
        if (!original_hipMallocManaged) {
            resolve_original_safety_functions();
        }
        rc = original_hipMallocManaged ?
            original_hipMallocManaged(ptr, size, flags) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && ptr && *ptr) {
        note_exclusion(*ptr, size, EXCLUSION_HIP_MANAGED, *ptr);
    }
    return rc;
}

static int custom_hipFree(void* ptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_HIP_FREE);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(ptr);
    } else {
        if (!original_hipFree) {
            resolve_original_safety_functions();
        }
        rc = original_hipFree ? original_hipFree(ptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(ptr, EXCLUSION_HIP_MANAGED);
    }
    return rc;
}

static int custom_MPI_Alloc_mem(intptr_t size, void* info, void* baseptr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MPI_ALLOC_MEM);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(intptr_t, void*, void*))replacement->original)(size, info, baseptr);
    } else {
        if (!original_MPI_Alloc_mem) {
            resolve_original_safety_functions();
        }
        rc = original_MPI_Alloc_mem ?
            original_MPI_Alloc_mem(size, info, baseptr) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0 && baseptr && size > 0) {
        void* allocated = *(void**)baseptr;
        if (allocated) {
            note_exclusion(allocated, (size_t)size, EXCLUSION_MPI, allocated);
        }
    }
    return rc;
}

static int custom_MPI_Free_mem(void* base) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_MPI_FREE_MEM);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(base);
    } else {
        if (!original_MPI_Free_mem) {
            resolve_original_safety_functions();
        }
        rc = original_MPI_Free_mem ? original_MPI_Free_mem(base) : missing_runtime_status();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_exclusion_start(base, EXCLUSION_MPI);
    }
    return rc;
}

static void remember_rdma_registration(void* mr, void* addr, size_t length) {
    if (!mr || !runtime_configured || !addr || length == 0) {
        return;
    }

    int saved_internal_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    if (!registration_exists_locked(mr, EXCLUSION_RDMA)) {
        add_exclusion_range_locked(addr, length, EXCLUSION_RDMA, mr);
        remember_registration_locked(mr, addr, length, EXCLUSION_RDMA);
    }
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_internal_depth;
}

static void replace_rdma_registration(void* mr, void* addr, size_t length) {
    if (!mr || !runtime_configured || !addr || length == 0) {
        return;
    }

    int saved_internal_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    RegistrationRecord* record = take_registration_locked(mr, EXCLUSION_RDMA);
    remove_exclusion_token_locked(mr, EXCLUSION_RDMA);
    meta_free(record);
    add_exclusion_range_locked(addr, length, EXCLUSION_RDMA, mr);
    remember_registration_locked(mr, addr, length, EXCLUSION_RDMA);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_internal_depth;
}

static void release_rdma_registration(void* mr) {
    if (!runtime_configured || !mr) {
        return;
    }

    int saved_internal_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);
    RegistrationRecord* record = take_registration_locked(mr, EXCLUSION_RDMA);
    remove_exclusion_token_locked(mr, EXCLUSION_RDMA);
    meta_free(record);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_internal_depth;
}

static void* custom_ibv_reg_mr(void* pd, void* addr, size_t length, int access) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_IBV_REG_MR);
    int saved_hook_depth = in_mai_hook;
    void* mr;

    in_mai_hook++;
    if (replacement) {
        mr = ((void* (*)(void*, void*, size_t, int))replacement->original)(pd, addr,
                                                                           length, access);
    } else {
        if (!original_ibv_reg_mr) {
            resolve_original_safety_functions();
        }
        mr = original_ibv_reg_mr ? original_ibv_reg_mr(pd, addr, length, access) : NULL;
    }
    in_mai_hook = saved_hook_depth;

    remember_rdma_registration(mr, addr, length);
    return mr;
}

static void* custom_ibv_reg_mr_iova(void* pd, void* addr, size_t length, uint64_t iova,
                                    int access) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_IBV_REG_MR_IOVA);
    int saved_hook_depth = in_mai_hook;
    void* mr;

    in_mai_hook++;
    if (replacement) {
        mr = ((void* (*)(void*, void*, size_t, uint64_t, int))replacement->original)(pd,
                                                                                    addr,
                                                                                    length,
                                                                                    iova,
                                                                                    access);
    } else {
        if (!original_ibv_reg_mr_iova) {
            resolve_original_safety_functions();
        }
        mr = original_ibv_reg_mr_iova ?
            original_ibv_reg_mr_iova(pd, addr, length, iova, access) : NULL;
    }
    in_mai_hook = saved_hook_depth;

    remember_rdma_registration(mr, addr, length);
    return mr;
}

static int custom_ibv_rereg_mr(void* mr, int flags, void* pd, void* addr, size_t length,
                               int access) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_IBV_REREG_MR);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*, int, void*, void*, size_t, int))replacement->original)(
            mr, flags, pd, addr, length, access);
    } else {
        if (!original_ibv_rereg_mr) {
            resolve_original_safety_functions();
        }
        rc = original_ibv_rereg_mr ?
            original_ibv_rereg_mr(mr, flags, pd, addr, length, access) :
            missing_status_symbol();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        replace_rdma_registration(mr, addr, length);
    }
    return rc;
}

static int custom_ibv_dereg_mr(void* mr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_IBV_DEREG_MR);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(mr);
    } else {
        if (!original_ibv_dereg_mr) {
            resolve_original_safety_functions();
        }
        rc = original_ibv_dereg_mr ? original_ibv_dereg_mr(mr) : missing_status_symbol();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_rdma_registration(mr);
    }
    return rc;
}

static void* custom_rdma_reg_msgs(void* id, void* addr, size_t length) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_RDMA_REG_MSGS);
    int saved_hook_depth = in_mai_hook;
    void* mr;

    in_mai_hook++;
    if (replacement) {
        mr = ((void* (*)(void*, void*, size_t))replacement->original)(id, addr, length);
    } else {
        if (!original_rdma_reg_msgs) {
            resolve_original_safety_functions();
        }
        mr = original_rdma_reg_msgs ? original_rdma_reg_msgs(id, addr, length) : NULL;
    }
    in_mai_hook = saved_hook_depth;

    remember_rdma_registration(mr, addr, length);
    return mr;
}

static void* custom_rdma_reg_read(void* id, void* addr, size_t length) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_RDMA_REG_READ);
    int saved_hook_depth = in_mai_hook;
    void* mr;

    in_mai_hook++;
    if (replacement) {
        mr = ((void* (*)(void*, void*, size_t))replacement->original)(id, addr, length);
    } else {
        if (!original_rdma_reg_read) {
            resolve_original_safety_functions();
        }
        mr = original_rdma_reg_read ? original_rdma_reg_read(id, addr, length) : NULL;
    }
    in_mai_hook = saved_hook_depth;

    remember_rdma_registration(mr, addr, length);
    return mr;
}

static void* custom_rdma_reg_write(void* id, void* addr, size_t length) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_RDMA_REG_WRITE);
    int saved_hook_depth = in_mai_hook;
    void* mr;

    in_mai_hook++;
    if (replacement) {
        mr = ((void* (*)(void*, void*, size_t))replacement->original)(id, addr, length);
    } else {
        if (!original_rdma_reg_write) {
            resolve_original_safety_functions();
        }
        mr = original_rdma_reg_write ? original_rdma_reg_write(id, addr, length) : NULL;
    }
    in_mai_hook = saved_hook_depth;

    remember_rdma_registration(mr, addr, length);
    return mr;
}

static int custom_rdma_dereg_mr(void* mr) {
    DynamicReplacement* replacement = current_dynamic_replacement(HOOK_RDMA_DEREG_MR);
    int saved_hook_depth = in_mai_hook;
    int rc;

    in_mai_hook++;
    if (replacement) {
        rc = ((int (*)(void*))replacement->original)(mr);
    } else {
        if (!original_rdma_dereg_mr) {
            resolve_original_safety_functions();
        }
        rc = original_rdma_dereg_mr ?
            original_rdma_dereg_mr(mr) : missing_status_symbol();
    }
    in_mai_hook = saved_hook_depth;

    if (rc == 0) {
        release_rdma_registration(mr);
    }
    return rc;
}

static void* frida_malloc(size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_malloc(size);
}

static void frida_free(void* ptr) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    custom_free(ptr);
}

static void* frida_calloc(size_t nmemb, size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_calloc(nmemb, size);
}

static void* frida_realloc(void* ptr, size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_realloc(ptr, size);
}

static void* frida_aligned_alloc(size_t alignment, size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_aligned_alloc(alignment, size);
}

static int frida_posix_memalign(void** memptr, size_t alignment, size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_posix_memalign(memptr, alignment, size);
}

static void* frida_memalign(size_t alignment, size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_memalign(alignment, size);
}

static void* frida_valloc(size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_valloc(size);
}

static void* frida_pvalloc(size_t size) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_pvalloc(size);
}

static size_t frida_malloc_usable_size(void* ptr) {
    NOTE_FRIDA_ALLOCATOR_PATH();
    return custom_malloc_usable_size(ptr);
}

static int frida_cudaHostAlloc(void** ptr, size_t size, unsigned int flags) {
    return custom_cudaHostAlloc(ptr, size, flags);
}

static int frida_cudaMallocHost(void** ptr, size_t size) {
    return custom_cudaMallocHost(ptr, size);
}

static int frida_cudaHostRegister(void* ptr, size_t size, unsigned int flags) {
    return custom_cudaHostRegister(ptr, size, flags);
}

static int frida_cudaHostUnregister(void* ptr) {
    return custom_cudaHostUnregister(ptr);
}

static int frida_cudaFreeHost(void* ptr) {
    return custom_cudaFreeHost(ptr);
}

static int frida_cudaMallocManaged(void** ptr, size_t size, unsigned int flags) {
    return custom_cudaMallocManaged(ptr, size, flags);
}

static int frida_cudaFree(void* ptr) {
    return custom_cudaFree(ptr);
}

static int frida_hipHostMalloc(void** ptr, size_t size, unsigned int flags) {
    return custom_hipHostMalloc(ptr, size, flags);
}

static int frida_hipHostRegister(void* ptr, size_t size, unsigned int flags) {
    return custom_hipHostRegister(ptr, size, flags);
}

static int frida_hipHostUnregister(void* ptr) {
    return custom_hipHostUnregister(ptr);
}

static int frida_hipHostFree(void* ptr) {
    return custom_hipHostFree(ptr);
}

static int frida_hipMallocManaged(void** ptr, size_t size, unsigned int flags) {
    return custom_hipMallocManaged(ptr, size, flags);
}

static int frida_hipFree(void* ptr) {
    return custom_hipFree(ptr);
}

static int frida_MPI_Alloc_mem(intptr_t size, void* info, void* baseptr) {
    return custom_MPI_Alloc_mem(size, info, baseptr);
}

static int frida_MPI_Free_mem(void* base) {
    return custom_MPI_Free_mem(base);
}

static void* frida_ibv_reg_mr(void* pd, void* addr, size_t length, int access) {
    return custom_ibv_reg_mr(pd, addr, length, access);
}

static void* frida_ibv_reg_mr_iova(void* pd, void* addr, size_t length, uint64_t iova,
                                   int access) {
    return custom_ibv_reg_mr_iova(pd, addr, length, iova, access);
}

static int frida_ibv_rereg_mr(void* mr, int flags, void* pd, void* addr, size_t length,
                              int access) {
    return custom_ibv_rereg_mr(mr, flags, pd, addr, length, access);
}

static int frida_ibv_dereg_mr(void* mr) {
    return custom_ibv_dereg_mr(mr);
}

static void* frida_rdma_reg_msgs(void* id, void* addr, size_t length) {
    return custom_rdma_reg_msgs(id, addr, length);
}

static void* frida_rdma_reg_read(void* id, void* addr, size_t length) {
    return custom_rdma_reg_read(id, addr, length);
}

static void* frida_rdma_reg_write(void* id, void* addr, size_t length) {
    return custom_rdma_reg_write(id, addr, length);
}

static int frida_rdma_dereg_mr(void* mr) {
    return custom_rdma_dereg_mr(mr);
}

typedef struct {
    HookKind kind;
    const char* symbol;
    gpointer replacement;
} DynamicHookSpec;

static const DynamicHookSpec dynamic_hook_specs[] = {
    { HOOK_MALLOC, "malloc", (gpointer)frida_malloc },
    { HOOK_FREE, "free", (gpointer)frida_free },
    { HOOK_CALLOC, "calloc", (gpointer)frida_calloc },
    { HOOK_REALLOC, "realloc", (gpointer)frida_realloc },
    { HOOK_ALIGNED_ALLOC, "aligned_alloc", (gpointer)frida_aligned_alloc },
    { HOOK_POSIX_MEMALIGN, "posix_memalign", (gpointer)frida_posix_memalign },
    { HOOK_MEMALIGN, "memalign", (gpointer)frida_memalign },
    { HOOK_VALLOC, "valloc", (gpointer)frida_valloc },
    { HOOK_PVALLOC, "pvalloc", (gpointer)frida_pvalloc },
    { HOOK_MALLOC_USABLE_SIZE, "malloc_usable_size", (gpointer)frida_malloc_usable_size },
    { HOOK_CUDA_HOST_ALLOC, "cudaHostAlloc", (gpointer)frida_cudaHostAlloc },
    { HOOK_CUDA_MALLOC_HOST, "cudaMallocHost", (gpointer)frida_cudaMallocHost },
    { HOOK_CUDA_HOST_REGISTER, "cudaHostRegister", (gpointer)frida_cudaHostRegister },
    { HOOK_CUDA_HOST_UNREGISTER, "cudaHostUnregister", (gpointer)frida_cudaHostUnregister },
    { HOOK_CUDA_FREE_HOST, "cudaFreeHost", (gpointer)frida_cudaFreeHost },
    { HOOK_CUDA_MALLOC_MANAGED, "cudaMallocManaged", (gpointer)frida_cudaMallocManaged },
    { HOOK_CUDA_FREE, "cudaFree", (gpointer)frida_cudaFree },
    { HOOK_HIP_HOST_MALLOC, "hipHostMalloc", (gpointer)frida_hipHostMalloc },
    { HOOK_HIP_HOST_REGISTER, "hipHostRegister", (gpointer)frida_hipHostRegister },
    { HOOK_HIP_HOST_UNREGISTER, "hipHostUnregister", (gpointer)frida_hipHostUnregister },
    { HOOK_HIP_HOST_FREE, "hipHostFree", (gpointer)frida_hipHostFree },
    { HOOK_HIP_MALLOC_MANAGED, "hipMallocManaged", (gpointer)frida_hipMallocManaged },
    { HOOK_HIP_FREE, "hipFree", (gpointer)frida_hipFree },
    { HOOK_MPI_ALLOC_MEM, "MPI_Alloc_mem", (gpointer)frida_MPI_Alloc_mem },
    { HOOK_MPI_FREE_MEM, "MPI_Free_mem", (gpointer)frida_MPI_Free_mem },
    { HOOK_IBV_REG_MR, "ibv_reg_mr", (gpointer)frida_ibv_reg_mr },
    { HOOK_IBV_REG_MR_IOVA, "ibv_reg_mr_iova", (gpointer)frida_ibv_reg_mr_iova },
    { HOOK_IBV_REREG_MR, "ibv_rereg_mr", (gpointer)frida_ibv_rereg_mr },
    { HOOK_IBV_DEREG_MR, "ibv_dereg_mr", (gpointer)frida_ibv_dereg_mr },
    { HOOK_RDMA_REG_MSGS, "rdma_reg_msgs", (gpointer)frida_rdma_reg_msgs },
    { HOOK_RDMA_REG_READ, "rdma_reg_read", (gpointer)frida_rdma_reg_read },
    { HOOK_RDMA_REG_WRITE, "rdma_reg_write", (gpointer)frida_rdma_reg_write },
    { HOOK_RDMA_DEREG_MR, "rdma_dereg_mr", (gpointer)frida_rdma_dereg_mr },
};

static int hook_address_is_known(gpointer address) {
    if (!address) {
        return 1;
    }

    if (address == malloc_addr ||
        address == (gpointer)malloc ||
        address == free_addr ||
        address == (gpointer)free ||
        address == calloc_addr ||
        address == (gpointer)calloc ||
        address == realloc_addr ||
        address == (gpointer)realloc ||
        address == aligned_alloc_addr ||
        address == (gpointer)aligned_alloc ||
        address == posix_memalign_addr ||
        address == (gpointer)posix_memalign ||
        address == memalign_addr ||
        address == (gpointer)memalign ||
        address == valloc_addr ||
        address == (gpointer)valloc ||
        address == pvalloc_addr ||
        address == (gpointer)pvalloc ||
        address == malloc_usable_size_addr ||
        address == (gpointer)malloc_usable_size ||
        address == dlopen_addr ||
        address == dlmopen_addr ||
        address == dlclose_addr ||
        address == mmap_addr ||
        address == munmap_addr ||
        address == mremap_addr ||
        address == brk_addr ||
        address == sbrk_addr ||
        address == mlock_addr ||
        address == (gpointer)mlock ||
        address == mlock2_addr ||
        address == (gpointer)mlock2 ||
        address == mlockall_addr ||
        address == (gpointer)mlockall ||
        address == munlock_addr ||
        address == (gpointer)munlock ||
        address == munlockall_addr ||
        address == (gpointer)munlockall ||
        address == cuda_host_alloc_addr ||
        address == (gpointer)cudaHostAlloc ||
        address == cuda_malloc_host_addr ||
        address == (gpointer)cudaMallocHost ||
        address == cuda_host_register_addr ||
        address == (gpointer)cudaHostRegister ||
        address == cuda_host_unregister_addr ||
        address == (gpointer)cudaHostUnregister ||
        address == cuda_free_host_addr ||
        address == (gpointer)cudaFreeHost ||
        address == cuda_malloc_managed_addr ||
        address == (gpointer)cudaMallocManaged ||
        address == cuda_free_addr ||
        address == (gpointer)cudaFree ||
        address == hip_host_malloc_addr ||
        address == (gpointer)hipHostMalloc ||
        address == hip_host_register_addr ||
        address == (gpointer)hipHostRegister ||
        address == hip_host_unregister_addr ||
        address == (gpointer)hipHostUnregister ||
        address == hip_host_free_addr ||
        address == (gpointer)hipHostFree ||
        address == hip_malloc_managed_addr ||
        address == (gpointer)hipMallocManaged ||
        address == hip_free_addr ||
        address == (gpointer)hipFree ||
        address == mpi_alloc_mem_addr ||
        address == (gpointer)MPI_Alloc_mem ||
        address == mpi_free_mem_addr ||
        address == (gpointer)MPI_Free_mem ||
        address == ibv_reg_mr_addr ||
        address == (gpointer)ibv_reg_mr ||
        address == ibv_reg_mr_iova_addr ||
        address == (gpointer)ibv_reg_mr_iova ||
        address == ibv_rereg_mr_addr ||
        address == (gpointer)ibv_rereg_mr ||
        address == ibv_dereg_mr_addr ||
        address == (gpointer)ibv_dereg_mr ||
        address == rdma_reg_msgs_addr ||
        address == (gpointer)rdma_reg_msgs ||
        address == rdma_reg_read_addr ||
        address == (gpointer)rdma_reg_read ||
        address == rdma_reg_write_addr ||
        address == (gpointer)rdma_reg_write ||
        address == rdma_dereg_mr_addr ||
        address == (gpointer)rdma_dereg_mr) {
        return 1;
    }

    for (DynamicReplacement* replacement = dynamic_replacements;
         replacement;
         replacement = replacement->next) {
        if (replacement->address == address) {
            return 1;
        }
    }

    return 0;
}

static int should_patch_libc_allocator_symbols(void) {
    const char* mode = getenv("MAI_ALLOCATOR_HOOKS");

    if (mode && strcmp(mode, "frida") == 0) {
        direct_allocator_interposition = 0;
        return 1;
    }
    if (mode && strcmp(mode, "preload") == 0) {
        direct_allocator_interposition = 1;
        return 0;
    }

    void* default_malloc = dlsym(RTLD_DEFAULT, "malloc");
    direct_allocator_interposition = default_malloc == (void*)malloc;
    return !direct_allocator_interposition;
}

static int is_safety_hook_kind(HookKind kind) {
    return kind >= HOOK_MLOCK;
}

static DynamicHandleRecord* find_dynamic_handle(void* handle) {
    for (DynamicHandleRecord* record = dynamic_handles; record; record = record->next) {
        if (record->handle == handle) {
            return record;
        }
    }

    return NULL;
}

static int note_dynamic_handle(void* handle) {
    DynamicHandleRecord* record = find_dynamic_handle(handle);
    if (record) {
        record->refs++;
        return 0;
    }

    record = meta_alloc(sizeof(*record));
    if (!record) {
        return -1;
    }

    record->handle = handle;
    record->refs = 1;
    record->next = dynamic_handles;
    dynamic_handles = record;
    return 0;
}

static int dynamic_handle_will_unload(void* handle) {
    DynamicHandleRecord* previous = NULL;
    DynamicHandleRecord* record = dynamic_handles;

    while (record) {
        if (record->handle != handle) {
            previous = record;
            record = record->next;
            continue;
        }

        if (record->refs > 1) {
            record->refs--;
            return 0;
        }

        if (previous) {
            previous->next = record->next;
        } else {
            dynamic_handles = record->next;
        }
        meta_free(record);
        return 1;
    }

    return 0;
}

static void revert_dynamic_replacements_for_handle(void* handle) {
    DynamicReplacement* previous = NULL;
    DynamicReplacement* replacement = dynamic_replacements;

    while (replacement) {
        DynamicReplacement* next = replacement->next;
        if (replacement->handle != handle) {
            previous = replacement;
            replacement = next;
            continue;
        }

        gum_interceptor_revert(malloc_interceptor, replacement->address);
        if (previous) {
            previous->next = next;
        } else {
            dynamic_replacements = next;
        }
        meta_free(replacement);
        replacement = next;
    }

    if (!dynamic_replacements) {
        atomic_store_explicit(&dynamic_replacements_active, 0, memory_order_relaxed);
    }
}

static int replace_dynamic_symbol(void* handle, gpointer address, const DynamicHookSpec* spec) {
    if (hook_address_is_known(address)) {
        return 0;
    }

    DynamicReplacement* replacement = meta_alloc(sizeof(*replacement));
    if (!replacement) {
        return -1;
    }

    replacement->kind = spec->kind;
    replacement->symbol = spec->symbol;
    replacement->handle = handle;
    replacement->address = address;
    replacement->original = NULL;
    replacement->next = NULL;

    GumReplaceReturn ret = gum_interceptor_replace(malloc_interceptor,
                                                   address,
                                                   spec->replacement,
                                                   replacement,
                                                   (gpointer*)&replacement->original);
    if (ret == GUM_REPLACE_ALREADY_REPLACED) {
        meta_free(replacement);
        return 0;
    }
    if (ret != GUM_REPLACE_OK) {
        if (verbose_logging) {
            fprintf(stderr, "MAI: failed to replace dlopened %s at %p: %d\n",
                    spec->symbol, address, ret);
        }
        meta_free(replacement);
        return -1;
    }

    replacement->next = dynamic_replacements;
    dynamic_replacements = replacement;
    atomic_store_explicit(&dynamic_replacements_active, 1, memory_order_relaxed);

    if (is_safety_hook_kind(spec->kind)) {
        pthread_mutex_lock(&runtime_lock);
        stats_snapshot.safety_hook_patches++;
        pthread_mutex_unlock(&runtime_lock);
    }

    if (verbose_logging) {
        fprintf(stderr, "MAI: hooked dlopened %s at %p\n", spec->symbol, address);
    }

    return 0;
}

static void refresh_hooks_for_handle(void* handle) {
    if (!handle || !malloc_interceptor || cleanup_in_progress) {
        return;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;

    gum_interceptor_ignore_current_thread(malloc_interceptor);
    gum_interceptor_begin_transaction(malloc_interceptor);

    if (note_dynamic_handle(handle) != 0) {
        gum_interceptor_end_transaction(malloc_interceptor);
        gum_interceptor_unignore_current_thread(malloc_interceptor);
        in_mai_hook = saved_hook_depth;
        return;
    }

    for (size_t i = 0; i < sizeof(dynamic_hook_specs) / sizeof(dynamic_hook_specs[0]); i++) {
        void* symbol_address = dlsym(handle, dynamic_hook_specs[i].symbol);
        if (symbol_address) {
            replace_dynamic_symbol(handle, (gpointer)symbol_address, &dynamic_hook_specs[i]);
        }
    }

    gum_interceptor_end_transaction(malloc_interceptor);
    gum_interceptor_unignore_current_thread(malloc_interceptor);

    in_mai_hook = saved_hook_depth;
}

static void* custom_dlopen(const char* filename, int flags) {
    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    void* handle = original_dlopen(filename, flags);
    in_mai_hook = saved_hook_depth;

    if (handle) {
        refresh_hooks_for_handle(handle);
    }

    return handle;
}

static void* custom_dlmopen(Lmid_t nsid, const char* filename, int flags) {
    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    void* handle = original_dlmopen(nsid, filename, flags);
    in_mai_hook = saved_hook_depth;

    if (handle) {
        refresh_hooks_for_handle(handle);
    }

    return handle;
}

static int custom_dlclose(void* handle) {
    int saved_hook_depth = in_mai_hook;

    if (handle && malloc_interceptor && !cleanup_in_progress) {
        in_mai_hook++;
        gum_interceptor_ignore_current_thread(malloc_interceptor);
        gum_interceptor_begin_transaction(malloc_interceptor);
        if (dynamic_handle_will_unload(handle)) {
            revert_dynamic_replacements_for_handle(handle);
        }
        gum_interceptor_end_transaction(malloc_interceptor);
        gum_interceptor_unignore_current_thread(malloc_interceptor);
        in_mai_hook = saved_hook_depth;
    }

    in_mai_hook++;
    int rc = original_dlclose(handle);
    in_mai_hook = saved_hook_depth;
    return rc;
}

static int replace_fast(gpointer address, gpointer replacement, gpointer* original,
                        int* replaced, const char* name) {
    GumReplaceReturn ret;

    if (!address) {
        return 0;
    }

    ret = gum_interceptor_replace_fast(malloc_interceptor, address, replacement, original);
    if (ret == GUM_REPLACE_OK) {
        *replaced = 1;
        return 0;
    }

    GumReplaceReturn regular_ret =
        gum_interceptor_replace(malloc_interceptor, address, replacement, NULL, original);
    if (regular_ret == GUM_REPLACE_OK) {
        *replaced = 1;
        return 0;
    }

    fprintf(stderr, "MAI: failed to replace %s: fast=%d regular=%d\n",
            name, ret, regular_ret);
    return -1;
}

static int replace_regular(gpointer address, gpointer replacement, gpointer* original,
                           int* replaced, const char* name) {
    GumReplaceReturn ret;

    if (!address) {
        return 0;
    }

    ret = gum_interceptor_replace(malloc_interceptor, address, replacement, NULL, original);
    if (ret != GUM_REPLACE_OK) {
        fprintf(stderr, "MAI: failed to replace %s: %d\n", name, ret);
        return -1;
    }

    *replaced = 1;
    return 0;
}

static void revert_replacements(void) {
    if (!malloc_interceptor) {
        return;
    }

    gum_interceptor_begin_transaction(malloc_interceptor);

    for (DynamicReplacement* replacement = dynamic_replacements;
         replacement;
         replacement = replacement->next) {
        gum_interceptor_revert(malloc_interceptor, replacement->address);
    }

    if (malloc_replaced) gum_interceptor_revert(malloc_interceptor, malloc_addr);
    if (free_replaced) gum_interceptor_revert(malloc_interceptor, free_addr);
    if (calloc_replaced) gum_interceptor_revert(malloc_interceptor, calloc_addr);
    if (realloc_replaced) gum_interceptor_revert(malloc_interceptor, realloc_addr);
    if (aligned_alloc_replaced) gum_interceptor_revert(malloc_interceptor, aligned_alloc_addr);
    if (posix_memalign_replaced) gum_interceptor_revert(malloc_interceptor, posix_memalign_addr);
    if (memalign_replaced) gum_interceptor_revert(malloc_interceptor, memalign_addr);
    if (valloc_replaced) gum_interceptor_revert(malloc_interceptor, valloc_addr);
    if (pvalloc_replaced) gum_interceptor_revert(malloc_interceptor, pvalloc_addr);
    if (malloc_usable_size_replaced) gum_interceptor_revert(malloc_interceptor, malloc_usable_size_addr);
    if (dlopen_replaced) gum_interceptor_revert(malloc_interceptor, dlopen_addr);
    if (dlmopen_replaced) gum_interceptor_revert(malloc_interceptor, dlmopen_addr);
    if (dlclose_replaced) gum_interceptor_revert(malloc_interceptor, dlclose_addr);
    if (mmap_replaced) gum_interceptor_revert(malloc_interceptor, mmap_addr);
    if (munmap_replaced) gum_interceptor_revert(malloc_interceptor, munmap_addr);
    if (mremap_replaced) gum_interceptor_revert(malloc_interceptor, mremap_addr);
    if (brk_replaced) gum_interceptor_revert(malloc_interceptor, brk_addr);
    if (sbrk_replaced) gum_interceptor_revert(malloc_interceptor, sbrk_addr);
    if (mlock_replaced) gum_interceptor_revert(malloc_interceptor, mlock_addr);
    if (mlock2_replaced) gum_interceptor_revert(malloc_interceptor, mlock2_addr);
    if (mlockall_replaced) gum_interceptor_revert(malloc_interceptor, mlockall_addr);
    if (munlock_replaced) gum_interceptor_revert(malloc_interceptor, munlock_addr);
    if (munlockall_replaced) gum_interceptor_revert(malloc_interceptor, munlockall_addr);
    if (cuda_host_alloc_replaced) gum_interceptor_revert(malloc_interceptor, cuda_host_alloc_addr);
    if (cuda_malloc_host_replaced) gum_interceptor_revert(malloc_interceptor, cuda_malloc_host_addr);
    if (cuda_host_register_replaced) gum_interceptor_revert(malloc_interceptor, cuda_host_register_addr);
    if (cuda_host_unregister_replaced) gum_interceptor_revert(malloc_interceptor, cuda_host_unregister_addr);
    if (cuda_free_host_replaced) gum_interceptor_revert(malloc_interceptor, cuda_free_host_addr);
    if (cuda_malloc_managed_replaced) gum_interceptor_revert(malloc_interceptor, cuda_malloc_managed_addr);
    if (cuda_free_replaced) gum_interceptor_revert(malloc_interceptor, cuda_free_addr);
    if (hip_host_malloc_replaced) gum_interceptor_revert(malloc_interceptor, hip_host_malloc_addr);
    if (hip_host_register_replaced) gum_interceptor_revert(malloc_interceptor, hip_host_register_addr);
    if (hip_host_unregister_replaced) gum_interceptor_revert(malloc_interceptor, hip_host_unregister_addr);
    if (hip_host_free_replaced) gum_interceptor_revert(malloc_interceptor, hip_host_free_addr);
    if (hip_malloc_managed_replaced) gum_interceptor_revert(malloc_interceptor, hip_malloc_managed_addr);
    if (hip_free_replaced) gum_interceptor_revert(malloc_interceptor, hip_free_addr);
    if (mpi_alloc_mem_replaced) gum_interceptor_revert(malloc_interceptor, mpi_alloc_mem_addr);
    if (mpi_free_mem_replaced) gum_interceptor_revert(malloc_interceptor, mpi_free_mem_addr);
    if (ibv_reg_mr_replaced) gum_interceptor_revert(malloc_interceptor, ibv_reg_mr_addr);
    if (ibv_reg_mr_iova_replaced) gum_interceptor_revert(malloc_interceptor, ibv_reg_mr_iova_addr);
    if (ibv_rereg_mr_replaced) gum_interceptor_revert(malloc_interceptor, ibv_rereg_mr_addr);
    if (ibv_dereg_mr_replaced) gum_interceptor_revert(malloc_interceptor, ibv_dereg_mr_addr);
    if (rdma_reg_msgs_replaced) gum_interceptor_revert(malloc_interceptor, rdma_reg_msgs_addr);
    if (rdma_reg_read_replaced) gum_interceptor_revert(malloc_interceptor, rdma_reg_read_addr);
    if (rdma_reg_write_replaced) gum_interceptor_revert(malloc_interceptor, rdma_reg_write_addr);
    if (rdma_dereg_mr_replaced) gum_interceptor_revert(malloc_interceptor, rdma_dereg_mr_addr);

    gum_interceptor_end_transaction(malloc_interceptor);

    while (dynamic_replacements) {
        DynamicReplacement* next = dynamic_replacements->next;
        meta_free(dynamic_replacements);
        dynamic_replacements = next;
    }
    atomic_store_explicit(&dynamic_replacements_active, 0, memory_order_relaxed);
    while (dynamic_handles) {
        DynamicHandleRecord* next = dynamic_handles->next;
        meta_free(dynamic_handles);
        dynamic_handles = next;
    }

    malloc_replaced = 0;
    free_replaced = 0;
    calloc_replaced = 0;
    realloc_replaced = 0;
    aligned_alloc_replaced = 0;
    posix_memalign_replaced = 0;
    memalign_replaced = 0;
    valloc_replaced = 0;
    pvalloc_replaced = 0;
    malloc_usable_size_replaced = 0;
    dlopen_replaced = 0;
    dlmopen_replaced = 0;
    dlclose_replaced = 0;
    mmap_replaced = 0;
    munmap_replaced = 0;
    mremap_replaced = 0;
    brk_replaced = 0;
    sbrk_replaced = 0;
    mlock_replaced = 0;
    mlock2_replaced = 0;
    mlockall_replaced = 0;
    munlock_replaced = 0;
    munlockall_replaced = 0;
    cuda_host_alloc_replaced = 0;
    cuda_malloc_host_replaced = 0;
    cuda_host_register_replaced = 0;
    cuda_host_unregister_replaced = 0;
    cuda_free_host_replaced = 0;
    cuda_malloc_managed_replaced = 0;
    cuda_free_replaced = 0;
    hip_host_malloc_replaced = 0;
    hip_host_register_replaced = 0;
    hip_host_unregister_replaced = 0;
    hip_host_free_replaced = 0;
    hip_malloc_managed_replaced = 0;
    hip_free_replaced = 0;
    mpi_alloc_mem_replaced = 0;
    mpi_free_mem_replaced = 0;
    ibv_reg_mr_replaced = 0;
    ibv_reg_mr_iova_replaced = 0;
    ibv_rereg_mr_replaced = 0;
    ibv_dereg_mr_replaced = 0;
    rdma_reg_msgs_replaced = 0;
    rdma_reg_read_replaced = 0;
    rdma_reg_write_replaced = 0;
    rdma_dereg_mr_replaced = 0;
}

int malloc_interceptor_attach(void) {
    int failed = 0;

    pthread_mutex_lock(&lifecycle_lock);

    if (hooks_attached) {
        pthread_mutex_unlock(&lifecycle_lock);
        return 0;
    }

    if (configure_runtime() != 0) {
        if (verbose_logging || stats_logging) {
            fprintf(stderr, "MAI: disabled because configuration is invalid or no scratch path was found\n");
            print_stats();
        }
        runtime_enabled = 0;
        pthread_mutex_unlock(&lifecycle_lock);
        return -1;
    }

    if (!runtime_enabled) {
        pthread_mutex_unlock(&lifecycle_lock);
        return 0;
    }

    gum_init_embedded();
    gum_initialized = 1;

    malloc_interceptor = gum_interceptor_obtain();
    if (!malloc_interceptor) {
        gum_deinit_embedded();
        gum_initialized = 0;
        pthread_mutex_unlock(&lifecycle_lock);
        return -1;
    }

    resolve_original_allocators();
    resolve_original_safety_functions();
    int patch_libc_allocators = should_patch_libc_allocator_symbols();

    malloc_addr = (void*)original_malloc;
    free_addr = (void*)original_free;
    calloc_addr = (void*)original_calloc;
    realloc_addr = (void*)original_realloc;
    aligned_alloc_addr = (void*)original_aligned_alloc;
    posix_memalign_addr = (void*)original_posix_memalign;
    memalign_addr = (void*)original_memalign;
    valloc_addr = (void*)original_valloc;
    pvalloc_addr = (void*)original_pvalloc;
    malloc_usable_size_addr = (void*)original_malloc_usable_size;
    dlopen_addr = (void*)dlopen;
    dlmopen_addr = (void*)dlmopen;
    dlclose_addr = (void*)dlclose;
    mmap_addr = (void*)mmap;
    munmap_addr = (void*)munmap;
    mremap_addr = (void*)mremap;
    brk_addr = (void*)brk;
    sbrk_addr = (void*)sbrk;
    mlock_addr = (void*)original_mlock;
    mlock2_addr = (void*)original_mlock2;
    mlockall_addr = (void*)original_mlockall;
    munlock_addr = (void*)original_munlock;
    munlockall_addr = (void*)original_munlockall;
    cuda_host_alloc_addr = (void*)original_cudaHostAlloc;
    cuda_malloc_host_addr = (void*)original_cudaMallocHost;
    cuda_host_register_addr = (void*)original_cudaHostRegister;
    cuda_host_unregister_addr = (void*)original_cudaHostUnregister;
    cuda_free_host_addr = (void*)original_cudaFreeHost;
    cuda_malloc_managed_addr = (void*)original_cudaMallocManaged;
    cuda_free_addr = (void*)original_cudaFree;
    hip_host_malloc_addr = (void*)original_hipHostMalloc;
    hip_host_register_addr = (void*)original_hipHostRegister;
    hip_host_unregister_addr = (void*)original_hipHostUnregister;
    hip_host_free_addr = (void*)original_hipHostFree;
    hip_malloc_managed_addr = (void*)original_hipMallocManaged;
    hip_free_addr = (void*)original_hipFree;
    mpi_alloc_mem_addr = (void*)original_MPI_Alloc_mem;
    mpi_free_mem_addr = (void*)original_MPI_Free_mem;
    ibv_reg_mr_addr = (void*)original_ibv_reg_mr;
    ibv_reg_mr_iova_addr = (void*)original_ibv_reg_mr_iova;
    ibv_rereg_mr_addr = (void*)original_ibv_rereg_mr;
    ibv_dereg_mr_addr = (void*)original_ibv_dereg_mr;
    rdma_reg_msgs_addr = (void*)original_rdma_reg_msgs;
    rdma_reg_read_addr = (void*)original_rdma_reg_read;
    rdma_reg_write_addr = (void*)original_rdma_reg_write;
    rdma_dereg_mr_addr = (void*)original_rdma_dereg_mr;

    gum_interceptor_begin_transaction(malloc_interceptor);

    if (patch_libc_allocators) {
        failed |= replace_fast(malloc_addr, (gpointer)frida_malloc,
                               (gpointer*)&original_malloc, &malloc_replaced, "malloc");
        failed |= replace_fast(free_addr, (gpointer)frida_free,
                               (gpointer*)&original_free, &free_replaced, "free");
        failed |= replace_fast(calloc_addr, (gpointer)frida_calloc,
                               (gpointer*)&original_calloc, &calloc_replaced, "calloc");
        failed |= replace_fast(realloc_addr, (gpointer)frida_realloc,
                               (gpointer*)&original_realloc, &realloc_replaced, "realloc");
        failed |= replace_fast(aligned_alloc_addr, (gpointer)frida_aligned_alloc,
                               (gpointer*)&original_aligned_alloc,
                               &aligned_alloc_replaced, "aligned_alloc");
        failed |= replace_regular(posix_memalign_addr, (gpointer)frida_posix_memalign,
                                  (gpointer*)&original_posix_memalign,
                                  &posix_memalign_replaced, "posix_memalign");
        failed |= replace_fast(memalign_addr, (gpointer)frida_memalign,
                               (gpointer*)&original_memalign, &memalign_replaced, "memalign");
        failed |= replace_fast(valloc_addr, (gpointer)frida_valloc,
                               (gpointer*)&original_valloc, &valloc_replaced, "valloc");
        failed |= replace_fast(pvalloc_addr, (gpointer)frida_pvalloc,
                               (gpointer*)&original_pvalloc, &pvalloc_replaced, "pvalloc");
        failed |= replace_fast(malloc_usable_size_addr, (gpointer)frida_malloc_usable_size,
                               (gpointer*)&original_malloc_usable_size,
                               &malloc_usable_size_replaced, "malloc_usable_size");
    }
    failed |= replace_fast(dlopen_addr, (gpointer)custom_dlopen,
                           (gpointer*)&original_dlopen, &dlopen_replaced, "dlopen");
    failed |= replace_fast(dlmopen_addr, (gpointer)custom_dlmopen,
                           (gpointer*)&original_dlmopen, &dlmopen_replaced, "dlmopen");
    failed |= replace_fast(dlclose_addr, (gpointer)custom_dlclose,
                           (gpointer*)&original_dlclose, &dlclose_replaced, "dlclose");
    failed |= replace_fast(mmap_addr, (gpointer)custom_mmap,
                           (gpointer*)&original_mmap, &mmap_replaced, "mmap");
    failed |= replace_fast(munmap_addr, (gpointer)custom_munmap,
                           (gpointer*)&original_munmap, &munmap_replaced, "munmap");
    failed |= replace_fast(mremap_addr, (gpointer)custom_mremap,
                           (gpointer*)&original_mremap, &mremap_replaced, "mremap");
    failed |= replace_fast(brk_addr, (gpointer)custom_brk,
                           (gpointer*)&original_brk, &brk_replaced, "brk");
    failed |= replace_fast(sbrk_addr, (gpointer)custom_sbrk,
                           (gpointer*)&original_sbrk, &sbrk_replaced, "sbrk");
    gum_interceptor_end_transaction(malloc_interceptor);

    if (failed) {
        cleanup_in_progress = 1;
        revert_replacements();
        g_object_unref(malloc_interceptor);
        malloc_interceptor = NULL;
        gum_deinit_embedded();
        gum_initialized = 0;
        runtime_enabled = 0;
        cleanup_in_progress = 0;
        pthread_mutex_unlock(&lifecycle_lock);
        return -1;
    }

    hooks_attached = 1;
    stats_snapshot.allocator_hook_mode = patch_libc_allocators ?
        MAI_ALLOCATOR_HOOK_MODE_FRIDA : MAI_ALLOCATOR_HOOK_MODE_PRELOAD;
    stats_snapshot.allocator_libc_patches =
        (size_t)malloc_replaced +
        (size_t)free_replaced +
        (size_t)calloc_replaced +
        (size_t)realloc_replaced +
        (size_t)aligned_alloc_replaced +
        (size_t)posix_memalign_replaced +
        (size_t)memalign_replaced +
        (size_t)valloc_replaced +
        (size_t)pvalloc_replaced +
        (size_t)malloc_usable_size_replaced;
    stats_snapshot.safety_hook_patches =
        (size_t)mlock_replaced +
        (size_t)mlock2_replaced +
        (size_t)mlockall_replaced +
        (size_t)munlock_replaced +
        (size_t)munlockall_replaced +
        (size_t)cuda_host_alloc_replaced +
        (size_t)cuda_malloc_host_replaced +
        (size_t)cuda_host_register_replaced +
        (size_t)cuda_host_unregister_replaced +
        (size_t)cuda_free_host_replaced +
        (size_t)cuda_malloc_managed_replaced +
        (size_t)cuda_free_replaced +
        (size_t)hip_host_malloc_replaced +
        (size_t)hip_host_register_replaced +
        (size_t)hip_host_unregister_replaced +
        (size_t)hip_host_free_replaced +
        (size_t)hip_malloc_managed_replaced +
        (size_t)hip_free_replaced +
        (size_t)mpi_alloc_mem_replaced +
        (size_t)mpi_free_mem_replaced +
        (size_t)ibv_reg_mr_replaced +
        (size_t)ibv_reg_mr_iova_replaced +
        (size_t)ibv_rereg_mr_replaced +
        (size_t)ibv_dereg_mr_replaced +
        (size_t)rdma_reg_msgs_replaced +
        (size_t)rdma_reg_read_replaced +
        (size_t)rdma_reg_write_replaced +
        (size_t)rdma_dereg_mr_replaced;
    if (verbose_logging) {
        fprintf(stderr,
                "MAI: enabled path=%s threshold=%zu arena_size=%zu reclaim=%d "
                "allocator_hooks=%s\n",
                mai_path, threshold_bytes, arena_size_bytes, reclaim_policy,
                patch_libc_allocators ? "frida" : "preload");
    }

    pthread_mutex_unlock(&lifecycle_lock);
    return 0;
}

void malloc_interceptor_detach(void) {
    pthread_mutex_lock(&lifecycle_lock);

    if (!hooks_attached && !runtime_enabled) {
        pthread_mutex_unlock(&lifecycle_lock);
        return;
    }

    cleanup_in_progress = 1;
    revert_replacements();

    if (stats_logging || verbose_logging || profile_enabled || hotness_enabled) {
        print_stats();
        print_profile_report();
        print_hotness_report();
    }

    if (malloc_interceptor) {
        g_object_unref(malloc_interceptor);
        malloc_interceptor = NULL;
    }
    if (gum_initialized) {
        gum_deinit_embedded();
        gum_initialized = 0;
    }

    hooks_attached = 0;
    runtime_enabled = 0;
    cleanup_in_progress = 0;

    pthread_mutex_unlock(&lifecycle_lock);
}

void malloc_interceptor_dettach(void) {
    malloc_interceptor_detach();
}
