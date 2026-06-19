#define _GNU_SOURCE

#include "malloc_interceptor.h"

#include <ctype.h>
#include <dlfcn.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>

#include "frida-gum.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
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
#define MAI_AUTO_MEMORY_CAP_PERCENT 95
#define MAI_CGROUP_LIMIT_SENTINEL (1ULL << 60)
#define MAI_ZERO_FILL_CHUNK (1024ULL * 1024ULL)
#define MAI_MEMORY_CAP_CHECK_INTERVAL 1024
#define MAI_MEMORY_CAP_REFRESH_INTERVAL 1024
#define MAI_AUTO_ANON_LIMIT_PERCENT 85
#define MAI_AUTO_LARGE_ALLOC_CAP_PERCENT 12
#define MAI_ACCESS_TRACE_MAX_PAGES 64
#define MAI_DEFAULT_ACCESS_TRACE_PAGES 16
#define MAI_DEFAULT_HEARTBEAT_OBSERVE_PAGES 16
#define MAI_DEFAULT_HEARTBEAT_CHUNK_BYTES (64ULL * 1024ULL * 1024ULL)
#define MAI_DEFAULT_HEARTBEAT_MIN_QUIET_EPOCHS 3
#define MAI_DEFAULT_BACKGROUND_HEARTBEAT_INTERVAL_US 1000
#define MAI_DEFAULT_BACKGROUND_HEARTBEAT_MIGRATE_BYTES 0
#define MAI_DEFAULT_FILE_DEDICATED_MIN_BYTES (64ULL * 1024ULL * 1024ULL)
#define MAI_HEARTBEAT_BUSY_SCORE_CAP 1024
#define MAI_DEFAULT_MIGRATION_CHUNK_BYTES (2ULL * 1024ULL * 1024ULL)
#define MAI_DEFAULT_UFFD_PREFETCH_CHUNKS 4
#define MAI_MAX_UFFD_PREFETCH_CHUNKS 16
#define MAI_POLICY_STALL_HIST_BUCKETS 64
#define MAI_POLICY_STREAM_SLOTS 4
#define MAI_HUGEPAGE_SIZE (2ULL * 1024ULL * 1024ULL)
#define MAI_ACCESS_TRACE_RETIRED_GRACE_NS (10ULL * 1000ULL * 1000ULL)

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
    BACKEND_ARENA = 0,
    BACKEND_ANON = 1,
    BACKEND_UFFD_PAGER = 2
} BackendType;

typedef enum {
    BACKEND_MODE_AUTO = 0,
    BACKEND_MODE_ANON,
    BACKEND_MODE_FILE
} BackendMode;

typedef enum {
    UFFD_PAGER_OFF = 0,
    UFFD_PAGER_AUTO,
    UFFD_PAGER_REQUIRED
} UffdPagerMode;

typedef enum {
    CHUNK_ANON_HOT = 0,
    CHUNK_FILE_COLD = 1
} ChunkState;

typedef enum {
    MIGRATION_POLICY_LEGACY = 0,
    MIGRATION_POLICY_LRU,
    MIGRATION_POLICY_CLOCK,
    MIGRATION_POLICY_FIFO,
    MIGRATION_POLICY_RANDOM,
    MIGRATION_POLICY_STREAM,
    MIGRATION_POLICY_STRIDE,
    MIGRATION_POLICY_2Q,
    MIGRATION_POLICY_LFU
} MigrationPolicy;

enum {
    MAI_CHUNK_POLICY_DEMANDED = 1u << 0,
    MAI_CHUNK_POLICY_PREFETCHED = 1u << 1,
    MAI_CHUNK_POLICY_PREFETCH_USED = 1u << 2,
    MAI_CHUNK_POLICY_REFERENCED = 1u << 3,
    MAI_CHUNK_POLICY_PROBATION = 1u << 4,
    MAI_CHUNK_POLICY_PROTECTED = 1u << 5
};

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
    ACCESS_TRACE_FREE = 0,
    ACCESS_TRACE_ARMED = 1,
    ACCESS_TRACE_TOUCHED = 2,
    ACCESS_TRACE_TOUCHING = 3,
    ACCESS_TRACE_STOPPING = 4
} AccessTraceState;

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
typedef struct AccessTracePage AccessTracePage;

typedef struct {
    size_t last_access_epoch;
    size_t last_prefetch_epoch;
    size_t first_resident_epoch;
    size_t frequency;
    uint32_t flags;
    uint16_t policy_state;
    uint16_t confidence;
    ptrdiff_t last_delta;
} MaiChunkPolicyMeta;

typedef struct {
    size_t last_index;
    ptrdiff_t delta;
    size_t confidence;
    size_t last_epoch;
    int active;
} MaiStreamPolicySlot;

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
    uint32_t hint_kind;
    uint32_t hint_flags;
    size_t hint_offset;
    size_t hint_length;
    size_t hint_hotset_bytes;
    size_t hint_window_bytes;
    size_t hint_epoch;
    size_t access_trace_id;
    uintptr_t access_trace_start;
    size_t access_trace_length;
    size_t access_trace_total_pages;
    size_t access_trace_armed_pages;
    size_t heartbeat_last_touch_epoch;
    size_t heartbeat_quiet_epochs;
    size_t heartbeat_busy_score;
    size_t hotness_samples;
    size_t hotness_sampled_pages;
    size_t hotness_resident_pages;
    int storage_fd;
    size_t storage_length;
    size_t chunk_bytes;
    size_t chunk_count;
    unsigned char* chunk_states;
    unsigned char* chunk_has_storage;
    size_t* chunk_touch_epochs;
    MaiChunkPolicyMeta* chunk_policy_meta;
    size_t resident_bytes;
    size_t policy_clock_hand;
    size_t policy_last_fault_index;
    int policy_has_last_fault;
    ptrdiff_t policy_last_delta;
    size_t policy_run_length;
    size_t policy_prefetch_window;
    MaiStreamPolicySlot policy_stream_slots[MAI_POLICY_STREAM_SLOTS];
    int uffd_registered;
    int uffd_closing;
    ArenaSegment* segment;
    ArenaBlock* block;
    AllocationRecord* hash_next;
    AllocationRecord* live_prev;
    AllocationRecord* live_next;
    AllocationRecord* uffd_prev;
    AllocationRecord* uffd_next;
};

typedef struct {
    AllocationRecord* record;
    size_t indices[MAI_MAX_UFFD_PREFETCH_CHUNKS + 1];
    size_t count;
} MaiProtectedChunkSet;

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

struct AccessTracePage {
    atomic_int state;
    atomic_uintptr_t page;
    atomic_uintptr_t retired_page;
    _Atomic(uint64_t) retired_deadline_ns;
    _Atomic(AllocationRecord*) record;
    atomic_size_t trace_id;
    atomic_size_t sample_index;
    atomic_size_t touch_sequence;
};

static GumInterceptor* malloc_interceptor = NULL;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t uffd_fault_lock = PTHREAD_MUTEX_INITIALIZER;
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
static size_t max_rss_bytes = 0;
static int max_rss_auto = 1;
static int max_rss_enabled = 1;
static size_t auto_large_alloc_cap_percent = MAI_AUTO_LARGE_ALLOC_CAP_PERCENT;
static size_t memory_cap_check_counter = 0;
static size_t memory_cap_refresh_counter = 0;
static ReclaimPolicy reclaim_policy = RECLAIM_NONE;
static ReclaimSelection reclaim_selection = RECLAIM_SELECT_OLDEST;
static BackendMode backend_mode = BACKEND_MODE_AUTO;
static UffdPagerMode uffd_pager_mode = UFFD_PAGER_OFF;
static MigrationPolicy migration_policy = MIGRATION_POLICY_LEGACY;
static int policy_observe_prefetch_writes = 0;
static int uffd_pager_available = 0;
static int uffd_fd = -1;
static pthread_t uffd_thread;
static int uffd_thread_started = 0;
static atomic_int uffd_thread_stop;
static size_t uffd_resident_limit_bytes = 0;
static size_t uffd_resident_low_limit_bytes = 0;
static int uffd_resident_limit_explicit = 0;
static size_t uffd_resident_bytes = 0;
static size_t uffd_touch_epoch = 0;
static uint64_t policy_random_state = 0x9e3779b97f4a7c15ULL;
static size_t policy_fault_stall_hist[MAI_POLICY_STALL_HIST_BUCKETS];
static size_t policy_fault_stall_max_ns = 0;
static void* uffd_scratch_buffer = NULL;
static size_t uffd_scratch_length = 0;
static size_t migration_chunk_bytes = MAI_DEFAULT_MIGRATION_CHUNK_BYTES;
static size_t uffd_prefetch_chunks = MAI_DEFAULT_UFFD_PREFETCH_CHUNKS;
static size_t file_dedicated_min_bytes = MAI_DEFAULT_FILE_DEDICATED_MIN_BYTES;
static int profile_enabled = 0;
static int hotness_enabled = 0;
static size_t hotness_sample_pages = MAI_DEFAULT_HOTNESS_SAMPLE_PAGES;

static ArenaSegment* arena_segments = NULL;
static size_t next_segment_id = 0;
static AllocationRecord* allocation_buckets[MAI_TRACK_BUCKETS];
static AllocationRecord* live_head = NULL;
static AllocationRecord* uffd_head = NULL;
static ProfileRecord* profile_buckets[MAI_PROFILE_BUCKETS];
static DynamicReplacement* dynamic_replacements = NULL;
static atomic_int dynamic_replacements_active;
static DynamicHandleRecord* dynamic_handles = NULL;
static ExclusionRange* exclusion_ranges = NULL;
static RegistrationRecord* registration_records = NULL;
static AccessTracePage access_trace_pages[MAI_ACCESS_TRACE_MAX_PAGES];
static struct sigaction previous_sigsegv_action;
static int access_trace_handler_installed = 0;
static atomic_size_t access_trace_sequence;
static size_t access_trace_id_sequence = 0;
static size_t allocation_sequence = 0;
static size_t reclaim_epoch = 0;
static size_t heartbeat_epoch = 0;
static AllocationRecord* heartbeat_cursor = NULL;
static size_t heartbeat_min_quiet_epochs = MAI_DEFAULT_HEARTBEAT_MIN_QUIET_EPOCHS;
static int background_heartbeat_enabled = 0;
static size_t background_heartbeat_interval_us =
    MAI_DEFAULT_BACKGROUND_HEARTBEAT_INTERVAL_US;
static size_t background_heartbeat_observe_pages =
    MAI_DEFAULT_HEARTBEAT_OBSERVE_PAGES;
static size_t background_heartbeat_chunk_bytes =
    MAI_DEFAULT_HEARTBEAT_CHUNK_BYTES;
static size_t background_heartbeat_migrate_bytes =
    MAI_DEFAULT_BACKGROUND_HEARTBEAT_MIGRATE_BYTES;
static pthread_t background_heartbeat_thread;
static int background_heartbeat_started = 0;
static atomic_int background_heartbeat_stop;
static size_t hint_epoch_sequence = 0;
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
static int auto_backend_should_prefer_file_locked(size_t incoming_managed_bytes);
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
static int reclaim_record_range_locked(AllocationRecord* record,
                                       void* range_start,
                                       size_t range_length,
                                       ReclaimPolicy policy,
                                       size_t account_bytes);
static AllocationRecord* free_managed_pointer_locked(void* ptr);
static size_t effective_max_rss_locked(size_t current_rss);
static size_t percent_of_size(size_t bytes, size_t percent);
static int ensure_uffd_pager_started_locked(void);
static void remove_uffd_record_locked(AllocationRecord* record);
static int evict_uffd_chunks_locked(size_t target_bytes,
                                   const MaiProtectedChunkSet* protected_set,
                                   int runtime_lock_held);
static void stop_uffd_pager(void);
static void access_trace_sigsegv_handler(int signo, siginfo_t* info, void* context);
static void stop_record_access_trace_locked(AllocationRecord* record);
static void stop_all_access_traces_locked(void);

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

static int parse_migration_policy_env(const char* value,
                                      MigrationPolicy* out) {
    if (!value || value[0] == '\0' || strcmp(value, "legacy") == 0) {
        *out = MIGRATION_POLICY_LEGACY;
        return 0;
    }
    if (strcmp(value, "lru") == 0) {
        *out = MIGRATION_POLICY_LRU;
        return 0;
    }
    if (strcmp(value, "clock") == 0) {
        *out = MIGRATION_POLICY_CLOCK;
        return 0;
    }
    if (strcmp(value, "fifo") == 0) {
        *out = MIGRATION_POLICY_FIFO;
        return 0;
    }
    if (strcmp(value, "random") == 0) {
        *out = MIGRATION_POLICY_RANDOM;
        return 0;
    }
    if (strcmp(value, "stream") == 0 ||
        strcmp(value, "adaptive-stream") == 0 ||
        strcmp(value, "sequential") == 0) {
        *out = MIGRATION_POLICY_STREAM;
        return 0;
    }
    if (strcmp(value, "stride") == 0 ||
        strcmp(value, "multi-stream") == 0 ||
        strcmp(value, "multistream") == 0) {
        *out = MIGRATION_POLICY_STRIDE;
        return 0;
    }
    if (strcmp(value, "2q") == 0 || strcmp(value, "twoq") == 0 ||
        strcmp(value, "prefetch-aware-2q") == 0) {
        *out = MIGRATION_POLICY_2Q;
        return 0;
    }
    if (strcmp(value, "lfu") == 0 || strcmp(value, "decayed-lfu") == 0) {
        *out = MIGRATION_POLICY_LFU;
        return 0;
    }
    return -1;
}

static int init_record_policy_meta_locked(AllocationRecord* record) {
    if (!record || record->chunk_count == 0) {
        return 0;
    }
    size_t meta_bytes;
    if (mul_overflow(record->chunk_count, sizeof(*record->chunk_policy_meta),
                     &meta_bytes) != 0) {
        return -1;
    }
    record->chunk_policy_meta =
        meta_alloc(meta_bytes);
    if (!record->chunk_policy_meta) {
        return -1;
    }
    memset(record->chunk_policy_meta, 0, meta_bytes);
    record->policy_clock_hand = 0;
    record->policy_has_last_fault = 0;
    record->policy_last_fault_index = 0;
    record->policy_last_delta = 0;
    record->policy_run_length = 0;
    record->policy_prefetch_window = 0;
    return 0;
}

static void free_record_policy_meta_locked(AllocationRecord* record) {
    if (!record) {
        return;
    }
    meta_free(record->chunk_policy_meta);
    record->chunk_policy_meta = NULL;
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

static int read_size_file(const char* path, size_t* out) {
    char buffer[128];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return -1;
    }
    buffer[bytes_read] = '\0';

    char* cursor = buffer;
    while (*cursor && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (strncmp(cursor, "max", 3) == 0) {
        return -1;
    }

    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || parsed > (unsigned long long)SIZE_MAX ||
        parsed >= MAI_CGROUP_LIMIT_SENTINEL) {
        return -1;
    }

    *out = (size_t)parsed;
    return 0;
}

static size_t sample_physical_memory_bytes(void) {
    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages <= 0 || (unsigned long)pages > SIZE_MAX / page_size) {
        return 0;
    }
    return (size_t)pages * page_size;
}

static size_t sample_mem_available_bytes(void) {
    char buffer[4096];
    int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return 0;
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return 0;
    }
    buffer[bytes_read] = '\0';

    const char* key = "MemAvailable:";
    char* line = strstr(buffer, key);
    if (!line) {
        return 0;
    }
    line += strlen(key);
    while (*line && isspace((unsigned char)*line)) {
        line++;
    }

    errno = 0;
    char* end = NULL;
    unsigned long long kib = strtoull(line, &end, 10);
    if (errno != 0 || end == line ||
        kib > (unsigned long long)(SIZE_MAX / 1024ULL)) {
        return 0;
    }

    return (size_t)kib * 1024ULL;
}

static int controller_list_has_memory(const char* controllers) {
    const char* cursor = controllers;
    while (*cursor) {
        const char* comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        if (length == strlen("memory") && strncmp(cursor, "memory", length) == 0) {
            return 1;
        }
        if (!comma) {
            break;
        }
        cursor = comma + 1;
    }
    return 0;
}

static int build_cgroup_file_path(char* buffer, size_t buffer_size,
                                  const char* mount_root,
                                  const char* relative_path,
                                  const char* file_name) {
    if (!buffer || buffer_size == 0 || !mount_root || !relative_path || !file_name) {
        return -1;
    }

    while (*relative_path == '/') {
        relative_path++;
    }
    if (strstr(relative_path, "..")) {
        return -1;
    }

    int written;
    if (*relative_path) {
        written = snprintf(buffer, buffer_size, "%s/%s/%s", mount_root,
                           relative_path, file_name);
    } else {
        written = snprintf(buffer, buffer_size, "%s/%s", mount_root, file_name);
    }

    return written >= 0 && (size_t)written < buffer_size ? 0 : -1;
}

static int read_process_cgroup_memory_file(const char* v2_file, const char* v1_file,
                                           size_t* out) {
    char buffer[4096];
    int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return -1;
    }
    buffer[bytes_read] = '\0';

    for (char* line = buffer; line && *line;) {
        char* next = strchr(line, '\n');
        if (next) {
            *next = '\0';
            next++;
        }

        char* first_colon = strchr(line, ':');
        char* second_colon = first_colon ? strchr(first_colon + 1, ':') : NULL;
        if (!first_colon || !second_colon) {
            line = next;
            continue;
        }

        *first_colon = '\0';
        *second_colon = '\0';
        const char* hierarchy = line;
        const char* controllers = first_colon + 1;
        const char* relative_path = second_colon + 1;
        char path[PATH_MAX];

        if (strcmp(hierarchy, "0") == 0 && controllers[0] == '\0') {
            if (build_cgroup_file_path(path, sizeof(path), "/sys/fs/cgroup",
                                       relative_path, v2_file) == 0 &&
                read_size_file(path, out) == 0) {
                return 0;
            }
        } else if (controller_list_has_memory(controllers)) {
            if (build_cgroup_file_path(path, sizeof(path), "/sys/fs/cgroup/memory",
                                       relative_path, v1_file) == 0 &&
                read_size_file(path, out) == 0) {
                return 0;
            }
        }

        line = next;
    }

    return -1;
}

static size_t sample_cgroup_limit_bytes(void) {
    size_t value = 0;
    if (read_process_cgroup_memory_file("memory.max", "memory.limit_in_bytes",
                                        &value) == 0) {
        return value;
    }
    if (read_size_file("/sys/fs/cgroup/memory.max", &value) == 0) {
        return value;
    }
    if (read_size_file("/sys/fs/cgroup/memory/memory.limit_in_bytes", &value) == 0) {
        return value;
    }
    return 0;
}

static size_t sample_cgroup_current_bytes(void) {
    size_t value = 0;
    if (read_process_cgroup_memory_file("memory.current", "memory.usage_in_bytes",
                                        &value) == 0) {
        return value;
    }
    if (read_size_file("/sys/fs/cgroup/memory.current", &value) == 0) {
        return value;
    }
    if (read_size_file("/sys/fs/cgroup/memory/memory.usage_in_bytes", &value) == 0) {
        return value;
    }
    return 0;
}

static size_t min_nonzero_size(size_t a, size_t b) {
    if (a == 0) {
        return b;
    }
    if (b == 0) {
        return a;
    }
    return a < b ? a : b;
}

static size_t apply_auto_cap_headroom(size_t bytes) {
    if (bytes == 0) {
        return 0;
    }

    size_t capped = (bytes / 100) * MAI_AUTO_MEMORY_CAP_PERCENT +
        ((bytes % 100) * MAI_AUTO_MEMORY_CAP_PERCENT) / 100;
    if (capped == 0) {
        return bytes;
    }
    if (capped < page_size && bytes >= page_size) {
        return page_size;
    }
    return capped;
}

static size_t detect_auto_max_rss_bytes(size_t current_rss) {
    size_t cgroup_limit = sample_cgroup_limit_bytes();
    size_t cap = min_nonzero_size(sample_physical_memory_bytes(), cgroup_limit);
    size_t cgroup_current = sample_cgroup_current_bytes();
    if (cgroup_limit != 0 && cgroup_current != 0) {
        size_t cgroup_cap = current_rss;
        if (cgroup_limit > cgroup_current) {
            size_t remaining = cgroup_limit - cgroup_current;
            cgroup_cap = current_rss > SIZE_MAX - remaining ? SIZE_MAX :
                current_rss + remaining;
        }
        cap = min_nonzero_size(cap, cgroup_cap);
    }

    size_t mem_available = sample_mem_available_bytes();
    if (mem_available != 0) {
        size_t available_cap = current_rss > SIZE_MAX - mem_available ? SIZE_MAX :
            current_rss + mem_available;
        cap = min_nonzero_size(cap, available_cap);
    }

    return apply_auto_cap_headroom(cap);
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

static int hint_kind_valid(uint32_t kind) {
    return kind == MAI_HINT_UNKNOWN ||
           kind == MAI_HINT_NONE ||
           kind == MAI_HINT_SEQUENTIAL ||
           kind == MAI_HINT_SPARSE ||
           kind == MAI_HINT_RANDOM_HOTSET ||
           kind == MAI_HINT_COLD_RECLAIM;
}

static int hint_options_valid(const MaiHintOptions* opts) {
    if (!opts) {
        return 1;
    }

    return opts->size >= offsetof(MaiHintOptions, reserved);
}

static void clear_record_hint_locked(AllocationRecord* record) {
    record->hint_kind = MAI_HINT_UNKNOWN;
    record->hint_flags = 0;
    record->hint_offset = 0;
    record->hint_length = 0;
    record->hint_hotset_bytes = 0;
    record->hint_window_bytes = 0;
    record->hint_epoch = 0;
}

static int range_overlaps_exclusion_locked(uintptr_t start, uintptr_t end) {
    for (ExclusionRange* range = exclusion_ranges; range; range = range->next) {
        if (ranges_overlap(start, end, range->start, range->end)) {
            return 1;
        }
    }

    return 0;
}

static int record_user_range_locked(AllocationRecord* record,
                                    uintptr_t* start,
                                    uintptr_t* end) {
    return make_range(record->user_ptr, record->user_size, start, end);
}

static AllocationRecord* find_record_containing_range_locked(uintptr_t start,
                                                             uintptr_t end,
                                                             int* partial_overlap) {
    *partial_overlap = 0;

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        uintptr_t record_start;
        uintptr_t record_end;
        if (record_user_range_locked(record, &record_start, &record_end) != 0) {
            continue;
        }

        if (!record->uffd_closing && start >= record_start && end <= record_end) {
            return record;
        }
        if (ranges_overlap(start, end, record_start, record_end)) {
            *partial_overlap = 1;
        }
    }

    return NULL;
}

static int clamp_range_to_record_pages_locked(AllocationRecord* record,
                                              uintptr_t start,
                                              uintptr_t end,
                                              void** page_start_out,
                                              size_t* page_length_out) {
    void* record_page_start_ptr = NULL;
    size_t record_page_length = record_page_range(record, &record_page_start_ptr);
    if (record_page_length == 0) {
        *page_start_out = NULL;
        *page_length_out = 0;
        return 0;
    }

    uintptr_t page_mask = (uintptr_t)page_size - 1;
    uintptr_t record_page_start = (uintptr_t)record_page_start_ptr;
    uintptr_t record_page_end = record_page_start + record_page_length;
    uintptr_t page_start = start & ~page_mask;
    uintptr_t page_end;

    if (end > UINTPTR_MAX - page_mask) {
        page_end = UINTPTR_MAX & ~page_mask;
    } else {
        page_end = (end + page_mask) & ~page_mask;
    }

    if (page_start < record_page_start) {
        page_start = record_page_start;
    }
    if (page_end > record_page_end) {
        page_end = record_page_end;
    }

    if (page_end <= page_start) {
        *page_start_out = NULL;
        *page_length_out = 0;
        return 0;
    }

    *page_start_out = (void*)page_start;
    *page_length_out = (size_t)(page_end - page_start);
    return 0;
}

static int full_user_page_range(uintptr_t start,
                                uintptr_t end,
                                uintptr_t* page_start_out,
                                size_t* total_pages_out) {
    uintptr_t page_start = align_up_uintptr(start, page_size);
    uintptr_t page_end = end & ~((uintptr_t)page_size - 1);

    if (page_end <= page_start) {
        *page_start_out = 0;
        *total_pages_out = 0;
        return 0;
    }

    *page_start_out = page_start;
    *total_pages_out = (size_t)((page_end - page_start) / page_size);
    return 0;
}

static int access_trace_options_valid(const MaiAccessTraceOptions* opts) {
    if (!opts) {
        return 1;
    }

    return opts->size >= offsetof(MaiAccessTraceOptions, reserved);
}

static int heartbeat_options_valid(const MaiHeartbeatOptions* opts) {
    if (!opts) {
        return 1;
    }

    return opts->size >= offsetof(MaiHeartbeatOptions, reserved);
}

static size_t access_trace_chunk_pages(size_t chunk_bytes) {
    if (chunk_bytes == 0) {
        return 0;
    }

    size_t aligned = align_up_size(chunk_bytes, page_size);
    if (aligned == 0) {
        return SIZE_MAX / page_size;
    }
    if (aligned < page_size) {
        return 1;
    }
    return aligned / page_size;
}

static size_t access_trace_requested_pages_from_values(size_t max_pages,
                                                       size_t chunk_pages,
                                                       size_t total_pages) {
    size_t requested = max_pages == 0 ? MAI_DEFAULT_ACCESS_TRACE_PAGES : max_pages;

    if (requested > MAI_ACCESS_TRACE_MAX_PAGES) {
        requested = MAI_ACCESS_TRACE_MAX_PAGES;
    }
    if (requested > total_pages) {
        requested = total_pages;
    }
    if (chunk_pages != 0 && requested != 0) {
        size_t chunk_samples =
            total_pages / chunk_pages + (total_pages % chunk_pages != 0);
        if (requested > chunk_samples) {
            requested = chunk_samples;
        }
    }
    return requested;
}

static size_t access_trace_sample_page_index(size_t sample_index,
                                             size_t requested_pages,
                                             size_t total_pages,
                                             size_t chunk_pages,
                                             size_t chunk_phase_pages) {
    if (chunk_pages != 0) {
        size_t page_index = sample_index * chunk_pages;
        size_t phase = chunk_phase_pages < chunk_pages ?
            chunk_phase_pages : chunk_pages - 1;
        if (page_index <= SIZE_MAX - phase) {
            page_index += phase;
        } else {
            page_index = total_pages - 1;
        }
        return page_index < total_pages ? page_index : total_pages - 1;
    }

    return (sample_index * total_pages) / requested_pages;
}

static size_t heartbeat_chunk_phase_pages(size_t chunk_pages, size_t epoch) {
    if (chunk_pages <= 1) {
        return 0;
    }

    switch ((epoch == 0 ? 0 : epoch - 1) % 3) {
    case 0:
        return 0;
    case 1:
        return chunk_pages / 2;
    default:
        return chunk_pages - 1;
    }
}

static void clear_record_access_trace_locked(AllocationRecord* record) {
    record->access_trace_id = 0;
    record->access_trace_start = 0;
    record->access_trace_length = 0;
    record->access_trace_total_pages = 0;
    record->access_trace_armed_pages = 0;
}

static void dispatch_previous_sigsegv(int signo, siginfo_t* info, void* context) {
    if ((previous_sigsegv_action.sa_flags & SA_SIGINFO) &&
        previous_sigsegv_action.sa_sigaction) {
        previous_sigsegv_action.sa_sigaction(signo, info, context);
        return;
    }

    if (previous_sigsegv_action.sa_handler == SIG_IGN) {
        return;
    }
    if (previous_sigsegv_action.sa_handler &&
        previous_sigsegv_action.sa_handler != SIG_DFL) {
        previous_sigsegv_action.sa_handler(signo);
        return;
    }

    (void)sigaction(SIGSEGV, &previous_sigsegv_action, NULL);
    (void)raise(SIGSEGV);
}

static uint64_t monotonic_time_ns_signal_safe(void) {
    struct timespec ts;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void access_trace_sigsegv_handler(int signo, siginfo_t* info, void* context) {
    int saved_errno = errno;
    uintptr_t fault = (uintptr_t)info->si_addr;
    uintptr_t page = fault & ~((uintptr_t)page_size - 1);

    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        uintptr_t trace_page_addr =
            atomic_load_explicit(&trace_page->page, memory_order_acquire);
        if (trace_page_addr != page) {
            continue;
        }

        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        if (state == ACCESS_TRACE_STOPPING ||
            state == ACCESS_TRACE_TOUCHING ||
            state == ACCESS_TRACE_TOUCHED) {
            if (syscall(SYS_mprotect, (void*)trace_page_addr, page_size,
                        PROT_READ | PROT_WRITE) == 0) {
                errno = saved_errno;
                return;
            }
            break;
        }

        if (state != ACCESS_TRACE_ARMED) {
            continue;
        }

        int expected = ACCESS_TRACE_ARMED;
        if (!atomic_compare_exchange_strong_explicit(&trace_page->state,
                                                     &expected,
                                                     ACCESS_TRACE_TOUCHING,
                                                     memory_order_acq_rel,
                                                     memory_order_acquire)) {
            if (expected == ACCESS_TRACE_STOPPING ||
                expected == ACCESS_TRACE_TOUCHING ||
                expected == ACCESS_TRACE_TOUCHED) {
                if (syscall(SYS_mprotect, (void*)trace_page_addr, page_size,
                            PROT_READ | PROT_WRITE) == 0) {
                    errno = saved_errno;
                    return;
                }
                break;
            }
            continue;
        }

        if (syscall(SYS_mprotect, (void*)trace_page_addr, page_size,
                    PROT_READ | PROT_WRITE) == 0) {
            size_t sequence = atomic_fetch_add_explicit(&access_trace_sequence, 1,
                                                        memory_order_relaxed) + 1;
            atomic_store_explicit(&trace_page->touch_sequence, sequence,
                                  memory_order_release);
            atomic_store_explicit(&trace_page->state, ACCESS_TRACE_TOUCHED,
                                  memory_order_release);
            errno = saved_errno;
            return;
        }
        atomic_store_explicit(&trace_page->state, ACCESS_TRACE_ARMED,
                              memory_order_release);
        break;
    }

    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        uintptr_t retired_page =
            atomic_load_explicit(&trace_page->retired_page, memory_order_acquire);
        if (retired_page != page) {
            continue;
        }

        uint64_t deadline =
            atomic_load_explicit(&trace_page->retired_deadline_ns,
                                 memory_order_acquire);
        uint64_t now = monotonic_time_ns_signal_safe();
        if (deadline == 0 || now == 0 || now > deadline) {
            uintptr_t expected = retired_page;
            (void)atomic_compare_exchange_strong_explicit(
                &trace_page->retired_page, &expected, 0,
                memory_order_acq_rel, memory_order_acquire);
            break;
        }

        uintptr_t expected = retired_page;
        if (atomic_compare_exchange_strong_explicit(&trace_page->retired_page,
                                                    &expected, 0,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire) &&
            syscall(SYS_mprotect, (void*)retired_page, page_size,
                    PROT_READ | PROT_WRITE) == 0) {
            atomic_store_explicit(&trace_page->retired_deadline_ns, 0,
                                  memory_order_release);
            errno = saved_errno;
            return;
        }
        break;
    }

    errno = saved_errno;
    dispatch_previous_sigsegv(signo, info, context);
}

static int install_access_trace_handler_locked(void) {
    if (access_trace_handler_installed) {
        return 0;
    }

    struct sigaction current;
    memset(&current, 0, sizeof(current));
    if (sigaction(SIGSEGV, NULL, &current) != 0) {
        return -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = access_trace_sigsegv_handler;
    action.sa_flags = SA_SIGINFO;
#ifdef SA_ONSTACK
    action.sa_flags |= current.sa_flags & SA_ONSTACK;
#endif

    if (sigaction(SIGSEGV, &action, &previous_sigsegv_action) != 0) {
        return -1;
    }

    access_trace_handler_installed = 1;
    return 0;
}

static void restore_access_trace_handler(void) {
    if (!access_trace_handler_installed) {
        return;
    }

    struct sigaction current;
    memset(&current, 0, sizeof(current));
    if (sigaction(SIGSEGV, NULL, &current) == 0 &&
        (current.sa_flags & SA_SIGINFO) &&
        current.sa_sigaction == access_trace_sigsegv_handler) {
        (void)sigaction(SIGSEGV, &previous_sigsegv_action, NULL);
    }
    memset(&previous_sigsegv_action, 0, sizeof(previous_sigsegv_action));
    access_trace_handler_installed = 0;
}

static int access_trace_page_busy_locked(uintptr_t page) {
    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        uintptr_t trace_page_addr =
            atomic_load_explicit(&trace_page->page, memory_order_acquire);
        if (state != ACCESS_TRACE_FREE && trace_page_addr == page) {
            return 1;
        }
    }

    return 0;
}

static AccessTracePage* find_free_access_trace_page_locked(void) {
    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        if (atomic_load_explicit(&trace_page->state, memory_order_acquire) ==
            ACCESS_TRACE_FREE) {
            return trace_page;
        }
    }

    return NULL;
}

static void reset_trace_page(AccessTracePage* trace_page) {
    uintptr_t page = atomic_load_explicit(&trace_page->page, memory_order_acquire);
    uint64_t now = monotonic_time_ns_signal_safe();
    if (page != 0 && now != 0) {
        atomic_store_explicit(&trace_page->retired_deadline_ns,
                              now + MAI_ACCESS_TRACE_RETIRED_GRACE_NS,
                              memory_order_release);
        atomic_store_explicit(&trace_page->retired_page, page,
                              memory_order_release);
    } else {
        atomic_store_explicit(&trace_page->retired_deadline_ns, 0,
                              memory_order_release);
        atomic_store_explicit(&trace_page->retired_page, 0,
                              memory_order_release);
    }
    atomic_store_explicit(&trace_page->page, 0, memory_order_release);
    atomic_store_explicit(&trace_page->record, NULL, memory_order_release);
    atomic_store_explicit(&trace_page->trace_id, 0, memory_order_relaxed);
    atomic_store_explicit(&trace_page->sample_index, 0, memory_order_relaxed);
    atomic_store_explicit(&trace_page->touch_sequence, 0, memory_order_relaxed);
    atomic_store_explicit(&trace_page->state, ACCESS_TRACE_FREE,
                          memory_order_release);
}

static void stop_trace_page_locked(AccessTracePage* trace_page) {
    for (;;) {
        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        if (state == ACCESS_TRACE_FREE) {
            return;
        }

        uintptr_t page =
            atomic_load_explicit(&trace_page->page, memory_order_acquire);
        if (state == ACCESS_TRACE_ARMED) {
            int expected = ACCESS_TRACE_ARMED;
            if (!atomic_compare_exchange_strong_explicit(&trace_page->state,
                                                         &expected,
                                                         ACCESS_TRACE_STOPPING,
                                                         memory_order_acq_rel,
                                                         memory_order_acquire)) {
                continue;
            }
            (void)mprotect((void*)page, page_size, PROT_READ | PROT_WRITE);
            reset_trace_page(trace_page);
            return;
        }

        if (state == ACCESS_TRACE_TOUCHING) {
            sched_yield();
            continue;
        }

        if (state == ACCESS_TRACE_STOPPING) {
            (void)mprotect((void*)page, page_size, PROT_READ | PROT_WRITE);
        }
        reset_trace_page(trace_page);
        return;
    }
}

static void stop_record_access_trace_locked(AllocationRecord* record) {
    if (!record || record->access_trace_id == 0) {
        return;
    }

    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        AllocationRecord* trace_record =
            atomic_load_explicit(&trace_page->record, memory_order_acquire);
        size_t trace_id =
            atomic_load_explicit(&trace_page->trace_id, memory_order_acquire);
        if (state == ACCESS_TRACE_FREE ||
            trace_record != record ||
            trace_id != record->access_trace_id) {
            continue;
        }

        stop_trace_page_locked(trace_page);
    }

    clear_record_access_trace_locked(record);
}

static void stop_all_access_traces_locked(void) {
    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        stop_record_access_trace_locked(record);
    }

    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        if (state != ACCESS_TRACE_FREE) {
            stop_trace_page_locked(trace_page);
        }
    }
}

static int arm_record_access_trace_locked(AllocationRecord* record,
                                          uintptr_t start,
                                          uintptr_t end,
                                          size_t max_pages,
                                          size_t chunk_bytes,
                                          size_t chunk_phase_pages,
                                          size_t* armed_pages_out) {
    if (armed_pages_out) {
        *armed_pages_out = 0;
    }
    if (range_overlaps_exclusion_locked(start, end)) {
        return 0;
    }

    if (install_access_trace_handler_locked() != 0) {
        return -1;
    }

    stop_record_access_trace_locked(record);

    uintptr_t page_start = 0;
    size_t total_pages = 0;
    (void)full_user_page_range(start, end, &page_start, &total_pages);
    if (total_pages == 0) {
        return 0;
    }

    size_t chunk_pages = access_trace_chunk_pages(chunk_bytes);
    size_t requested_pages =
        access_trace_requested_pages_from_values(max_pages, chunk_pages,
                                                 total_pages);
    if (requested_pages == 0) {
        return 0;
    }

    size_t trace_id = ++access_trace_id_sequence;
    size_t armed_pages = 0;
    int rc = 0;
    for (size_t i = 0; i < requested_pages; i++) {
        size_t page_index =
            access_trace_sample_page_index(i, requested_pages, total_pages,
                                           chunk_pages, chunk_phase_pages);
        uintptr_t page = page_start + page_index * page_size;
        if (access_trace_page_busy_locked(page)) {
            errno = EBUSY;
            rc = -1;
            break;
        }

        AccessTracePage* trace_page = find_free_access_trace_page_locked();
        if (!trace_page) {
            errno = ENOMEM;
            rc = -1;
            break;
        }

        atomic_store_explicit(&trace_page->page, page, memory_order_release);
        atomic_store_explicit(&trace_page->record, record, memory_order_release);
        atomic_store_explicit(&trace_page->trace_id, trace_id,
                              memory_order_release);
        atomic_store_explicit(&trace_page->sample_index, i,
                              memory_order_release);
        atomic_store_explicit(&trace_page->touch_sequence, 0, memory_order_relaxed);
        atomic_store_explicit(&trace_page->state, ACCESS_TRACE_ARMED,
                              memory_order_release);

        if (mprotect((void*)page, page_size, PROT_NONE) != 0) {
            reset_trace_page(trace_page);
            rc = -1;
            break;
        }
        armed_pages++;
    }

    if (rc == 0) {
        record->access_trace_id = trace_id;
        record->access_trace_start = page_start;
        record->access_trace_length = total_pages * page_size;
        record->access_trace_total_pages = total_pages;
        record->access_trace_armed_pages = armed_pages;
        if (armed_pages_out) {
            *armed_pages_out = armed_pages;
        }
    } else {
        record->access_trace_id = trace_id;
        stop_record_access_trace_locked(record);
    }

    return rc;
}

static void record_access_trace_counts_locked(AllocationRecord* record,
                                              size_t* armed_pages_out,
                                              size_t* touched_pages_out) {
    size_t armed_pages = 0;
    size_t touched_pages = 0;

    if (record && record->access_trace_id != 0) {
        for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
            AccessTracePage* trace_page = &access_trace_pages[i];
            int state = atomic_load_explicit(&trace_page->state,
                                             memory_order_acquire);
            AllocationRecord* trace_record =
                atomic_load_explicit(&trace_page->record, memory_order_acquire);
            size_t trace_id =
                atomic_load_explicit(&trace_page->trace_id, memory_order_acquire);
            if (state == ACCESS_TRACE_FREE ||
                trace_record != record ||
                trace_id != record->access_trace_id) {
                continue;
            }

            armed_pages++;
            size_t sequence = atomic_load_explicit(&trace_page->touch_sequence,
                                                   memory_order_acquire);
            if (state == ACCESS_TRACE_TOUCHED || sequence != 0) {
                touched_pages++;
            }
        }
    }

    if (armed_pages_out) {
        *armed_pages_out = armed_pages;
    }
    if (touched_pages_out) {
        *touched_pages_out = touched_pages;
    }
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

    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        uintptr_t record_start;
        uintptr_t record_end;
        if (record->access_trace_id == 0 ||
            record_user_range_locked(record, &record_start, &record_end) != 0) {
            continue;
        }
        if (ranges_overlap(start, end, record_start, record_end)) {
            stop_record_access_trace_locked(record);
        }
    }

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
    if (record_user_range_locked(record, &start, &end) != 0) {
        return 0;
    }

    return range_overlaps_exclusion_locked(start, end);
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
    if (!heartbeat_cursor) {
        heartbeat_cursor = record;
    }
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

        if (heartbeat_cursor == record) {
            heartbeat_cursor = record->live_next ? record->live_next :
                (record->live_prev ? live_head : NULL);
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

static int create_unlinked_backing_file(size_t length) {
    char filename[PATH_MAX];
    int fd;
    int saved_errno;

    if (length == 0 || build_arena_template(filename, sizeof(filename)) != 0) {
        return -1;
    }

    fd = mkstemp(filename);
    if (fd == -1) {
        return -1;
    }
    if (unlink(filename) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (ftruncate(fd, (off_t)length) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    return fd;
}

static int write_all_at(int fd, const void* buffer, size_t length, off_t offset) {
    const unsigned char* cursor = (const unsigned char*)buffer;
    size_t written_total = 0;

    while (written_total < length) {
        ssize_t written = pwrite(fd, cursor + written_total,
                                 length - written_total,
                                 offset + (off_t)written_total);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = ENOSPC;
            return -1;
        }
        written_total += (size_t)written;
    }

    return 0;
}

static size_t file_segment_length_for_request(size_t minimum_size) {
    if (file_dedicated_min_bytes != 0 &&
        minimum_size >= file_dedicated_min_bytes) {
        return minimum_size;
    }
    return max_size(arena_size_bytes, minimum_size);
}

static int read_all_at(int fd, void* buffer, size_t length, off_t offset) {
    unsigned char* cursor = (unsigned char*)buffer;
    size_t read_total = 0;

    while (read_total < length) {
        ssize_t nread = pread(fd, cursor + read_total,
                              length - read_total,
                              offset + (off_t)read_total);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (nread == 0) {
            memset(cursor + read_total, 0, length - read_total);
            break;
        }
        read_total += (size_t)nread;
    }

    return 0;
}

static ArenaSegment* create_segment_locked(size_t minimum_size) {
    char filename[PATH_MAX];
    int fd = -1;
    int saved_errno;
    size_t length = file_segment_length_for_request(minimum_size);
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
    record->hint_kind = MAI_HINT_UNKNOWN;
    record->hint_flags = 0;
    record->hint_offset = 0;
    record->hint_length = 0;
    record->hint_hotset_bytes = 0;
    record->hint_window_bytes = 0;
    record->hint_epoch = 0;
    record->access_trace_id = 0;
    record->access_trace_start = 0;
    record->access_trace_length = 0;
    record->access_trace_total_pages = 0;
    record->access_trace_armed_pages = 0;
    record->heartbeat_last_touch_epoch = 0;
    record->heartbeat_quiet_epochs = 0;
    record->heartbeat_busy_score = 0;
    record->hotness_samples = 0;
    record->hotness_sampled_pages = 0;
    record->hotness_resident_pages = 0;
    record->storage_fd = -1;
    record->storage_length = 0;
    record->chunk_bytes = migration_chunk_bytes;
    record->chunk_count = 0;
    record->chunk_states = NULL;
    record->chunk_has_storage = NULL;
    record->chunk_touch_epochs = NULL;
    record->chunk_policy_meta = NULL;
    record->resident_bytes = 0;
    record->policy_clock_hand = 0;
    record->policy_last_fault_index = 0;
    record->policy_has_last_fault = 0;
    record->policy_last_delta = 0;
    record->policy_run_length = 0;
    record->policy_prefetch_window = 0;
    record->uffd_registered = 0;
    record->segment = block->segment;
    record->block = block;
    record->hash_next = NULL;
    record->live_prev = NULL;
    record->live_next = NULL;
    record->uffd_prev = NULL;
    record->uffd_next = NULL;

    insert_record_locked(record);
    stats_note_managed_alloc(user_size);
    stats_snapshot.file_allocations++;
    note_profile_locked(call_site, user_size);

    return record;
}

static size_t managed_chunk_count(size_t mapped_length, size_t chunk_bytes) {
    if (chunk_bytes == 0) {
        return 0;
    }
    return mapped_length / chunk_bytes + (mapped_length % chunk_bytes != 0);
}

static AllocationRecord* managed_anon_alloc_locked(size_t size, size_t alignment,
                                                   void* call_site) {
    size_t user_size = align_up_size(size, page_size);
    size_t effective_alignment = alignment;
    size_t mapped_length;
    void* base;
    uintptr_t aligned_start;
    AllocationRecord* record = NULL;

    if (size == 0 || user_size == 0 || !is_power_of_two(alignment)) {
        return NULL;
    }
    if (effective_alignment < default_alignment()) {
        effective_alignment = default_alignment();
    }
    if (effective_alignment < page_size) {
        effective_alignment = page_size;
    }
    if (size >= MAI_HUGEPAGE_SIZE && effective_alignment < MAI_HUGEPAGE_SIZE) {
        effective_alignment = MAI_HUGEPAGE_SIZE;
    }
    if (add_overflow(user_size, effective_alignment, &mapped_length) != 0) {
        return NULL;
    }
    mapped_length = align_up_size(mapped_length, page_size);
    if (mapped_length == 0) {
        return NULL;
    }

    base = mmap(NULL, mapped_length, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        return NULL;
    }

    aligned_start = align_up_uintptr((uintptr_t)base, effective_alignment);
    if (aligned_start < (uintptr_t)base ||
        aligned_start + user_size > (uintptr_t)base + mapped_length) {
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }

#ifdef MADV_HUGEPAGE
    (void)madvise((void*)aligned_start, user_size, MADV_HUGEPAGE);
#endif

    record = meta_alloc(sizeof(*record));
    if (!record) {
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }
    memset(record, 0, sizeof(*record));

    record->user_ptr = (void*)aligned_start;
    record->base_ptr = base;
    record->user_size = size;
    record->mapped_length = mapped_length;
    record->alignment = effective_alignment;
    record->backend = BACKEND_ANON;
    record->call_site = call_site;
    record->allocation_seq = ++allocation_sequence;
    record->hint_kind = MAI_HINT_UNKNOWN;
    record->storage_fd = -1;
    record->chunk_bytes = migration_chunk_bytes;
    record->chunk_count = managed_chunk_count(user_size, record->chunk_bytes);
    if (record->chunk_count != 0) {
        record->chunk_states = meta_alloc(record->chunk_count);
        if (!record->chunk_states) {
            meta_free(record);
            munmap(base, mapped_length);
            errno = ENOMEM;
            return NULL;
        }
        memset(record->chunk_states, CHUNK_ANON_HOT, record->chunk_count);
        (void)init_record_policy_meta_locked(record);
    }

    insert_record_locked(record);
    stats_note_managed_alloc(size);
    stats_snapshot.anon_allocations++;
    note_profile_locked(call_site, size);
    update_managed_range(base, mapped_length);

    return record;
}

static AllocationRecord* managed_uffd_alloc_locked(size_t size, size_t alignment,
                                                   void* call_site) {
    size_t user_size = align_up_size(size, page_size);
    size_t effective_alignment = alignment;
    size_t mapped_length;
    void* base;
    uintptr_t aligned_start;
    AllocationRecord* record = NULL;

    if (size == 0 || user_size == 0 || !is_power_of_two(alignment)) {
        return NULL;
    }
    if (ensure_uffd_pager_started_locked() != 0) {
        return NULL;
    }
    if (effective_alignment < default_alignment()) {
        effective_alignment = default_alignment();
    }
    if (effective_alignment < page_size) {
        effective_alignment = page_size;
    }
    if (size >= MAI_HUGEPAGE_SIZE && effective_alignment < MAI_HUGEPAGE_SIZE) {
        effective_alignment = MAI_HUGEPAGE_SIZE;
    }
    if (add_overflow(user_size, effective_alignment, &mapped_length) != 0) {
        return NULL;
    }
    mapped_length = align_up_size(mapped_length, page_size);
    if (mapped_length == 0) {
        return NULL;
    }

    base = mmap(NULL, mapped_length, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        return NULL;
    }

    aligned_start = align_up_uintptr((uintptr_t)base, effective_alignment);
    if (aligned_start < (uintptr_t)base ||
        aligned_start + user_size > (uintptr_t)base + mapped_length) {
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }

    record = meta_alloc(sizeof(*record));
    if (!record) {
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }
    memset(record, 0, sizeof(*record));

    record->user_ptr = (void*)aligned_start;
    record->base_ptr = base;
    record->user_size = size;
    record->mapped_length = mapped_length;
    record->alignment = effective_alignment;
    record->backend = BACKEND_UFFD_PAGER;
    record->call_site = call_site;
    record->allocation_seq = ++allocation_sequence;
    record->hint_kind = MAI_HINT_UNKNOWN;
    record->storage_fd = -1;
    record->chunk_bytes = migration_chunk_bytes;
    record->chunk_count = managed_chunk_count(user_size, record->chunk_bytes);
    if (record->chunk_count == 0) {
        meta_free(record);
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }
    record->chunk_states = meta_alloc(record->chunk_count);
    record->chunk_has_storage = meta_alloc(record->chunk_count);
    record->chunk_touch_epochs = meta_alloc(record->chunk_count * sizeof(size_t));
    if (!record->chunk_states || !record->chunk_has_storage ||
        !record->chunk_touch_epochs) {
        meta_free(record->chunk_states);
        meta_free(record->chunk_has_storage);
        meta_free(record->chunk_touch_epochs);
        meta_free(record);
        munmap(base, mapped_length);
        errno = ENOMEM;
        return NULL;
    }
    memset(record->chunk_states, CHUNK_FILE_COLD, record->chunk_count);
    memset(record->chunk_has_storage, 0, record->chunk_count);
    memset(record->chunk_touch_epochs, 0, record->chunk_count * sizeof(size_t));
    (void)init_record_policy_meta_locked(record);

    void* page_start = NULL;
    size_t page_length = record_page_range(record, &page_start);
    if (page_length == 0) {
        meta_free(record->chunk_states);
        meta_free(record->chunk_has_storage);
        meta_free(record->chunk_touch_epochs);
        free_record_policy_meta_locked(record);
        meta_free(record);
        munmap(base, mapped_length);
        errno = EINVAL;
        return NULL;
    }
    record->storage_fd = create_unlinked_backing_file(page_length);
    if (record->storage_fd < 0) {
        meta_free(record->chunk_states);
        meta_free(record->chunk_has_storage);
        meta_free(record->chunk_touch_epochs);
        free_record_policy_meta_locked(record);
        meta_free(record);
        munmap(base, mapped_length);
        return NULL;
    }
    record->storage_length = page_length;

    insert_record_locked(record);
    stats_note_managed_alloc(size);
    stats_snapshot.uffd_pager_allocations++;
    note_profile_locked(call_site, size);
    update_managed_range(base, mapped_length);

    return record;
}

static AllocationRecord* managed_auto_pressure_fallback_locked(size_t size,
                                                               size_t alignment,
                                                               void* call_site) {
    size_t block_size = align_up_size(size, page_size);
    if (block_size == 0) {
        return NULL;
    }

    AllocationRecord* anon_record =
        managed_anon_alloc_locked(size, alignment, call_site);
    if (!anon_record) {
        return NULL;
    }

    ReclaimPolicy cap_policy =
        reclaim_policy == RECLAIM_NONE ? RECLAIM_DONTNEED : reclaim_policy;
    if (reclaim_record_range_locked(anon_record, anon_record->user_ptr,
                                    block_size, cap_policy,
                                    block_size) != 0) {
        AllocationRecord* old_record =
            free_managed_pointer_locked(anon_record->user_ptr);
        meta_free(old_record);
        return NULL;
    }
    return anon_record;
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

    int prefer_file_backend = auto_backend_should_prefer_file_locked(block_size);
    if (backend_mode == BACKEND_MODE_AUTO && prefer_file_backend) {
        if (uffd_pager_mode != UFFD_PAGER_OFF && uffd_pager_available) {
            AllocationRecord* uffd_record =
                managed_uffd_alloc_locked(size, alignment, call_site);
            if (uffd_record) {
                return uffd_record;
            }
            pthread_mutex_lock(&uffd_fault_lock);
            stats_snapshot.uffd_fallbacks++;
            pthread_mutex_unlock(&uffd_fault_lock);
            if (uffd_pager_mode == UFFD_PAGER_REQUIRED) {
                return NULL;
            }
        }

        return managed_auto_pressure_fallback_locked(size, alignment, call_site);
    }

    if (backend_mode != BACKEND_MODE_FILE && !prefer_file_backend) {
        AllocationRecord* anon_record =
            managed_anon_alloc_locked(size, alignment, call_site);
        if (anon_record || backend_mode == BACKEND_MODE_ANON) {
            return anon_record;
        }
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
    stop_record_access_trace_locked(record);
    clear_record_hint_locked(record);
    stats_note_managed_free(record->user_size);

    if (record->backend == BACKEND_ANON || record->backend == BACKEND_UFFD_PAGER) {
        if (record->backend == BACKEND_UFFD_PAGER) {
            pthread_mutex_lock(&uffd_fault_lock);
            record->uffd_closing = 1;
            remove_uffd_record_locked(record);
            pthread_mutex_unlock(&uffd_fault_lock);
        }
        if (record->backend == BACKEND_UFFD_PAGER && record->uffd_registered &&
            uffd_fd >= 0) {
            struct uffdio_range range;
            void* page_start = NULL;
            size_t page_length = record_page_range(record, &page_start);
            if (page_length != 0) {
                memset(&range, 0, sizeof(range));
                range.start = (unsigned long)page_start;
                range.len = (unsigned long)page_length;
                (void)ioctl(uffd_fd, UFFDIO_UNREGISTER, &range);
            }
        }
        if (record->backend == BACKEND_UFFD_PAGER) {
            pthread_mutex_lock(&uffd_fault_lock);
            record->uffd_registered = 0;
            if (record->resident_bytes != 0) {
                if (uffd_resident_bytes >= record->resident_bytes) {
                    uffd_resident_bytes -= record->resident_bytes;
                } else {
                    uffd_resident_bytes = 0;
                }
                stats_snapshot.uffd_resident_bytes = uffd_resident_bytes;
            }
            pthread_mutex_unlock(&uffd_fault_lock);
        }
        if (record->storage_fd >= 0) {
            close(record->storage_fd);
            record->storage_fd = -1;
        }
        free_record_policy_meta_locked(record);
        meta_free(record->chunk_states);
        record->chunk_states = NULL;
        meta_free(record->chunk_has_storage);
        record->chunk_has_storage = NULL;
        meta_free(record->chunk_touch_epochs);
        record->chunk_touch_epochs = NULL;
        if (record->base_ptr && record->mapped_length != 0) {
            munmap(record->base_ptr, record->mapped_length);
        }
        return;
    }

    ArenaBlock* block = record->block;
    block->free = 1;
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

static int ensure_record_storage_locked(AllocationRecord* record) {
    if (record->backend != BACKEND_ANON) {
        return 0;
    }
    if (record->storage_fd >= 0) {
        return 0;
    }

    void* page_start = NULL;
    size_t page_length = record_page_range(record, &page_start);
    if (page_length == 0) {
        errno = EINVAL;
        return -1;
    }

    int fd = create_unlinked_backing_file(page_length);
    if (fd < 0) {
        return -1;
    }
    record->storage_fd = fd;
    record->storage_length = page_length;
    return 0;
}

static int record_chunk_bounds_locked(AllocationRecord* record, void* range_start,
                                      size_t range_length, uintptr_t* first_start,
                                      uintptr_t* final_end, size_t* first_index,
                                      size_t* end_index) {
    void* record_page_start_ptr = NULL;
    size_t record_page_length = record_page_range(record, &record_page_start_ptr);
    if (record_page_length == 0 || record->chunk_bytes == 0 ||
        record->chunk_count == 0 || range_length == 0) {
        return -1;
    }

    uintptr_t record_start = (uintptr_t)record_page_start_ptr;
    uintptr_t record_end = record_start + record_page_length;
    uintptr_t start = (uintptr_t)range_start;
    uintptr_t end = start + range_length;
    if (end < start) {
        return -1;
    }
    if (start < record_start) {
        start = record_start;
    }
    if (end > record_end) {
        end = record_end;
    }
    if (end <= start) {
        return -1;
    }

    size_t first = (size_t)((start - record_start) / record->chunk_bytes);
    size_t last_exclusive =
        (size_t)((end - record_start + record->chunk_bytes - 1) /
                 record->chunk_bytes);
    if (last_exclusive > record->chunk_count) {
        last_exclusive = record->chunk_count;
    }
    if (first >= last_exclusive) {
        return -1;
    }

    uintptr_t chunk_start = record_start + first * record->chunk_bytes;
    uintptr_t chunk_end = record_start + last_exclusive * record->chunk_bytes;
    if (chunk_end > record_end) {
        chunk_end = record_end;
    }

    *first_start = chunk_start;
    *final_end = chunk_end;
    *first_index = first;
    *end_index = last_exclusive;
    return 0;
}

static size_t uffd_record_chunk_length_locked(AllocationRecord* record,
                                             size_t index,
                                             uintptr_t* chunk_start_out) {
    void* page_start_ptr = NULL;
    size_t page_length = record_page_range(record, &page_start_ptr);
    if (page_length == 0 || index >= record->chunk_count) {
        return 0;
    }

    uintptr_t page_start = (uintptr_t)page_start_ptr;
    uintptr_t chunk_start = page_start + index * record->chunk_bytes;
    uintptr_t chunk_end = chunk_start + record->chunk_bytes;
    uintptr_t page_end = page_start + page_length;
    if (chunk_start >= page_end) {
        return 0;
    }
    if (chunk_end > page_end) {
        chunk_end = page_end;
    }
    *chunk_start_out = chunk_start;
    return (size_t)(chunk_end - chunk_start);
}

static int uffd_writeprotect_range(uintptr_t start, size_t length, int protect) {
    if (uffd_fd < 0 || length == 0) {
        return -1;
    }

    struct uffdio_writeprotect wp;
    memset(&wp, 0, sizeof(wp));
    wp.range.start = (unsigned long)start;
    wp.range.len = (unsigned long)length;
    wp.mode = protect ? UFFDIO_WRITEPROTECT_MODE_WP : 0;
    return ioctl(uffd_fd, UFFDIO_WRITEPROTECT, &wp);
}

static void insert_uffd_record_locked(AllocationRecord* record) {
    if (!record || record->uffd_prev || record->uffd_next ||
        uffd_head == record) {
        return;
    }
    record->uffd_prev = NULL;
    record->uffd_next = uffd_head;
    if (uffd_head) {
        uffd_head->uffd_prev = record;
    }
    uffd_head = record;
}

static void remove_uffd_record_locked(AllocationRecord* record) {
    if (!record || (!record->uffd_prev && !record->uffd_next &&
                    uffd_head != record)) {
        return;
    }
    if (record->uffd_prev) {
        record->uffd_prev->uffd_next = record->uffd_next;
    } else {
        uffd_head = record->uffd_next;
    }
    if (record->uffd_next) {
        record->uffd_next->uffd_prev = record->uffd_prev;
    }
    record->uffd_prev = NULL;
    record->uffd_next = NULL;
}

static AllocationRecord* find_uffd_record_containing_locked(uintptr_t start,
                                                            uintptr_t end) {
    for (AllocationRecord* record = uffd_head; record; record = record->uffd_next) {
        uintptr_t record_start;
        uintptr_t record_end;
        if (record_user_range_locked(record, &record_start, &record_end) != 0) {
            continue;
        }
        if (start >= record_start && end <= record_end) {
            return record;
        }
    }
    return NULL;
}

static int register_uffd_record(AllocationRecord* record) {
    if (!record || record->backend != BACKEND_UFFD_PAGER) {
        errno = EINVAL;
        return -1;
    }
    if (record->uffd_registered) {
        return 0;
    }
    if (uffd_fd < 0) {
        errno = ENOSYS;
        return -1;
    }
    if (parse_bool_env(getenv("MAI_UFFD_TEST_REGISTER_FAIL"))) {
        errno = EIO;
        return -1;
    }

    void* page_start = NULL;
    size_t page_length = record_page_range(record, &page_start);
    if (page_length == 0) {
        errno = EINVAL;
        return -1;
    }

    struct uffdio_register reg;
    memset(&reg, 0, sizeof(reg));
    reg.range.start = (unsigned long)page_start;
    reg.range.len = (unsigned long)page_length;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    if (ioctl(uffd_fd, UFFDIO_REGISTER, &reg) != 0) {
        return -1;
    }
    pthread_mutex_lock(&uffd_fault_lock);
    record->uffd_registered = 1;
    insert_uffd_record_locked(record);
    pthread_mutex_unlock(&uffd_fault_lock);
    return 0;
}

static uint64_t policy_next_random_locked(void) {
    uint64_t x = policy_random_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    policy_random_state = x ? x : 0x9e3779b97f4a7c15ULL;
    return policy_random_state * 2685821657736338717ULL;
}

static void policy_protect_chunk_index(MaiProtectedChunkSet* set,
                                       AllocationRecord* record,
                                       size_t index) {
    if (!set || !record) {
        return;
    }
    if (!set->record) {
        set->record = record;
    }
    if (set->record != record) {
        return;
    }
    for (size_t i = 0; i < set->count; i++) {
        if (set->indices[i] == index) {
            return;
        }
    }
    if (set->count < sizeof(set->indices) / sizeof(set->indices[0])) {
        set->indices[set->count++] = index;
    }
}

static int policy_chunk_is_protected(AllocationRecord* record, size_t index,
                                     const MaiProtectedChunkSet* set) {
    if (!set || record != set->record) {
        return 0;
    }
    for (size_t i = 0; i < set->count; i++) {
        if (set->indices[i] == index) {
            return 1;
        }
    }
    return 0;
}

static int policy_chunk_is_prefetched_unused(MaiChunkPolicyMeta* meta) {
    return meta &&
        (meta->flags & MAI_CHUNK_POLICY_PREFETCHED) != 0 &&
        (meta->flags & MAI_CHUNK_POLICY_PREFETCH_USED) == 0 &&
        (meta->flags & MAI_CHUNK_POLICY_DEMANDED) == 0;
}

static size_t policy_lfu_score_locked(MaiChunkPolicyMeta* meta) {
    if (!meta || meta->frequency == 0) {
        return 0;
    }
    size_t epoch = uffd_touch_epoch + 1;
    size_t last = meta->last_access_epoch;
    if (last == 0) {
        last = meta->first_resident_epoch;
    }
    if (last == 0) {
        last = meta->last_prefetch_epoch;
    }
    size_t age = last == 0 || epoch <= last ? 0 : epoch - last;
    size_t decay = age / 16;
    if (decay >= sizeof(size_t) * CHAR_BIT - 1) {
        return 1;
    }
    size_t score = meta->frequency >> decay;
    return score == 0 ? 1 : score;
}

static void policy_lfu_note_touch_locked(MaiChunkPolicyMeta* meta) {
    if (!meta) {
        return;
    }
    if (migration_policy == MIGRATION_POLICY_LFU) {
        meta->frequency = policy_lfu_score_locked(meta);
    }
    if (meta->frequency < SIZE_MAX) {
        meta->frequency++;
    }
}

static int policy_lfu_candidate_class(MaiChunkPolicyMeta* meta) {
    if (policy_chunk_is_prefetched_unused(meta) ||
        (meta && (meta->flags & MAI_CHUNK_POLICY_PROBATION) != 0 &&
         (meta->flags & MAI_CHUNK_POLICY_PREFETCH_USED) == 0)) {
        return 0;
    }
    return 1;
}

static int policy_index_add(size_t index, ptrdiff_t delta, size_t limit,
                            size_t* out) {
    if (delta >= 0) {
        size_t step = (size_t)delta;
        if (index > SIZE_MAX - step || index + step >= limit) {
            return 0;
        }
        *out = index + step;
        return 1;
    }

    if (delta == PTRDIFF_MIN) {
        return 0;
    }
    size_t step = (size_t)(-delta);
    if (index < step) {
        return 0;
    }
    *out = index - step;
    return 1;
}

static void policy_update_stream_slots_locked(AllocationRecord* record,
                                              size_t index) {
    if (!record) {
        return;
    }

    ptrdiff_t observed_delta = 0;
    int has_delta = 0;
    size_t epoch = uffd_touch_epoch + 1;
    if (record->policy_has_last_fault) {
        observed_delta =
            (ptrdiff_t)index - (ptrdiff_t)record->policy_last_fault_index;
        has_delta = observed_delta != 0;
    }

    int matched = -1;
    if (has_delta) {
        for (size_t i = 0; i < MAI_POLICY_STREAM_SLOTS; i++) {
            MaiStreamPolicySlot* slot = &record->policy_stream_slots[i];
            size_t predicted = 0;
            if (slot->active && slot->delta != 0 &&
                policy_index_add(slot->last_index, slot->delta,
                                 record->chunk_count, &predicted) &&
                predicted == index) {
                matched = (int)i;
                break;
            }
        }
    }

    if (matched >= 0) {
        MaiStreamPolicySlot* slot =
            &record->policy_stream_slots[(size_t)matched];
        slot->last_index = index;
        if (slot->confidence < SIZE_MAX) {
            slot->confidence++;
        }
        slot->last_epoch = epoch;
    } else if (has_delta) {
        size_t victim = 0;
        for (size_t i = 0; i < MAI_POLICY_STREAM_SLOTS; i++) {
            MaiStreamPolicySlot* slot = &record->policy_stream_slots[i];
            if (!slot->active) {
                victim = i;
                break;
            }
            MaiStreamPolicySlot* current = &record->policy_stream_slots[victim];
            if (slot->confidence < current->confidence ||
                (slot->confidence == current->confidence &&
                 slot->last_epoch < current->last_epoch)) {
                victim = i;
            }
        }
        MaiStreamPolicySlot* slot = &record->policy_stream_slots[victim];
        slot->active = 1;
        slot->last_index = index;
        slot->delta = observed_delta;
        slot->confidence = 1;
        slot->last_epoch = epoch;
    }

    if (record->policy_has_last_fault) {
        if (observed_delta == record->policy_last_delta) {
            record->policy_run_length++;
        } else {
            record->policy_run_length = 1;
        }
        record->policy_last_delta = observed_delta;
    } else {
        record->policy_has_last_fault = 1;
        record->policy_run_length = 1;
        record->policy_last_delta = 0;
    }
    record->policy_last_fault_index = index;
}

static void policy_note_demand_fault_locked(AllocationRecord* record,
                                            size_t index) {
    if (!record || index >= record->chunk_count) {
        return;
    }

    policy_update_stream_slots_locked(record, index);
    if (!record->chunk_policy_meta) {
        return;
    }
    MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
    meta->last_delta = record->policy_last_delta;
    meta->flags |= MAI_CHUNK_POLICY_DEMANDED | MAI_CHUNK_POLICY_REFERENCED;
    policy_lfu_note_touch_locked(meta);
    meta->last_access_epoch = uffd_touch_epoch + 1;
}

static size_t policy_prefetch_window_locked(AllocationRecord* record,
                                            size_t index) {
    (void)index;
    size_t base = uffd_prefetch_chunks == 0 ? 1 : uffd_prefetch_chunks;
    if (migration_policy != MIGRATION_POLICY_STREAM) {
        return base;
    }

    if (!record || !record->policy_has_last_fault ||
        record->policy_last_delta != 1 || record->policy_run_length < 2) {
        return 1;
    }
    size_t adaptive = record->policy_run_length + 1;
    if (adaptive > base) {
        adaptive = base;
    }
    if (adaptive < 2) {
        adaptive = 2;
    }
    record->policy_prefetch_window = adaptive;
    return adaptive;
}

static int policy_choose_uffd_victim_locked(AllocationRecord** out_record,
                                            size_t* out_index,
                                            const MaiProtectedChunkSet* protected_set);

static size_t policy_build_prefetch_indices_locked(AllocationRecord* record,
                                                   size_t index,
                                                   size_t prefetch_window,
                                                   size_t* out,
                                                   size_t out_cap) {
    if (!record || !out || out_cap == 0 || prefetch_window <= 1) {
        return 0;
    }

    size_t limit = prefetch_window - 1;
    if (limit > out_cap) {
        limit = out_cap;
    }

    if (migration_policy == MIGRATION_POLICY_STRIDE) {
        MaiStreamPolicySlot* best = NULL;
        for (size_t i = 0; i < MAI_POLICY_STREAM_SLOTS; i++) {
            MaiStreamPolicySlot* slot = &record->policy_stream_slots[i];
            if (!slot->active || slot->last_index != index ||
                slot->delta == 0 || slot->confidence < 2) {
                continue;
            }
            if (!best || slot->confidence > best->confidence ||
                (slot->confidence == best->confidence &&
                 slot->last_epoch > best->last_epoch)) {
                best = slot;
            }
        }
        if (!best) {
            return 0;
        }

        size_t count = 0;
        size_t current = index;
        while (count < limit &&
               policy_index_add(current, best->delta,
                                record->chunk_count, &current)) {
            out[count++] = current;
        }
        return count;
    }

    size_t count = 0;
    for (size_t offset = 1;
         count < limit && index + offset < record->chunk_count;
         offset++) {
        out[count++] = index + offset;
    }
    return count;
}

static int policy_admit_prefetch_locked(AllocationRecord* record, size_t index,
                                        size_t length) {
    if (!record || index >= record->chunk_count) {
        return 0;
    }
    stats_snapshot.policy_prefetch_requests++;
    stats_snapshot.policy_admission_requests++;

    int admit = 1;
    if (migration_policy == MIGRATION_POLICY_2Q &&
        uffd_resident_limit_bytes != 0 &&
        uffd_resident_bytes + length > uffd_resident_limit_bytes) {
        admit = 0;
    } else if (migration_policy == MIGRATION_POLICY_LFU &&
               uffd_resident_limit_bytes != 0 &&
               uffd_resident_bytes + length > uffd_resident_limit_bytes) {
        MaiChunkPolicyMeta* candidate = record->chunk_policy_meta ?
            &record->chunk_policy_meta[index] : NULL;
        size_t candidate_score = policy_lfu_score_locked(candidate);
        AllocationRecord* victim_record = NULL;
        size_t victim_index = 0;
        if (policy_choose_uffd_victim_locked(&victim_record, &victim_index,
                                             NULL) &&
            victim_record && victim_record->chunk_policy_meta) {
            MaiChunkPolicyMeta* victim =
                &victim_record->chunk_policy_meta[victim_index];
            int victim_class = policy_lfu_candidate_class(victim);
            size_t victim_score = policy_lfu_score_locked(victim);
            if (candidate_score > victim_score ||
                (candidate_score == victim_score && victim_class == 0)) {
                admit = 1;
            } else {
                admit = 0;
            }
        } else {
            admit = candidate_score > 0;
        }
    }
    if (!admit) {
        stats_snapshot.policy_admission_rejected++;
        return 0;
    }

    stats_snapshot.policy_prefetch_admitted++;
    if (record->chunk_policy_meta) {
        MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
        meta->flags |= MAI_CHUNK_POLICY_PREFETCHED |
            MAI_CHUNK_POLICY_PROBATION;
        meta->last_prefetch_epoch = uffd_touch_epoch + 1;
        meta->confidence = record->policy_run_length > UINT16_MAX ?
            UINT16_MAX : (uint16_t)record->policy_run_length;
    }
    return 1;
}

static void policy_note_populate_locked(AllocationRecord* record, size_t index,
                                        int demand, int had_storage,
                                        size_t length) {
    if (had_storage) {
        stats_snapshot.policy_migration_read_bytes += length;
    }
    stats_snapshot.policy_promotions++;

    if (!record || index >= record->chunk_count ||
        !record->chunk_policy_meta) {
        if (demand) {
            stats_snapshot.policy_demand_faults++;
        } else {
            stats_snapshot.policy_prefetch_completed++;
            stats_snapshot.policy_prefetch_bytes += length;
        }
        return;
    }

    MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
    meta->first_resident_epoch = uffd_touch_epoch + 1;
    meta->last_access_epoch = uffd_touch_epoch + 1;
    meta->flags |= MAI_CHUNK_POLICY_REFERENCED;

    if (demand) {
        stats_snapshot.policy_demand_faults++;
        if ((meta->flags & MAI_CHUNK_POLICY_PREFETCHED) != 0 &&
            (meta->flags & MAI_CHUNK_POLICY_PREFETCH_USED) == 0) {
            meta->flags |= MAI_CHUNK_POLICY_PREFETCH_USED |
                MAI_CHUNK_POLICY_PROTECTED;
            meta->flags &= ~MAI_CHUNK_POLICY_PROBATION;
            stats_snapshot.policy_prefetch_useful++;
            stats_snapshot.policy_prefetch_useful_bytes += length;
        } else if ((meta->flags & MAI_CHUNK_POLICY_PREFETCHED) == 0) {
            stats_snapshot.policy_prefetch_late++;
        }
    } else {
        meta->flags |= MAI_CHUNK_POLICY_PREFETCHED |
            MAI_CHUNK_POLICY_PROBATION;
        meta->last_prefetch_epoch = uffd_touch_epoch + 1;
        stats_snapshot.policy_prefetch_completed++;
        stats_snapshot.policy_prefetch_bytes += length;
    }
}

static void policy_note_resident_demand_locked(AllocationRecord* record,
                                               size_t index,
                                               size_t length) {
    if (!record || index >= record->chunk_count) {
        stats_snapshot.policy_demand_faults++;
        return;
    }
    policy_update_stream_slots_locked(record, index);
    if (!record->chunk_policy_meta) {
        stats_snapshot.policy_demand_faults++;
        return;
    }
    MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
    if ((meta->flags & MAI_CHUNK_POLICY_PREFETCHED) != 0 &&
        (meta->flags & MAI_CHUNK_POLICY_PREFETCH_USED) == 0) {
        meta->flags |= MAI_CHUNK_POLICY_PREFETCH_USED |
            MAI_CHUNK_POLICY_PROTECTED;
        meta->flags &= ~MAI_CHUNK_POLICY_PROBATION;
        stats_snapshot.policy_prefetch_useful++;
        stats_snapshot.policy_prefetch_useful_bytes += length;
    }
    meta->flags |= MAI_CHUNK_POLICY_DEMANDED | MAI_CHUNK_POLICY_REFERENCED;
    policy_lfu_note_touch_locked(meta);
    meta->last_access_epoch = uffd_touch_epoch + 1;
    stats_snapshot.policy_demand_faults++;
}

static void policy_note_evict_locked(AllocationRecord* record, size_t index,
                                     size_t length) {
    stats_snapshot.policy_demotions++;
    stats_snapshot.policy_migration_write_bytes += length;
    if (!record || index >= record->chunk_count ||
        !record->chunk_policy_meta) {
        return;
    }
    MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
    if (policy_chunk_is_prefetched_unused(meta)) {
        stats_snapshot.policy_prefetch_unused_evictions++;
        stats_snapshot.policy_prefetch_unused_evicted_bytes += length;
    } else if ((meta->flags & MAI_CHUNK_POLICY_DEMANDED) != 0 ||
               meta->frequency > 1) {
        stats_snapshot.policy_evicted_hot_bytes += length;
    }
    size_t ghost_frequency = 0;
    if (migration_policy == MIGRATION_POLICY_LFU) {
        ghost_frequency = policy_lfu_score_locked(meta);
    }
    memset(meta, 0, sizeof(*meta));
    if (ghost_frequency != 0) {
        meta->frequency = ghost_frequency;
        meta->last_access_epoch = uffd_touch_epoch + 1;
    }
}

static void policy_note_evict_runtime_locked(AllocationRecord* record,
                                             size_t index, size_t length) {
    pthread_mutex_lock(&uffd_fault_lock);
    policy_note_evict_locked(record, index, length);
    pthread_mutex_unlock(&uffd_fault_lock);
}

static void policy_note_promote_runtime_locked(AllocationRecord* record,
                                               size_t index, size_t length,
                                               int counted_read) {
    pthread_mutex_lock(&uffd_fault_lock);
    if (counted_read) {
        stats_snapshot.policy_migration_read_bytes += length;
    }
    stats_snapshot.policy_promotions++;
    pthread_mutex_unlock(&uffd_fault_lock);

    if (!record || index >= record->chunk_count ||
        !record->chunk_policy_meta) {
        return;
    }
    MaiChunkPolicyMeta* meta = &record->chunk_policy_meta[index];
    meta->flags |= MAI_CHUNK_POLICY_DEMANDED |
        MAI_CHUNK_POLICY_PROTECTED | MAI_CHUNK_POLICY_REFERENCED;
    policy_lfu_note_touch_locked(meta);
    meta->last_access_epoch = reclaim_epoch + 1;
    meta->first_resident_epoch = meta->last_access_epoch;
}

static size_t policy_stall_bucket(size_t ns) {
    size_t bucket = 0;
    while (ns > 1 && bucket + 1 < MAI_POLICY_STALL_HIST_BUCKETS) {
        ns >>= 1;
        bucket++;
    }
    return bucket;
}

static size_t policy_stall_bucket_upper_ns(size_t bucket) {
    if (bucket >= sizeof(size_t) * CHAR_BIT - 1) {
        return SIZE_MAX;
    }
    return ((size_t)1) << bucket;
}

static size_t policy_stall_percentile_locked(size_t percentile) {
    size_t samples = stats_snapshot.policy_demand_fault_stall_samples;
    if (samples == 0) {
        return 0;
    }
    size_t rank = (samples / 100) * percentile +
        ((samples % 100) * percentile + 99) / 100;
    if (rank == 0) {
        rank = 1;
    }
    size_t cumulative = 0;
    for (size_t i = 0; i < MAI_POLICY_STALL_HIST_BUCKETS; i++) {
        cumulative += policy_fault_stall_hist[i];
        if (cumulative >= rank) {
            return policy_stall_bucket_upper_ns(i);
        }
    }
    return policy_fault_stall_max_ns;
}

static void policy_note_fault_handler_stall_locked(size_t ns) {
    stats_snapshot.policy_demand_fault_stall_ns += ns;
    stats_snapshot.policy_demand_fault_stall_samples++;
    if (ns > policy_fault_stall_max_ns) {
        policy_fault_stall_max_ns = ns;
    }
    policy_fault_stall_hist[policy_stall_bucket(ns)]++;
}

static int policy_choose_uffd_victim_locked(AllocationRecord** out_record,
                                            size_t* out_index,
                                            const MaiProtectedChunkSet* protected_set) {
    AllocationRecord* best_record = NULL;
    size_t best_index = 0;
    size_t best_epoch = SIZE_MAX;
    size_t best_score = SIZE_MAX;
    int best_class = 2;
    size_t candidates_seen = 0;

    for (AllocationRecord* record = uffd_head; record; record = record->uffd_next) {
        if (record->backend != BACKEND_UFFD_PAGER || record->uffd_closing ||
            !record->chunk_states ||
            !record->chunk_touch_epochs || !record->uffd_registered) {
            continue;
        }

        for (size_t i = 0; i < record->chunk_count; i++) {
            if (policy_chunk_is_protected(record, i, protected_set) ||
                record->chunk_states[i] != CHUNK_ANON_HOT) {
                continue;
            }

            MaiChunkPolicyMeta* meta = record->chunk_policy_meta ?
                &record->chunk_policy_meta[i] : NULL;
            size_t epoch = record->chunk_touch_epochs[i];
            if (epoch == 0 && meta && meta->first_resident_epoch != 0) {
                epoch = meta->first_resident_epoch;
            }

            if (migration_policy == MIGRATION_POLICY_RANDOM) {
                candidates_seen++;
                if ((policy_next_random_locked() % candidates_seen) == 0) {
                    best_record = record;
                    best_index = i;
                }
                continue;
            }

            if (migration_policy == MIGRATION_POLICY_CLOCK && meta &&
                (meta->flags & MAI_CHUNK_POLICY_REFERENCED) != 0) {
                meta->flags &= ~MAI_CHUNK_POLICY_REFERENCED;
                continue;
            }

            int candidate_class =
                (migration_policy == MIGRATION_POLICY_LFU) ?
                policy_lfu_candidate_class(meta) :
                ((migration_policy != MIGRATION_POLICY_LEGACY &&
                  policy_chunk_is_prefetched_unused(meta)) ? 0 : 1);
            size_t candidate_score =
                migration_policy == MIGRATION_POLICY_LFU ?
                policy_lfu_score_locked(meta) : 0;
            if (migration_policy == MIGRATION_POLICY_FIFO && meta &&
                meta->first_resident_epoch != 0) {
                epoch = meta->first_resident_epoch;
            }
            if (!best_record || candidate_class < best_class ||
                (candidate_class == best_class &&
                 migration_policy == MIGRATION_POLICY_LFU &&
                 candidate_score < best_score) ||
                (candidate_class == best_class &&
                 candidate_score == best_score && epoch < best_epoch)) {
                best_record = record;
                best_index = i;
                best_epoch = epoch;
                best_score = candidate_score;
                best_class = candidate_class;
            }
        }
    }

    if (!best_record && migration_policy == MIGRATION_POLICY_CLOCK) {
        for (AllocationRecord* record = uffd_head; record; record = record->uffd_next) {
            if (record->backend != BACKEND_UFFD_PAGER || record->uffd_closing ||
                !record->chunk_states ||
                !record->chunk_touch_epochs || !record->uffd_registered) {
                continue;
            }
            for (size_t i = 0; i < record->chunk_count; i++) {
                if (policy_chunk_is_protected(record, i, protected_set) ||
                    record->chunk_states[i] != CHUNK_ANON_HOT) {
                    continue;
                }
                size_t epoch = record->chunk_touch_epochs[i];
                if (!best_record || epoch < best_epoch) {
                    best_record = record;
                    best_index = i;
                    best_epoch = epoch;
                }
            }
        }
    }

    if (!best_record) {
        return 0;
    }
    *out_record = best_record;
    *out_index = best_index;
    return 1;
}

static int evict_uffd_chunk_locked(AllocationRecord* record, size_t index,
                                   int runtime_lock_held) {
    uintptr_t start = 0;
    size_t length = uffd_record_chunk_length_locked(record, index, &start);
    if (length == 0 || !record->chunk_states ||
        record->chunk_states[index] == CHUNK_FILE_COLD) {
        return 0;
    }
    if (runtime_lock_held && range_overlaps_exclusion_locked(start, start + length)) {
        return 0;
    }
    if (ensure_record_storage_locked(record) != 0) {
        return -1;
    }

    if (uffd_writeprotect_range(start, length, 1) != 0) {
        return -1;
    }

    void* page_start_ptr = NULL;
    size_t page_length = record_page_range(record, &page_start_ptr);
    if (page_length == 0) {
        (void)uffd_writeprotect_range(start, length, 0);
        return -1;
    }
    off_t offset = (off_t)(start - (uintptr_t)page_start_ptr);
    int rc = write_all_at(record->storage_fd, (void*)start, length, offset);
    if (rc == 0 && madvise((void*)start, length, MADV_DONTNEED) != 0) {
        rc = -1;
    }
    (void)uffd_writeprotect_range(start, length, 0);
    if (rc != 0) {
        return -1;
    }

    policy_note_evict_locked(record, index, length);
    record->chunk_states[index] = CHUNK_FILE_COLD;
    if (record->chunk_has_storage) {
        record->chunk_has_storage[index] = 1;
    }
    if (record->resident_bytes >= length) {
        record->resident_bytes -= length;
    } else {
        record->resident_bytes = 0;
    }
    if (uffd_resident_bytes >= length) {
        uffd_resident_bytes -= length;
    } else {
        uffd_resident_bytes = 0;
    }
    stats_snapshot.uffd_evictions++;
    stats_snapshot.uffd_resident_bytes = uffd_resident_bytes;
    return 0;
}

static int evict_uffd_chunks_locked(size_t target_bytes,
                                    const MaiProtectedChunkSet* protected_set,
                                    int runtime_lock_held) {
    while (uffd_resident_bytes > target_bytes) {
        AllocationRecord* best_record = NULL;
        size_t best_index = 0;
        if (!policy_choose_uffd_victim_locked(&best_record, &best_index,
                                              protected_set)) {
            break;
        }
        if (evict_uffd_chunk_locked(best_record, best_index,
                                    runtime_lock_held) != 0) {
            return -1;
        }
    }
    return 0;
}

static int ensure_uffd_scratch_locked(size_t length, void** out) {
    if (length == 0) {
        errno = EINVAL;
        return -1;
    }
    if (uffd_scratch_buffer && uffd_scratch_length >= length) {
        *out = uffd_scratch_buffer;
        return 0;
    }
    if (uffd_scratch_buffer) {
        munmap(uffd_scratch_buffer, uffd_scratch_length);
        uffd_scratch_buffer = NULL;
        uffd_scratch_length = 0;
    }
    void* scratch = mmap(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) {
        return -1;
    }
    uffd_scratch_buffer = scratch;
    uffd_scratch_length = length;
    *out = scratch;
    return 0;
}

static void release_uffd_scratch_locked(void) {
    if (uffd_scratch_buffer) {
        munmap(uffd_scratch_buffer, uffd_scratch_length);
        uffd_scratch_buffer = NULL;
        uffd_scratch_length = 0;
    }
}

static int populate_uffd_chunk_locked(AllocationRecord* record, size_t index,
                                      int count_fault_event,
                                      size_t* populated_bytes) {
    if (!record || record->backend != BACKEND_UFFD_PAGER ||
        !record->chunk_states || index >= record->chunk_count) {
        errno = EINVAL;
        return -1;
    }

    uintptr_t chunk_start = 0;
    size_t length = uffd_record_chunk_length_locked(record, index, &chunk_start);
    if (length == 0) {
        errno = EINVAL;
        return -1;
    }

    if (record->chunk_states[index] == CHUNK_ANON_HOT) {
        if (count_fault_event) {
            policy_note_resident_demand_locked(record, index, length);
            record->chunk_touch_epochs[index] = ++uffd_touch_epoch;
            stats_snapshot.uffd_faults++;
        }
        return 0;
    }

    int has_storage = record->chunk_states[index] == CHUNK_FILE_COLD &&
        record->chunk_has_storage && record->chunk_has_storage[index];
    if (has_storage) {
        void* temp = NULL;
        if (ensure_uffd_scratch_locked(length, &temp) != 0) {
            return -1;
        }

        void* page_start_ptr = NULL;
        size_t page_length = record_page_range(record, &page_start_ptr);
        if (page_length == 0) {
            errno = EINVAL;
            return -1;
        }
        off_t offset = (off_t)(chunk_start - (uintptr_t)page_start_ptr);
        if (read_all_at(record->storage_fd, temp, length, offset) != 0) {
            return -1;
        }

        struct uffdio_copy copy;
        memset(&copy, 0, sizeof(copy));
        copy.dst = (unsigned long)chunk_start;
        copy.src = (unsigned long)temp;
        copy.len = (unsigned long)length;
        if (ioctl(uffd_fd, UFFDIO_COPY, &copy) != 0) {
            return -1;
        }
    } else {
        struct uffdio_zeropage zero;
        memset(&zero, 0, sizeof(zero));
        zero.range.start = (unsigned long)chunk_start;
        zero.range.len = (unsigned long)length;
        if (ioctl(uffd_fd, UFFDIO_ZEROPAGE, &zero) != 0) {
            return -1;
        }
    }

    if (record->chunk_states[index] == CHUNK_FILE_COLD) {
        record->chunk_states[index] = CHUNK_ANON_HOT;
        record->resident_bytes += length;
        uffd_resident_bytes += length;
        if (populated_bytes) {
            *populated_bytes += length;
        }
        policy_note_populate_locked(record, index, count_fault_event,
                                    has_storage, length);
        if (policy_observe_prefetch_writes &&
            (!count_fault_event || migration_policy == MIGRATION_POLICY_LFU)) {
            (void)uffd_writeprotect_range(chunk_start, length, 1);
        }
    }
    record->chunk_touch_epochs[index] = ++uffd_touch_epoch;
    if (count_fault_event) {
        stats_snapshot.uffd_faults++;
    }
    stats_snapshot.uffd_resident_bytes = uffd_resident_bytes;
    return 0;
}

static int policy_prefetch_and_reclaim_after_access_locked(AllocationRecord* record,
                                                           size_t index,
                                                           int runtime_lock_held) {
    MaiProtectedChunkSet protected_set = {0};
    policy_protect_chunk_index(&protected_set, record, index);
    size_t prefetch_window = policy_prefetch_window_locked(record, index);
    if (record->chunk_bytes != 0 && uffd_resident_limit_bytes != 0) {
        size_t cap_window = (uffd_resident_limit_bytes / 2) / record->chunk_bytes;
        if (cap_window == 0) {
            cap_window = 1;
        }
        if (prefetch_window > cap_window) {
            prefetch_window = cap_window;
        }
    }
    size_t prefetch_indices[MAI_MAX_UFFD_PREFETCH_CHUNKS];
    size_t prefetch_count =
        policy_build_prefetch_indices_locked(record, index, prefetch_window,
                                             prefetch_indices,
                                             MAI_MAX_UFFD_PREFETCH_CHUNKS);
    for (size_t candidate = 0; candidate < prefetch_count; candidate++) {
        size_t prefetch_index = prefetch_indices[candidate];
        if (record->chunk_states[prefetch_index] == CHUNK_ANON_HOT) {
            policy_protect_chunk_index(&protected_set, record, prefetch_index);
            continue;
        }
        uintptr_t prefetch_start = 0;
        size_t prefetch_length =
            uffd_record_chunk_length_locked(record, prefetch_index,
                                            &prefetch_start);
        if (prefetch_length == 0 ||
            !policy_admit_prefetch_locked(record, prefetch_index,
                                          prefetch_length)) {
            continue;
        }
        if (populate_uffd_chunk_locked(record, prefetch_index, 0, NULL) != 0) {
            break;
        }
        policy_protect_chunk_index(&protected_set, record, prefetch_index);
    }

    int explicit_resident_limit = uffd_resident_limit_bytes != 0;
    size_t target = uffd_resident_limit_bytes;
    if (target == 0 && runtime_lock_held) {
        size_t cap = effective_max_rss_locked(stats_snapshot.current_rss_bytes);
        target = cap == 0 ? SIZE_MAX : percent_of_size(cap, MAI_AUTO_ANON_LIMIT_PERCENT);
    } else if (target == 0) {
        target = SIZE_MAX;
    }
    if ((explicit_resident_limit || runtime_lock_held) &&
        target != SIZE_MAX && uffd_resident_bytes > target) {
        size_t low_target = uffd_resident_low_limit_bytes;
        if (low_target == 0) {
            low_target = target;
        }
        if (low_target > target) {
            low_target = target;
        }
        if (evict_uffd_chunks_locked(low_target, &protected_set,
                                     runtime_lock_held) != 0) {
            return -1;
        }
    }
    return 0;
}

static int resolve_uffd_fault_locked(uintptr_t fault_address,
                                     unsigned long long flags,
                                     int runtime_lock_held) {
    uintptr_t page = fault_address & ~((uintptr_t)page_size - 1);
    AllocationRecord* record =
        find_uffd_record_containing_locked(page, page + 1);
    if (!record || record->backend != BACKEND_UFFD_PAGER) {
        struct uffdio_zeropage zero;
        memset(&zero, 0, sizeof(zero));
        zero.range.start = (unsigned long)page;
        zero.range.len = (unsigned long)page_size;
        if (ioctl(uffd_fd, UFFDIO_ZEROPAGE, &zero) == 0) {
            return 0;
        }
        if (errno == EINVAL || errno == ENOENT || errno == ESRCH) {
            return 0;
        }
        return -1;
    }

    uintptr_t chunk_start = 0;
    uintptr_t chunk_end = 0;
    size_t index = 0;
    size_t end_index = 0;
    if (record_chunk_bounds_locked(record, (void*)page, page_size,
                                   &chunk_start, &chunk_end,
                                   &index, &end_index) != 0 ||
        index >= record->chunk_count) {
        return -1;
    }
    size_t length = (size_t)(chunk_end - chunk_start);
    if (length == 0) {
        return -1;
    }
    if (flags & UFFD_PAGEFAULT_FLAG_WP) {
        if (uffd_writeprotect_range(chunk_start, length, 0) != 0) {
            return -1;
        }
        policy_note_resident_demand_locked(record, index, length);
        record->chunk_touch_epochs[index] = ++uffd_touch_epoch;
        stats_snapshot.uffd_faults++;
        return policy_prefetch_and_reclaim_after_access_locked(
            record, index, runtime_lock_held);
    }
    policy_note_demand_fault_locked(record, index);
    if (populate_uffd_chunk_locked(record, index, 1, NULL) != 0) {
        return -1;
    }
    return policy_prefetch_and_reclaim_after_access_locked(
        record, index, runtime_lock_held);
}

static void fail_uffd_pager_locked(void) {
    stats_snapshot.uffd_fallbacks++;
    atomic_store_explicit(&uffd_thread_stop, 1, memory_order_release);
    if (uffd_fd >= 0) {
        int fd = uffd_fd;
        uffd_fd = -1;
        close(fd);
    }
}

static void* uffd_pager_main(void* arg) {
    (void)arg;
    for (;;) {
        if (atomic_load_explicit(&uffd_thread_stop, memory_order_acquire) != 0) {
            return NULL;
        }
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = uffd_fd;
        pfd.events = POLLIN;
        int prc = poll(&pfd, 1, 100);
        if (prc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NULL;
        }
        if (prc == 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        for (;;) {
            struct uffd_msg msg;
            ssize_t nread = read(uffd_fd, &msg, sizeof(msg));
            if (nread < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    break;
                }
                return NULL;
            }
            if (nread == 0) {
                return NULL;
            }
            if ((size_t)nread != sizeof(msg) || msg.event != UFFD_EVENT_PAGEFAULT) {
                continue;
            }
            int runtime_lock_held = 0;
            pthread_mutex_lock(&uffd_fault_lock);
            uint64_t fault_start_ns = monotonic_time_ns_signal_safe();
            int rc = resolve_uffd_fault_locked(
                (uintptr_t)msg.arg.pagefault.address,
                msg.arg.pagefault.flags,
                runtime_lock_held);
            uint64_t fault_end_ns = monotonic_time_ns_signal_safe();
            if (fault_start_ns != 0 && fault_end_ns >= fault_start_ns) {
                policy_note_fault_handler_stall_locked(
                    (size_t)(fault_end_ns - fault_start_ns));
            }
            if (rc != 0) {
                fail_uffd_pager_locked();
            }
            pthread_mutex_unlock(&uffd_fault_lock);
            if (rc != 0) {
                kill(getpid(), SIGBUS);
                return NULL;
            }
        }
    }
}

static int open_uffd_pager_fd(void) {
    int fd = (int)syscall(SYS_userfaultfd,
                          O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    if (fd < 0) {
        return -1;
    }
    struct uffdio_api api;
    memset(&api, 0, sizeof(api));
    api.api = UFFD_API;
    api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
    if (ioctl(fd, UFFDIO_API, &api) != 0 ||
        !(api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int ensure_uffd_pager_started_locked(void) {
    if (uffd_fd >= 0 && uffd_thread_started) {
        return 0;
    }
    if (!uffd_pager_available) {
        errno = ENOSYS;
        return -1;
    }
    uffd_fd = open_uffd_pager_fd();
    if (uffd_fd < 0) {
        uffd_pager_available = 0;
        stats_snapshot.uffd_pager_available = 0;
        pthread_mutex_lock(&uffd_fault_lock);
        stats_snapshot.uffd_fallbacks++;
        pthread_mutex_unlock(&uffd_fault_lock);
        return -1;
    }
    atomic_store_explicit(&uffd_thread_stop, 0, memory_order_release);
    if (pthread_create(&uffd_thread, NULL, uffd_pager_main, NULL) != 0) {
        close(uffd_fd);
        uffd_fd = -1;
        pthread_mutex_lock(&uffd_fault_lock);
        stats_snapshot.uffd_fallbacks++;
        pthread_mutex_unlock(&uffd_fault_lock);
        return -1;
    }
    uffd_thread_started = 1;
    return 0;
}

static void stop_uffd_pager(void) {
    if (!uffd_thread_started) {
        if (uffd_fd >= 0) {
            close(uffd_fd);
            uffd_fd = -1;
        }
        return;
    }
    atomic_store_explicit(&uffd_thread_stop, 1, memory_order_release);
    (void)pthread_join(uffd_thread, NULL);
    uffd_thread_started = 0;
    if (uffd_fd >= 0) {
        close(uffd_fd);
        uffd_fd = -1;
    }
    pthread_mutex_lock(&uffd_fault_lock);
    uffd_head = NULL;
    release_uffd_scratch_locked();
    pthread_mutex_unlock(&uffd_fault_lock);
}

static int migrate_anon_range_to_file_locked(AllocationRecord* record,
                                             void* range_start,
                                             size_t range_length,
                                             ReclaimPolicy policy,
                                             size_t account_bytes) {
    uintptr_t chunk_start;
    uintptr_t chunk_end;
    size_t first_index;
    size_t end_index;
    void* record_page_start_ptr = NULL;
    size_t record_page_length;

    if (record->backend != BACKEND_ANON) {
        return 0;
    }
    if (record_chunk_bounds_locked(record, range_start, range_length,
                                   &chunk_start, &chunk_end, &first_index,
                                   &end_index) != 0) {
        return 0;
    }
    if (ensure_record_storage_locked(record) != 0) {
        return -1;
    }

    record_page_length = record_page_range(record, &record_page_start_ptr);
    if (record_page_length == 0) {
        return -1;
    }
    uintptr_t record_start = (uintptr_t)record_page_start_ptr;

    stop_record_access_trace_locked(record);

    size_t migrated = 0;
    for (size_t i = first_index; i < end_index; i++) {
        if (record->chunk_states && record->chunk_states[i] == CHUNK_FILE_COLD) {
            continue;
        }

        uintptr_t start = record_start + i * record->chunk_bytes;
        uintptr_t end = start + record->chunk_bytes;
        if (end > record_start + record_page_length) {
            end = record_start + record_page_length;
        }
        size_t length = (size_t)(end - start);
        off_t offset = (off_t)(start - record_start);

        if (write_all_at(record->storage_fd, (void*)start, length, offset) != 0) {
            return -1;
        }

        void* mapped = mmap((void*)start, length, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_FIXED, record->storage_fd, offset);
        if (mapped == MAP_FAILED || mapped != (void*)start) {
            return -1;
        }

        if (record->chunk_states) {
            policy_note_evict_runtime_locked(record, i, length);
            record->chunk_states[i] = CHUNK_FILE_COLD;
        }
        migrated += length;

        int advice = MADV_DONTNEED;
#ifdef MADV_PAGEOUT
        if (policy == RECLAIM_PAGEOUT) {
            advice = MADV_PAGEOUT;
        }
#else
        (void)policy;
#endif
        if (madvise((void*)start, length, advice) != 0) {
#ifdef MADV_PAGEOUT
            if (advice == MADV_PAGEOUT) {
                (void)madvise((void*)start, length, MADV_DONTNEED);
            }
#endif
        }
    }

    record->reclaim_epoch = reclaim_epoch;
    if (migrated != 0) {
        stats_snapshot.migrated_to_file_bytes += migrated;
        stats_snapshot.reclaimed_bytes += account_bytes;
    }
    return 0;
}

static int promote_record_range_to_anon_locked(AllocationRecord* record,
                                               void* range_start,
                                               size_t range_length) {
    uintptr_t chunk_start;
    uintptr_t chunk_end;
    size_t first_index;
    size_t end_index;
    void* record_page_start_ptr = NULL;
    size_t record_page_length;

    if (record->backend != BACKEND_ANON || !record->chunk_states) {
        return 0;
    }
    if (record_chunk_bounds_locked(record, range_start, range_length,
                                   &chunk_start, &chunk_end, &first_index,
                                   &end_index) != 0) {
        return 0;
    }

    record_page_length = record_page_range(record, &record_page_start_ptr);
    if (record_page_length == 0) {
        return -1;
    }
    uintptr_t record_start = (uintptr_t)record_page_start_ptr;

    stop_record_access_trace_locked(record);

    size_t promoted = 0;
    for (size_t i = first_index; i < end_index; i++) {
        if (record->chunk_states[i] != CHUNK_FILE_COLD) {
            continue;
        }

        uintptr_t start = record_start + i * record->chunk_bytes;
        uintptr_t end = start + record->chunk_bytes;
        if (end > record_start + record_page_length) {
            end = record_start + record_page_length;
        }
        size_t length = (size_t)(end - start);
        void* temp = mmap(NULL, length, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (temp == MAP_FAILED) {
            return -1;
        }
        memcpy(temp, (void*)start, length);

        void* mapped = mmap((void*)start, length, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == MAP_FAILED || mapped != (void*)start) {
            int saved_errno = errno;
            munmap(temp, length);
            errno = saved_errno;
            return -1;
        }
        memcpy((void*)start, temp, length);
        munmap(temp, length);
#ifdef MADV_HUGEPAGE
        (void)madvise((void*)start, length, MADV_HUGEPAGE);
#endif
        policy_note_promote_runtime_locked(record, i, length, 1);
        record->chunk_states[i] = CHUNK_ANON_HOT;
        promoted += length;
    }

    if (promoted != 0) {
        stats_snapshot.promoted_to_anon_bytes += promoted;
    }
    return 0;
}

static int prepare_record_range_for_write_locked(AllocationRecord* record,
                                                 void* range_start,
                                                 size_t range_length) {
    uintptr_t chunk_start;
    uintptr_t chunk_end;
    size_t first_index;
    size_t end_index;
    void* record_page_start_ptr = NULL;
    size_t record_page_length;

    if (record->backend != BACKEND_ANON || !record->chunk_states) {
        return 0;
    }
    if (record_chunk_bounds_locked(record, range_start, range_length,
                                   &chunk_start, &chunk_end, &first_index,
                                   &end_index) != 0) {
        return 0;
    }

    record_page_length = record_page_range(record, &record_page_start_ptr);
    if (record_page_length == 0) {
        return -1;
    }
    uintptr_t record_start = (uintptr_t)record_page_start_ptr;

    stop_record_access_trace_locked(record);

    size_t prepared = 0;
    for (size_t i = first_index; i < end_index; i++) {
        if (record->chunk_states[i] != CHUNK_FILE_COLD) {
            continue;
        }

        uintptr_t start = record_start + i * record->chunk_bytes;
        uintptr_t end = start + record->chunk_bytes;
        if (end > record_start + record_page_length) {
            end = record_start + record_page_length;
        }
        size_t length = (size_t)(end - start);

        void* mapped = mmap((void*)start, length, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == MAP_FAILED || mapped != (void*)start) {
            return -1;
        }
#ifdef MADV_HUGEPAGE
        (void)madvise((void*)start, length, MADV_HUGEPAGE);
#endif
        policy_note_promote_runtime_locked(record, i, length, 0);
        record->chunk_states[i] = CHUNK_ANON_HOT;
        prepared += length;
    }

    if (prepared != 0) {
        stats_snapshot.promoted_to_anon_bytes += prepared;
    }
    return 0;
}

static int reclaim_record_range_locked(AllocationRecord* record,
                                       void* range_start,
                                       size_t range_length,
                                       ReclaimPolicy policy,
                                       size_t account_bytes) {
    uintptr_t start = (uintptr_t)range_start;
    uintptr_t end = start + range_length;
    int rc = 0;

    if (range_overlaps_exclusion_locked(start, end)) {
        stats_snapshot.reclaim_skipped_excluded++;
        stats_snapshot.reclaim_skipped_excluded_bytes += account_bytes;
        return 0;
    }

    if (range_length == 0 || policy == RECLAIM_NONE) {
        return 0;
    }

    if (record->backend == BACKEND_UFFD_PAGER) {
        return 0;
    }

    if (record->backend == BACKEND_ANON) {
        return migrate_anon_range_to_file_locked(record, range_start,
                                                 range_length, policy,
                                                 account_bytes);
    }

    if (msync(range_start, range_length, MS_SYNC) != 0) {
        return -1;
    }

    int advice = MADV_DONTNEED;
#ifdef MADV_PAGEOUT
    if (policy == RECLAIM_PAGEOUT) {
        advice = MADV_PAGEOUT;
    }
#endif
    if (madvise(range_start, range_length, advice) != 0) {
#ifdef MADV_PAGEOUT
        if (advice == MADV_PAGEOUT && errno == EINVAL &&
            madvise(range_start, range_length, MADV_DONTNEED) == 0) {
            record->reclaim_epoch = reclaim_epoch;
            stats_snapshot.reclaimed_bytes += account_bytes;
            return rc;
        }
#endif
        rc = -1;
    }

    if (rc != 0) {
        return rc;
    }

    record->reclaim_epoch = reclaim_epoch;
    stats_snapshot.reclaimed_bytes += account_bytes;
    return 0;
}

static int reclaim_record_locked(AllocationRecord* record, ReclaimPolicy policy) {
    void* range_start = NULL;
    size_t range_length = record_page_range(record, &range_start);

    return reclaim_record_range_locked(record, range_start, range_length, policy,
                                       record->user_size);
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

static int reclaim_to_rss_locked(size_t target_rss, ReclaimPolicy policy,
                                 int count_policy_call) {
    size_t current_rss = update_observed_rss_locked();

    if (target_rss == 0 && current_rss == 0) {
        return 0;
    }
    if (policy == RECLAIM_NONE ||
        current_rss == 0 ||
        current_rss <= target_rss) {
        return 0;
    }

    size_t needed = current_rss - target_rss;
    size_t attempted = 0;
    int rc = 0;
    reclaim_epoch++;
    if (count_policy_call) {
        stats_snapshot.policy_reclaim_calls++;
    }

    while (attempted < needed) {
        size_t estimated_bytes = 0;
        AllocationRecord* candidate = select_reclaim_candidate_locked(&estimated_bytes);
        if (!candidate) {
            break;
        }

        int record_rc = reclaim_record_locked(candidate, policy);
        if (record_rc != 0) {
            rc = -1;
        }
        if (estimated_bytes > 0) {
            attempted += estimated_bytes;
        } else if (record_rc == 0) {
            attempted += page_size;
        } else {
            attempted += candidate->user_size;
        }

        if (reclaim_selection == RECLAIM_SELECT_ALL) {
            continue;
        }
    }

    update_observed_rss_locked();
    return rc;
}

static int reclaim_all_candidates_locked(ReclaimPolicy policy) {
    int rc = 0;

    if (policy == RECLAIM_NONE) {
        return 0;
    }

    reclaim_epoch++;
    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        if (reclaim_record_locked(record, policy) != 0) {
            rc = -1;
        }
    }

    update_observed_rss_locked();
    return rc;
}

static size_t effective_max_rss_locked(size_t current_rss) {
    if (!max_rss_enabled) {
        stats_snapshot.max_rss = 0;
        return 0;
    }

    if (max_rss_auto &&
        (max_rss_bytes == 0 || memory_cap_refresh_counter == 0)) {
        max_rss_bytes = detect_auto_max_rss_bytes(current_rss);
    }
    memory_cap_refresh_counter++;
    if (memory_cap_refresh_counter >= MAI_MEMORY_CAP_REFRESH_INTERVAL) {
        memory_cap_refresh_counter = 0;
    }

    stats_snapshot.max_rss = max_rss_bytes;
    return max_rss_bytes;
}

static int rss_has_headroom(size_t current_rss, size_t cap, size_t incoming_resident_bytes) {
    if (cap == 0) {
        return 1;
    }
    if (current_rss > cap) {
        return 0;
    }
    return incoming_resident_bytes <= cap - current_rss;
}

static size_t percent_of_size(size_t bytes, size_t percent) {
    if (bytes == 0) {
        return 0;
    }
    if (percent >= 100) {
        return bytes;
    }
    return (bytes / 100) * percent + ((bytes % 100) * percent) / 100;
}

static int probe_userfaultfd_pager(void) {
    int fd = (int)syscall(SYS_userfaultfd,
                          O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    if (fd < 0) {
        return 0;
    }

    struct uffdio_api api;
    memset(&api, 0, sizeof(api));
    api.api = UFFD_API;
    api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
    if (ioctl(fd, UFFDIO_API, &api) != 0 ||
        !(api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP) ||
        !(api.ioctls & ((__u64)1 << _UFFDIO_REGISTER))) {
        close(fd);
        return 0;
    }

    void* page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        close(fd);
        return 0;
    }

    struct uffdio_register reg;
    memset(&reg, 0, sizeof(reg));
    reg.range.start = (unsigned long)page;
    reg.range.len = (unsigned long)page_size;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    int registered = ioctl(fd, UFFDIO_REGISTER, &reg) == 0;
    int ok = registered &&
        (reg.ioctls & ((__u64)1 << _UFFDIO_COPY)) &&
        (reg.ioctls & ((__u64)1 << _UFFDIO_ZEROPAGE)) &&
        (reg.ioctls & ((__u64)1 << _UFFDIO_WRITEPROTECT));
    if (ok) {
        struct uffdio_zeropage zero;
        memset(&zero, 0, sizeof(zero));
        zero.range.start = (unsigned long)page;
        zero.range.len = (unsigned long)page_size;
        ok = ioctl(fd, UFFDIO_ZEROPAGE, &zero) == 0;
    }
    if (ok) {
        struct uffdio_writeprotect wp;
        memset(&wp, 0, sizeof(wp));
        wp.range.start = (unsigned long)page;
        wp.range.len = (unsigned long)page_size;
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        ok = ioctl(fd, UFFDIO_WRITEPROTECT, &wp) == 0;
        if (ok) {
            wp.mode = 0;
            ok = ioctl(fd, UFFDIO_WRITEPROTECT, &wp) == 0;
        }
    }
    if (registered) {
        struct uffdio_range range;
        memset(&range, 0, sizeof(range));
        range.start = (unsigned long)page;
        range.len = (unsigned long)page_size;
        (void)ioctl(fd, UFFDIO_UNREGISTER, &range);
    }

    munmap(page, page_size);
    close(fd);
    return ok;
}

static int auto_backend_should_prefer_file_locked(size_t incoming_managed_bytes) {
    if (backend_mode != BACKEND_MODE_AUTO || !max_rss_enabled) {
        return 0;
    }

    size_t cap = effective_max_rss_locked(stats_snapshot.current_rss_bytes);
    if (cap == 0) {
        return 0;
    }

    size_t large_alloc_cutoff =
        percent_of_size(cap, auto_large_alloc_cap_percent);
    if (auto_large_alloc_cap_percent != 0) {
        if (large_alloc_cutoff < page_size && cap >= page_size) {
            large_alloc_cutoff = page_size;
        }
        if (incoming_managed_bytes >= large_alloc_cutoff) {
            return 1;
        }
    }

    size_t anon_budget = percent_of_size(cap, MAI_AUTO_ANON_LIMIT_PERCENT);
    if (anon_budget < page_size && cap >= page_size) {
        anon_budget = page_size;
    }

    size_t projected = stats_snapshot.live_managed_bytes;
    if (projected > SIZE_MAX - incoming_managed_bytes) {
        projected = SIZE_MAX;
    } else {
        projected += incoming_managed_bytes;
    }
    return projected > anon_budget;
}

static void estimate_rss_growth_locked(size_t bytes) {
    if (bytes == 0 || stats_snapshot.current_rss_bytes == 0) {
        return;
    }
    if (stats_snapshot.current_rss_bytes > SIZE_MAX - bytes) {
        stats_snapshot.current_rss_bytes = SIZE_MAX;
    } else {
        stats_snapshot.current_rss_bytes += bytes;
    }
    if (stats_snapshot.current_rss_bytes > stats_snapshot.high_water_rss_bytes) {
        stats_snapshot.high_water_rss_bytes = stats_snapshot.current_rss_bytes;
    }
}

static int ensure_memory_cap_headroom_locked(size_t incoming_resident_bytes) {
    if (!max_rss_enabled) {
        return 0;
    }

    if (stats_snapshot.current_rss_bytes != 0 &&
        max_rss_bytes != 0 &&
        rss_has_headroom(stats_snapshot.current_rss_bytes, max_rss_bytes,
                         incoming_resident_bytes)) {
        memory_cap_check_counter++;
        if (memory_cap_check_counter < MAI_MEMORY_CAP_CHECK_INTERVAL) {
            estimate_rss_growth_locked(incoming_resident_bytes);
            return 0;
        }
        memory_cap_check_counter = 0;
    }

    size_t current_rss = update_observed_rss_locked();
    size_t cap = effective_max_rss_locked(current_rss);
    if (rss_has_headroom(current_rss, cap, incoming_resident_bytes)) {
        return 0;
    }

    ReclaimPolicy cap_policy =
        reclaim_policy == RECLAIM_NONE ? RECLAIM_DONTNEED : reclaim_policy;
    size_t target = incoming_resident_bytes >= cap ? 0 : cap - incoming_resident_bytes;

    stats_snapshot.memory_cap_reclaim_calls++;
    (void)reclaim_to_rss_locked(target, cap_policy, 0);

    current_rss = update_observed_rss_locked();
    cap = effective_max_rss_locked(current_rss);
    if (rss_has_headroom(current_rss, cap, incoming_resident_bytes)) {
        return 0;
    }

    (void)reclaim_all_candidates_locked(cap_policy);

    current_rss = update_observed_rss_locked();
    cap = effective_max_rss_locked(current_rss);
    if (rss_has_headroom(current_rss, cap, incoming_resident_bytes)) {
        return 0;
    }

    stats_snapshot.memory_cap_failures++;
    errno = ENOMEM;
    return -1;
}

static void maybe_policy_reclaim_locked(void) {
    if (target_rss_bytes == 0 || reclaim_policy == RECLAIM_NONE) {
        return;
    }

    (void)reclaim_to_rss_locked(target_rss_bytes, reclaim_policy, 1);
}

static int zero_fill_managed_allocation(void* ptr, size_t size) {
    unsigned char* cursor = (unsigned char*)ptr;
    size_t offset = 0;

    while (offset < size) {
        size_t remaining = size - offset;
        size_t chunk = remaining < MAI_ZERO_FILL_CHUNK ? remaining : MAI_ZERO_FILL_CHUNK;

        pthread_mutex_lock(&runtime_lock);
        int headroom_rc = ensure_memory_cap_headroom_locked(chunk);
        pthread_mutex_unlock(&runtime_lock);
        if (headroom_rc != 0) {
            return -1;
        }

        memset(cursor + offset, 0, chunk);
        offset += chunk;

        pthread_mutex_lock(&runtime_lock);
        maybe_policy_reclaim_locked();
        (void)ensure_memory_cap_headroom_locked(0);
        pthread_mutex_unlock(&runtime_lock);
    }

    return 0;
}

static void* allocate_by_policy(size_t size, size_t alignment, int zero_fill, int* managed,
                                void* call_site) {
    void* ptr = NULL;

    *managed = 0;
    if (should_manage(size)) {
        pthread_mutex_lock(&runtime_lock);
        if (ensure_memory_cap_headroom_locked(0) != 0) {
            pthread_mutex_unlock(&runtime_lock);
            errno = ENOMEM;
            return NULL;
        }
        AllocationRecord* record = managed_alloc_locked(size, alignment, call_site);
        if (record) {
            ptr = record->user_ptr;
            *managed = 1;
        }
        pthread_mutex_unlock(&runtime_lock);

        if (ptr) {
            int is_uffd = record && record->backend == BACKEND_UFFD_PAGER;
            if (zero_fill && !is_uffd) {
                if (zero_fill_managed_allocation(ptr, size) != 0) {
                    pthread_mutex_lock(&runtime_lock);
                    AllocationRecord* old_record = free_managed_pointer_locked(ptr);
                    pthread_mutex_unlock(&runtime_lock);
                    meta_free(old_record);
                    errno = ENOMEM;
                    return NULL;
                }
            }
            pthread_mutex_lock(&runtime_lock);
            maybe_policy_reclaim_locked();
            (void)ensure_memory_cap_headroom_locked(0);
            pthread_mutex_unlock(&runtime_lock);
            if (is_uffd && register_uffd_record(record) != 0) {
                int register_errno = errno;
                pthread_mutex_lock(&runtime_lock);
                AllocationRecord* old_record = free_managed_pointer_locked(ptr);
                meta_free(old_record);
                pthread_mutex_lock(&uffd_fault_lock);
                stats_snapshot.uffd_fallbacks++;
                pthread_mutex_unlock(&uffd_fault_lock);
                if (uffd_pager_mode != UFFD_PAGER_REQUIRED &&
                    backend_mode == BACKEND_MODE_AUTO) {
                    AllocationRecord* fallback_record =
                        managed_auto_pressure_fallback_locked(size, alignment,
                                                              call_site);
                    if (fallback_record) {
                        ptr = fallback_record->user_ptr;
                        record = fallback_record;
                        *managed = 1;
                        pthread_mutex_unlock(&runtime_lock);
                        return ptr;
                    }
                }
                pthread_mutex_unlock(&runtime_lock);
                errno = uffd_pager_mode == UFFD_PAGER_REQUIRED ?
                    ENOMEM : register_errno;
                return NULL;
            }
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
    int saved_hook_depth = in_mai_hook;

    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    stats_snapshot.reclaim_calls++;

    if (reclaim_policy == RECLAIM_NONE) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        return 0;
    }

    rc = reclaim_all_candidates_locked(reclaim_policy);
    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
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

static void populate_stats_snapshot_locked(MaiStats* out) {
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
    out->max_rss = effective_max_rss_locked(stats_snapshot.current_rss_bytes);
    out->migration_policy = (size_t)migration_policy;
    out->policy_prefetch_observation =
        policy_observe_prefetch_writes ? 1u : 0u;
    out->policy_demand_fault_stall_p50_ns =
        policy_stall_percentile_locked(50);
    out->policy_demand_fault_stall_p90_ns =
        policy_stall_percentile_locked(90);
    out->policy_demand_fault_stall_p99_ns =
        policy_stall_percentile_locked(99);
    out->policy_demand_fault_stall_max_ns = policy_fault_stall_max_ns;
}

int mai_get_stats_sized(MaiStats* out, size_t stats_size) {
    if (!out || stats_size == 0) {
        errno = EINVAL;
        return -1;
    }

    flush_current_pass_through_counter();

    MaiStats snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    pthread_mutex_lock(&runtime_lock);
    update_observed_rss_locked();
    pthread_mutex_lock(&uffd_fault_lock);
    populate_stats_snapshot_locked(&snapshot);
    pthread_mutex_unlock(&uffd_fault_lock);
    pthread_mutex_unlock(&runtime_lock);

    size_t copy_size = stats_size < sizeof(snapshot) ? stats_size : sizeof(snapshot);
    memset(out, 0, stats_size);
    memcpy(out, &snapshot, copy_size);
    return 0;
}

int mai_get_stats(MaiStats* out) {
    return mai_get_stats_sized(out, offsetof(MaiStats, uffd_pager_available));
}

int mai_hint_range(void* ptr, size_t len, uint32_t kind,
                   const MaiHintOptions* opts) {
    uintptr_t start;
    uintptr_t end;

    if (len == 0) {
        return 0;
    }
    if (!ptr || !hint_kind_valid(kind) || !hint_options_valid(opts) ||
        make_range(ptr, len, &start, &end) != 0) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, end, &partial_overlap);
    if (!record) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        if (partial_overlap) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    uintptr_t record_start;
    uintptr_t record_end;
    if (record_user_range_locked(record, &record_start, &record_end) != 0) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        errno = EINVAL;
        return -1;
    }

    record->hint_kind = kind;
    record->hint_flags = opts ? opts->flags : 0;
    record->hint_offset = (size_t)(start - record_start);
    record->hint_length = len;
    record->hint_hotset_bytes = opts ? opts->hotset_bytes : 0;
    record->hint_window_bytes = opts ? opts->window_bytes : 0;
    record->hint_epoch = ++hint_epoch_sequence;

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return 0;
}

int mai_reclaim_range(void* ptr, size_t len) {
    uintptr_t start;
    uintptr_t end;
    int rc = 0;

    if (len == 0) {
        return 0;
    }
    if (!ptr || make_range(ptr, len, &start, &end) != 0) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, end, &partial_overlap);
    if (!record) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        if (partial_overlap) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    stats_snapshot.reclaim_calls++;
    if (reclaim_policy != RECLAIM_NONE) {
        void* page_start = NULL;
        size_t page_length = 0;
        if (clamp_range_to_record_pages_locked(record, start, end,
                                               &page_start, &page_length) != 0) {
            rc = -1;
        } else if (page_length != 0) {
            reclaim_epoch++;
            rc = reclaim_record_range_locked(record, page_start, page_length,
                                             reclaim_policy, page_length);
            update_observed_rss_locked();
        }
    }

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return rc;
}

int mai_prefetch(void* ptr, size_t len) {
    uintptr_t start;
    uintptr_t end;
    int rc = 0;

    if (len == 0) {
        return 0;
    }
    if (!ptr || make_range(ptr, len, &start, &end) != 0) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, end, &partial_overlap);
    if (!record) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        if (partial_overlap) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    void* page_start = NULL;
    size_t page_length = 0;
    if (clamp_range_to_record_pages_locked(record, start, end, &page_start,
                                           &page_length) != 0) {
        rc = -1;
    } else if (page_length != 0 &&
               !range_overlaps_exclusion_locked((uintptr_t)page_start,
                                                (uintptr_t)page_start + page_length)) {
        if (promote_record_range_to_anon_locked(record, page_start, page_length) != 0) {
            rc = -1;
        }
#ifdef MADV_WILLNEED
        if (rc == 0) {
            rc = madvise(page_start, page_length, MADV_WILLNEED);
        }
#else
        rc = rc == 0 ? 0 : rc;
#endif
    }

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return rc;
}

int mai_prepare_write(void* ptr, size_t len) {
    uintptr_t start;
    uintptr_t end;
    int rc = 0;

    if (len == 0) {
        return 0;
    }
    if (!ptr || make_range(ptr, len, &start, &end) != 0) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, end, &partial_overlap);
    if (!record) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        if (partial_overlap) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    void* page_start = NULL;
    size_t page_length = 0;
    if (clamp_range_to_record_pages_locked(record, start, end, &page_start,
                                           &page_length) != 0) {
        rc = -1;
    } else if (page_length != 0 &&
               !range_overlaps_exclusion_locked((uintptr_t)page_start,
                                                (uintptr_t)page_start + page_length)) {
        rc = prepare_record_range_for_write_locked(record, page_start, page_length);
    }

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return rc;
}

int mai_trace_access(void* ptr, size_t len, const MaiAccessTraceOptions* opts) {
    uintptr_t start;
    uintptr_t end;

    if (len == 0) {
        return 0;
    }
    if (!ptr || !access_trace_options_valid(opts) ||
        make_range(ptr, len, &start, &end) != 0) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, end, &partial_overlap);
    if (!record) {
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        if (partial_overlap) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    int rc = arm_record_access_trace_locked(record, start, end,
                                            opts ? opts->max_pages : 0,
                                            opts ? opts->chunk_bytes : 0,
                                            0,
                                            NULL);

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return rc;
}

int mai_get_access_trace(void* ptr, MaiAccessTraceSnapshot* snapshot) {
    if (!snapshot) {
        errno = EINVAL;
        return -1;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->size = sizeof(*snapshot);

    if (!ptr) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    uintptr_t start = (uintptr_t)ptr;
    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, start + 1, &partial_overlap);
    if (!record || record->access_trace_id == 0) {
        snapshot->page_size = page_size;
        pthread_mutex_unlock(&runtime_lock);
        in_mai_hook = saved_hook_depth;
        return 0;
    }

    snapshot->page_size = page_size;
    snapshot->total_pages = record->access_trace_total_pages;
    snapshot->armed_pages = record->access_trace_armed_pages;

    uint64_t bitmap = 0;
    uint64_t first_sequence = 0;
    uint64_t last_sequence = 0;
    size_t touched_pages = 0;

    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        AccessTracePage* trace_page = &access_trace_pages[i];
        int state = atomic_load_explicit(&trace_page->state, memory_order_acquire);
        AllocationRecord* trace_record =
            atomic_load_explicit(&trace_page->record, memory_order_acquire);
        size_t trace_id =
            atomic_load_explicit(&trace_page->trace_id, memory_order_acquire);
        if (state == ACCESS_TRACE_FREE ||
            trace_record != record ||
            trace_id != record->access_trace_id) {
            continue;
        }

        size_t sequence = atomic_load_explicit(&trace_page->touch_sequence,
                                               memory_order_acquire);
        if (state == ACCESS_TRACE_TOUCHED || sequence != 0) {
            touched_pages++;
            size_t sample_index =
                atomic_load_explicit(&trace_page->sample_index,
                                     memory_order_acquire);
            if (sample_index < 64) {
                bitmap |= 1ULL << sample_index;
            }
            if (first_sequence == 0 || sequence < first_sequence) {
                first_sequence = sequence;
            }
            if (sequence > last_sequence) {
                last_sequence = sequence;
            }
        }
    }

    snapshot->touched_pages = touched_pages;
    snapshot->touched_bitmap = bitmap;
    snapshot->first_touch_sequence = first_sequence;
    snapshot->last_touch_sequence = last_sequence;

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return 0;
}

int mai_stop_access_trace(void* ptr) {
    if (!ptr) {
        errno = EINVAL;
        return -1;
    }

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    uintptr_t start = (uintptr_t)ptr;
    int partial_overlap = 0;
    AllocationRecord* record =
        find_record_containing_range_locked(start, start + 1, &partial_overlap);
    if (record) {
        stop_record_access_trace_locked(record);
    }

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return 0;
}

int mai_heartbeat(const MaiHeartbeatOptions* opts, MaiHeartbeatSnapshot* snapshot) {
    if (!snapshot || !heartbeat_options_valid(opts)) {
        errno = EINVAL;
        return -1;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->size = sizeof(*snapshot);

    size_t observe_pages =
        opts && opts->observe_pages != 0 ? opts->observe_pages :
        MAI_DEFAULT_HEARTBEAT_OBSERVE_PAGES;
    if (observe_pages > MAI_ACCESS_TRACE_MAX_PAGES) {
        observe_pages = MAI_ACCESS_TRACE_MAX_PAGES;
    }

    size_t chunk_bytes =
        opts && opts->chunk_bytes != 0 ? opts->chunk_bytes :
        MAI_DEFAULT_HEARTBEAT_CHUNK_BYTES;
    size_t chunk_pages = access_trace_chunk_pages(chunk_bytes);
    if (chunk_pages == 0) {
        chunk_pages = 1;
    }
    size_t chunk_length =
        chunk_pages > SIZE_MAX / page_size ? SIZE_MAX : chunk_pages * page_size;

    size_t migrate_budget = opts ? opts->migrate_bytes : 0;
    migrate_budget -= migrate_budget % page_size;

    int saved_hook_depth = in_mai_hook;
    in_mai_hook++;
    pthread_mutex_lock(&runtime_lock);

    snapshot->epoch = ++heartbeat_epoch;

    size_t touched_pages = 0;
    size_t busy_score = 0;
    for (AllocationRecord* record = live_head; record; record = record->live_next) {
        size_t armed = 0;
        size_t touched = 0;
        record_access_trace_counts_locked(record, &armed, &touched);
        touched_pages += touched;

        if (armed != 0) {
            if (touched != 0) {
                record->heartbeat_last_touch_epoch = heartbeat_epoch;
                record->heartbeat_quiet_epochs = 0;
                if (record->heartbeat_busy_score >
                    MAI_HEARTBEAT_BUSY_SCORE_CAP - touched) {
                    record->heartbeat_busy_score = MAI_HEARTBEAT_BUSY_SCORE_CAP;
                } else {
                    record->heartbeat_busy_score += touched;
                }
            } else {
                record->heartbeat_quiet_epochs++;
                if (record->heartbeat_busy_score != 0) {
                    record->heartbeat_busy_score--;
                }
            }
        } else if (record->heartbeat_busy_score != 0) {
            record->heartbeat_busy_score--;
        }

        if (busy_score > SIZE_MAX - record->heartbeat_busy_score) {
            busy_score = SIZE_MAX;
        } else {
            busy_score += record->heartbeat_busy_score;
        }
    }

    int busy = touched_pages != 0;
    size_t reclaimed_bytes = 0;
    int rc = 0;

    if (!busy && migrate_budget != 0) {
        ReclaimPolicy policy =
            reclaim_policy == RECLAIM_NONE ? RECLAIM_DONTNEED : reclaim_policy;
        size_t remaining = migrate_budget;
        AllocationRecord* reclaim_records[MAI_ACCESS_TRACE_MAX_PAGES];
        uintptr_t reclaim_starts[MAI_ACCESS_TRACE_MAX_PAGES];
        size_t reclaim_lengths[MAI_ACCESS_TRACE_MAX_PAGES];
        size_t reclaim_count = 0;
        reclaim_epoch++;

        for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES && remaining >= page_size; i++) {
            AccessTracePage* trace_page = &access_trace_pages[i];
            int state = atomic_load_explicit(&trace_page->state,
                                             memory_order_acquire);
            size_t sequence = atomic_load_explicit(&trace_page->touch_sequence,
                                                   memory_order_acquire);
            AllocationRecord* record =
                atomic_load_explicit(&trace_page->record, memory_order_acquire);
            size_t trace_id =
                atomic_load_explicit(&trace_page->trace_id, memory_order_acquire);
            size_t sample_index =
                atomic_load_explicit(&trace_page->sample_index,
                                     memory_order_acquire);
            if (state != ACCESS_TRACE_ARMED || sequence != 0 || !record ||
                trace_id != record->access_trace_id) {
                continue;
            }
            if (record->heartbeat_quiet_epochs < heartbeat_min_quiet_epochs) {
                continue;
            }

            void* record_page_start_ptr = NULL;
            size_t record_page_length =
                record_page_range(record, &record_page_start_ptr);
            if (record_page_length == 0) {
                continue;
            }

            uintptr_t record_page_start = (uintptr_t)record_page_start_ptr;
            uintptr_t record_page_end = record_page_start + record_page_length;
            uintptr_t representative_page =
                atomic_load_explicit(&trace_page->page, memory_order_acquire);
            if (representative_page < record_page_start ||
                representative_page >= record_page_end) {
                continue;
            }

            uintptr_t trace_start = record->access_trace_start;
            uintptr_t range_start = trace_start;
            if (chunk_length > 0 && sample_index > 0) {
                if (sample_index > (UINTPTR_MAX - trace_start) / chunk_length) {
                    continue;
                }
                range_start = trace_start + sample_index * chunk_length;
            }
            if (range_start < record_page_start) {
                range_start = record_page_start;
            }
            if (range_start >= record_page_end) {
                continue;
            }

            uintptr_t range_end;
            if (chunk_length > UINTPTR_MAX - range_start) {
                range_end = UINTPTR_MAX;
            } else {
                range_end = range_start + chunk_length;
            }
            if (range_end > record_page_end) {
                range_end = record_page_end;
            }
            size_t range_length = (size_t)(range_end - range_start);
            if (range_length > remaining) {
                range_length = remaining - (remaining % page_size);
            }
            if (range_length == 0) {
                break;
            }

            reclaim_records[reclaim_count] = record;
            reclaim_starts[reclaim_count] = range_start;
            reclaim_lengths[reclaim_count] = range_length;
            reclaim_count++;
            remaining -= range_length;
        }

        for (size_t i = 0; rc == 0 && i < reclaim_count; i++) {
            AllocationRecord* record = reclaim_records[i];
            uintptr_t range_start = reclaim_starts[i];
            size_t range_length = reclaim_lengths[i];

            if (mprotect((void*)range_start, page_size,
                         PROT_READ | PROT_WRITE) != 0) {
                rc = -1;
                break;
            }

            if (reclaim_record_range_locked(record, (void*)range_start,
                                            range_length, policy,
                                            range_length) != 0) {
                rc = -1;
                break;
            }
            reclaimed_bytes += range_length;
        }

        if (reclaimed_bytes != 0) {
            update_observed_rss_locked();
        }
    }

    stop_all_access_traces_locked();

    size_t rearm_budget = busy && observe_pages > 1 ? observe_pages / 2 :
        observe_pages;
    size_t armed_pages = 0;
    size_t observed_allocations = 0;

    AllocationRecord* start_record = heartbeat_cursor ? heartbeat_cursor : live_head;
    AllocationRecord* record = start_record;
    while (rc == 0 && rearm_budget != 0 && record) {
        AllocationRecord* next_record = record->live_next ? record->live_next :
            live_head;
        uintptr_t start;
        uintptr_t end;
        if (record_user_range_locked(record, &start, &end) != 0) {
            if (next_record == start_record) {
                heartbeat_cursor = next_record;
                break;
            }
            record = next_record;
            continue;
        }

        size_t armed_for_record = 0;
        size_t chunk_phase =
            heartbeat_chunk_phase_pages(chunk_pages, heartbeat_epoch);
        rc = arm_record_access_trace_locked(record, start, end, rearm_budget,
                                            chunk_bytes, chunk_phase,
                                            &armed_for_record);
        if (rc != 0) {
            break;
        }
        if (armed_for_record != 0) {
            observed_allocations++;
            armed_pages += armed_for_record;
            if (armed_for_record >= rearm_budget) {
                rearm_budget = 0;
            } else {
                rearm_budget -= armed_for_record;
            }
        }
        heartbeat_cursor = next_record;
        if (next_record == start_record) {
            break;
        }
        record = next_record;
    }

    snapshot->observed_allocations = observed_allocations;
    snapshot->armed_pages = armed_pages;
    snapshot->touched_pages = touched_pages;
    snapshot->reclaimed_bytes = reclaimed_bytes;
    snapshot->busy_score = busy_score;
    snapshot->busy = busy;

    pthread_mutex_unlock(&runtime_lock);
    in_mai_hook = saved_hook_depth;
    return rc;
}

static void background_heartbeat_sleep(size_t interval_us) {
    struct timespec duration;
    duration.tv_sec = (time_t)(interval_us / 1000000);
    duration.tv_nsec = (long)((interval_us % 1000000) * 1000);
    while (nanosleep(&duration, &duration) != 0 && errno == EINTR) {
    }
}

static void* background_heartbeat_main(void* arg) {
    (void)arg;

    MaiHeartbeatOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.size = sizeof(opts);
    opts.observe_pages = background_heartbeat_observe_pages;
    opts.chunk_bytes = background_heartbeat_chunk_bytes;
    opts.migrate_bytes = background_heartbeat_migrate_bytes;

    while (atomic_load_explicit(&background_heartbeat_stop,
                                memory_order_acquire) == 0) {
        MaiHeartbeatSnapshot snapshot;
        (void)mai_heartbeat(&opts, &snapshot);
        background_heartbeat_sleep(background_heartbeat_interval_us);
    }

    return NULL;
}

static int start_background_heartbeat(void) {
    if (!background_heartbeat_enabled || background_heartbeat_started) {
        return 0;
    }
    atomic_store_explicit(&background_heartbeat_stop, 0, memory_order_release);
    if (pthread_create(&background_heartbeat_thread, NULL,
                       background_heartbeat_main, NULL) != 0) {
        background_heartbeat_enabled = 0;
        return -1;
    }
    background_heartbeat_started = 1;
    return 0;
}

static void stop_background_heartbeat(void) {
    if (!background_heartbeat_started) {
        return;
    }
    atomic_store_explicit(&background_heartbeat_stop, 1, memory_order_release);
    (void)pthread_join(background_heartbeat_thread, NULL);
    background_heartbeat_started = 0;
}

static void print_stats(void) {
    MaiStats stats;

    if (mai_get_stats_sized(&stats, sizeof(stats)) != 0) {
        return;
    }

    fprintf(stderr,
            "MAI stats: enabled=%d configured=%d config_error=%d threshold=%zu arena_size=%zu "
            "target_rss=%zu max_rss=%zu current_rss=%zu high_water_rss=%zu "
            "segments=%zu arena_bytes=%zu managed_total=%zu pass_through_total=%zu "
            "live_managed=%zu high_water=%zu managed_allocs=%zu pass_through_allocs=%zu "
            "managed_frees=%zu reclaim_calls=%zu policy_reclaim_calls=%zu "
            "memory_cap_reclaim_calls=%zu memory_cap_failures=%zu reclaimed_bytes=%zu "
            "mmap_calls=%zu munmap_calls=%zu mremap_calls=%zu brk_calls=%zu sbrk_calls=%zu "
            "profile_sites=%zu hotness_samples=%zu hotness_sampled_pages=%zu "
            "hotness_resident_pages=%zu allocator_hook_mode=%zu allocator_libc_patches=%zu "
            "allocator_preload_calls=%zu allocator_frida_calls=%zu excluded_ranges=%zu "
            "excluded_bytes=%zu exclusion_events=%zu exclusion_release_events=%zu "
            "reclaim_skipped_excluded=%zu reclaim_skipped_excluded_bytes=%zu "
            "safety_hook_patches=%zu anon_allocations=%zu file_allocations=%zu "
            "migrated_to_file_bytes=%zu promoted_to_anon_bytes=%zu "
            "uffd_pager_available=%zu uffd_pager_allocations=%zu "
            "uffd_faults=%zu uffd_evictions=%zu uffd_resident_bytes=%zu "
            "uffd_fallbacks=%zu migration_policy=%zu "
            "policy_prefetch_requests=%zu policy_prefetch_admitted=%zu "
            "policy_prefetch_completed=%zu policy_prefetch_useful=%zu "
            "policy_prefetch_late=%zu policy_prefetch_unused_evictions=%zu "
            "policy_prefetch_bytes=%zu policy_prefetch_useful_bytes=%zu "
            "policy_prefetch_unused_evicted_bytes=%zu "
            "policy_admission_requests=%zu policy_admission_rejected=%zu "
            "policy_demotions=%zu policy_promotions=%zu "
            "policy_evicted_hot_bytes=%zu policy_migration_read_bytes=%zu "
            "policy_migration_write_bytes=%zu policy_demand_faults=%zu "
            "policy_demand_fault_stall_ns=%zu policy_throttle_events=%zu "
            "policy_throttle_slept_ns=%zu policy_prefetch_observation=%zu "
            "policy_demand_fault_stall_samples=%zu "
            "policy_demand_fault_stall_p50_ns=%zu "
            "policy_demand_fault_stall_p90_ns=%zu "
            "policy_demand_fault_stall_p99_ns=%zu "
            "policy_demand_fault_stall_max_ns=%zu\n",
            stats.enabled, stats.configured, stats.config_error, stats.threshold,
            stats.arena_size, stats.target_rss, stats.max_rss,
            stats.current_rss_bytes, stats.high_water_rss_bytes,
            stats.arena_segments, stats.arena_bytes,
            stats.managed_bytes_total, stats.pass_through_bytes_total,
            stats.live_managed_bytes, stats.high_water_managed_bytes,
            stats.managed_allocations, stats.pass_through_allocations,
            stats.managed_frees, stats.reclaim_calls, stats.policy_reclaim_calls,
            stats.memory_cap_reclaim_calls, stats.memory_cap_failures,
            stats.reclaimed_bytes, stats.mmap_calls, stats.munmap_calls,
            stats.mremap_calls, stats.brk_calls, stats.sbrk_calls,
            stats.profile_sites, stats.hotness_samples, stats.hotness_sampled_pages,
            stats.hotness_resident_pages, stats.allocator_hook_mode,
            stats.allocator_libc_patches, stats.allocator_preload_calls,
            stats.allocator_frida_calls, stats.excluded_ranges, stats.excluded_bytes,
            stats.exclusion_events, stats.exclusion_release_events,
            stats.reclaim_skipped_excluded, stats.reclaim_skipped_excluded_bytes,
            stats.safety_hook_patches, stats.anon_allocations,
            stats.file_allocations, stats.migrated_to_file_bytes,
            stats.promoted_to_anon_bytes, stats.uffd_pager_available,
            stats.uffd_pager_allocations, stats.uffd_faults,
            stats.uffd_evictions, stats.uffd_resident_bytes,
            stats.uffd_fallbacks, stats.migration_policy,
            stats.policy_prefetch_requests, stats.policy_prefetch_admitted,
            stats.policy_prefetch_completed, stats.policy_prefetch_useful,
            stats.policy_prefetch_late,
            stats.policy_prefetch_unused_evictions,
            stats.policy_prefetch_bytes, stats.policy_prefetch_useful_bytes,
            stats.policy_prefetch_unused_evicted_bytes,
            stats.policy_admission_requests, stats.policy_admission_rejected,
            stats.policy_demotions, stats.policy_promotions,
            stats.policy_evicted_hot_bytes,
            stats.policy_migration_read_bytes,
            stats.policy_migration_write_bytes,
            stats.policy_demand_faults,
            stats.policy_demand_fault_stall_ns,
            stats.policy_throttle_events, stats.policy_throttle_slept_ns,
            stats.policy_prefetch_observation,
            stats.policy_demand_fault_stall_samples,
            stats.policy_demand_fault_stall_p50_ns,
            stats.policy_demand_fault_stall_p90_ns,
            stats.policy_demand_fault_stall_p99_ns,
            stats.policy_demand_fault_stall_max_ns);
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
    const char* max_rss = getenv("MAI_MAX_RSS");
    const char* reclaim = getenv("MAI_RECLAIM_POLICY");
    const char* reclaim_select = getenv("MAI_RECLAIM_SELECTION");
    const char* backend = getenv("MAI_BACKEND");
    const char* uffd_pager = getenv("MAI_UFFD_PAGER");
    const char* uffd_resident_limit = getenv("MAI_UFFD_RESIDENT_LIMIT");
    const char* uffd_resident_low_limit =
        getenv("MAI_UFFD_RESIDENT_LOW_LIMIT");
    const char* uffd_prefetch = getenv("MAI_UFFD_PREFETCH_CHUNKS");
    const char* migration_chunk = getenv("MAI_MIGRATION_CHUNK");
    const char* migration_policy_env = getenv("MAI_MIGRATION_POLICY");
    if (!migration_policy_env || migration_policy_env[0] == '\0') {
        migration_policy_env = getenv("MAI_POLICY");
    }
    const char* observe_prefetch_writes =
        getenv("MAI_POLICY_OBSERVE_PREFETCH_WRITES");
    const char* file_dedicated_min = getenv("MAI_FILE_DEDICATED_MIN");
    const char* auto_large_alloc_percent =
        getenv("MAI_AUTO_LARGE_ALLOC_CAP_PERCENT");
    const char* hotness_sample = getenv("MAI_HOTNESS_SAMPLE_PAGES");
    const char* heartbeat_quiet = getenv("MAI_HEARTBEAT_MIN_QUIET_EPOCHS");
    const char* background_heartbeat = getenv("MAI_HEARTBEAT_BACKGROUND");
    const char* background_interval =
        getenv("MAI_HEARTBEAT_BACKGROUND_INTERVAL_US");
    const char* background_observe =
        getenv("MAI_HEARTBEAT_BACKGROUND_OBSERVE_PAGES");
    const char* background_chunk =
        getenv("MAI_HEARTBEAT_BACKGROUND_CHUNK");
    const char* background_migrate =
        getenv("MAI_HEARTBEAT_BACKGROUND_MIGRATE");
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
    backend_mode = BACKEND_MODE_AUTO;
    uffd_pager_mode = UFFD_PAGER_OFF;
    migration_policy = MIGRATION_POLICY_LEGACY;
    policy_observe_prefetch_writes = 0;
    uffd_pager_available = 0;
    uffd_resident_limit_bytes = 0;
    uffd_resident_low_limit_bytes = 0;
    uffd_resident_limit_explicit = 0;
    uffd_resident_bytes = 0;
    uffd_touch_epoch = 0;
    uffd_head = NULL;

    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0) {
        page_size = 4096;
    }

    threshold_bytes = MAI_DEFAULT_THRESHOLD;
    arena_size_bytes = MAI_DEFAULT_ARENA_SIZE;
    target_rss_bytes = 0;
    max_rss_bytes = 0;
    max_rss_auto = 1;
    max_rss_enabled = 1;
    auto_large_alloc_cap_percent = MAI_AUTO_LARGE_ALLOC_CAP_PERCENT;
    memory_cap_check_counter = 0;
    memory_cap_refresh_counter = 0;
    hotness_sample_pages = MAI_DEFAULT_HOTNESS_SAMPLE_PAGES;
    heartbeat_min_quiet_epochs = MAI_DEFAULT_HEARTBEAT_MIN_QUIET_EPOCHS;
    background_heartbeat_enabled = parse_bool_env(background_heartbeat);
    background_heartbeat_interval_us =
        MAI_DEFAULT_BACKGROUND_HEARTBEAT_INTERVAL_US;
    background_heartbeat_observe_pages = MAI_DEFAULT_HEARTBEAT_OBSERVE_PAGES;
    background_heartbeat_chunk_bytes = MAI_DEFAULT_HEARTBEAT_CHUNK_BYTES;
    background_heartbeat_migrate_bytes =
        MAI_DEFAULT_BACKGROUND_HEARTBEAT_MIGRATE_BYTES;
    background_heartbeat_started = 0;
    atomic_store_explicit(&background_heartbeat_stop, 0, memory_order_relaxed);
    migration_chunk_bytes = MAI_DEFAULT_MIGRATION_CHUNK_BYTES;
    uffd_prefetch_chunks = MAI_DEFAULT_UFFD_PREFETCH_CHUNKS;
    file_dedicated_min_bytes = MAI_DEFAULT_FILE_DEDICATED_MIN_BYTES;

    memset(&stats_snapshot, 0, sizeof(stats_snapshot));
    memset(policy_fault_stall_hist, 0, sizeof(policy_fault_stall_hist));
    policy_fault_stall_max_ns = 0;
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
    heartbeat_cursor = NULL;
    mlockall_future_active = 0;
    atomic_store_explicit(&dynamic_replacements_active, 0, memory_order_relaxed);
    atomic_store_explicit(&managed_range_low, 0, memory_order_relaxed);
    atomic_store_explicit(&managed_range_high, 0, memory_order_relaxed);
    next_segment_id = 0;
    allocation_sequence = 0;
    reclaim_epoch = 0;
    heartbeat_epoch = 0;
    hint_epoch_sequence = 0;
    access_trace_id_sequence = 0;
    atomic_store_explicit(&access_trace_sequence, 0, memory_order_relaxed);
    for (size_t i = 0; i < MAI_ACCESS_TRACE_MAX_PAGES; i++) {
        atomic_store_explicit(&access_trace_pages[i].state, ACCESS_TRACE_FREE,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].page, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].retired_page, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].retired_deadline_ns, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].record, NULL,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].trace_id, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].sample_index, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&access_trace_pages[i].touch_sequence, 0,
                              memory_order_relaxed);
    }

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
    if (max_rss && max_rss[0] != '\0') {
        if (strcmp(max_rss, "auto") == 0) {
            max_rss_auto = 1;
            max_rss_enabled = 1;
        } else if (strcmp(max_rss, "off") == 0 || strcmp(max_rss, "none") == 0 ||
                   strcmp(max_rss, "0") == 0) {
            max_rss_auto = 0;
            max_rss_enabled = 0;
            max_rss_bytes = 0;
        } else {
            if (parse_size_env(max_rss, &max_rss_bytes) != 0) {
                runtime_config_error = 1;
                return -1;
            }
            max_rss_auto = 0;
            max_rss_enabled = max_rss_bytes != 0;
        }
    }
    if (auto_large_alloc_percent &&
        parse_count_env(auto_large_alloc_percent,
                        &auto_large_alloc_cap_percent) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (hotness_sample && parse_count_env(hotness_sample, &hotness_sample_pages) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (heartbeat_quiet &&
        parse_count_env(heartbeat_quiet, &heartbeat_min_quiet_epochs) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (background_interval &&
        parse_count_env(background_interval,
                        &background_heartbeat_interval_us) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (background_observe &&
        parse_count_env(background_observe,
                        &background_heartbeat_observe_pages) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (background_chunk &&
        parse_size_env(background_chunk,
                       &background_heartbeat_chunk_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (background_migrate &&
        parse_size_env(background_migrate,
                       &background_heartbeat_migrate_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (uffd_resident_limit && uffd_resident_limit[0] != '\0' &&
        strcmp(uffd_resident_limit, "auto") != 0) {
        if (parse_size_env(uffd_resident_limit, &uffd_resident_limit_bytes) != 0) {
            runtime_config_error = 1;
            return -1;
        }
        uffd_resident_limit_explicit = 1;
    }
    if (uffd_resident_low_limit && uffd_resident_low_limit[0] != '\0' &&
        strcmp(uffd_resident_low_limit, "auto") != 0 &&
        parse_size_env(uffd_resident_low_limit,
                       &uffd_resident_low_limit_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (uffd_prefetch &&
        parse_count_env(uffd_prefetch, &uffd_prefetch_chunks) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (migration_chunk && parse_size_env(migration_chunk, &migration_chunk_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (migration_policy_env &&
        parse_migration_policy_env(migration_policy_env,
                                   &migration_policy) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    policy_observe_prefetch_writes = parse_bool_env(observe_prefetch_writes);
    if (file_dedicated_min &&
        parse_size_env(file_dedicated_min, &file_dedicated_min_bytes) != 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (backend && backend[0] != '\0') {
        if (strcmp(backend, "auto") == 0) {
            backend_mode = BACKEND_MODE_AUTO;
        } else if (strcmp(backend, "anon") == 0 ||
                   strcmp(backend, "anonymous") == 0) {
            backend_mode = BACKEND_MODE_ANON;
        } else if (strcmp(backend, "file") == 0 ||
                   strcmp(backend, "arena") == 0) {
            backend_mode = BACKEND_MODE_FILE;
        } else {
            runtime_config_error = 1;
            return -1;
        }
    }
    if (uffd_pager && uffd_pager[0] != '\0') {
        if (strcmp(uffd_pager, "off") == 0 ||
            strcmp(uffd_pager, "0") == 0 ||
            strcmp(uffd_pager, "false") == 0) {
            uffd_pager_mode = UFFD_PAGER_OFF;
        } else if (strcmp(uffd_pager, "auto") == 0 ||
                   strcmp(uffd_pager, "1") == 0 ||
                   strcmp(uffd_pager, "true") == 0) {
            uffd_pager_mode = UFFD_PAGER_AUTO;
        } else if (strcmp(uffd_pager, "required") == 0 ||
                   strcmp(uffd_pager, "require") == 0) {
            uffd_pager_mode = UFFD_PAGER_REQUIRED;
        } else {
            runtime_config_error = 1;
            return -1;
        }
    }
    if (uffd_pager_mode != UFFD_PAGER_OFF) {
        uffd_pager_available = probe_userfaultfd_pager();
        stats_snapshot.uffd_pager_available = (size_t)uffd_pager_available;
        if (!uffd_pager_available) {
            pthread_mutex_lock(&uffd_fault_lock);
            stats_snapshot.uffd_fallbacks++;
            pthread_mutex_unlock(&uffd_fault_lock);
            if (uffd_pager_mode == UFFD_PAGER_REQUIRED) {
                runtime_config_error = 1;
                return -1;
            }
        }
    }

    if (threshold_bytes == 0) {
        threshold_bytes = 1;
    }
    if (arena_size_bytes < MAI_MIN_ARENA_SIZE) {
        arena_size_bytes = MAI_MIN_ARENA_SIZE;
    }
    if (file_dedicated_min_bytes != 0 && file_dedicated_min_bytes < page_size) {
        file_dedicated_min_bytes = page_size;
    }
    if (auto_large_alloc_cap_percent > 100) {
        runtime_config_error = 1;
        return -1;
    }
    if (hotness_sample_pages == 0) {
        hotness_sample_pages = 1;
    }
    if (hotness_sample_pages > MAI_MAX_HOTNESS_SAMPLE_PAGES) {
        hotness_sample_pages = MAI_MAX_HOTNESS_SAMPLE_PAGES;
    }
    if (heartbeat_min_quiet_epochs == 0) {
        heartbeat_min_quiet_epochs = 1;
    }
    if (background_heartbeat_interval_us == 0) {
        background_heartbeat_interval_us = 1;
    }
    if (background_heartbeat_observe_pages == 0) {
        background_heartbeat_observe_pages = 1;
    }
    if (background_heartbeat_observe_pages > MAI_ACCESS_TRACE_MAX_PAGES) {
        background_heartbeat_observe_pages = MAI_ACCESS_TRACE_MAX_PAGES;
    }
    if (background_heartbeat_chunk_bytes < page_size) {
        background_heartbeat_chunk_bytes = page_size;
    }
    background_heartbeat_chunk_bytes =
        align_up_size(background_heartbeat_chunk_bytes, page_size);
    background_heartbeat_migrate_bytes -=
        background_heartbeat_migrate_bytes % page_size;
    if (uffd_prefetch_chunks == 0) {
        uffd_prefetch_chunks = 1;
    }
    if (uffd_prefetch_chunks > MAI_MAX_UFFD_PREFETCH_CHUNKS) {
        uffd_prefetch_chunks = MAI_MAX_UFFD_PREFETCH_CHUNKS;
    }
    if (uffd_pager_mode != UFFD_PAGER_OFF && !uffd_resident_limit_explicit) {
        size_t cap = 0;
        if (max_rss_enabled) {
            cap = max_rss_auto ?
                detect_auto_max_rss_bytes(sample_process_rss_bytes()) :
                max_rss_bytes;
        }
        uffd_resident_limit_bytes = cap == 0 ? 0 :
            percent_of_size(cap, MAI_AUTO_ANON_LIMIT_PERCENT);
    }
    if (uffd_resident_limit_bytes != 0) {
        if (uffd_resident_limit_bytes < page_size) {
            uffd_resident_limit_bytes = page_size;
        }
        uffd_resident_limit_bytes =
            align_up_size(uffd_resident_limit_bytes, page_size);
    }
    if (uffd_resident_low_limit_bytes != 0) {
        if (uffd_resident_low_limit_bytes < page_size) {
            uffd_resident_low_limit_bytes = page_size;
        }
        uffd_resident_low_limit_bytes =
            align_up_size(uffd_resident_low_limit_bytes, page_size);
        if (uffd_resident_limit_bytes != 0 &&
            uffd_resident_low_limit_bytes > uffd_resident_limit_bytes) {
            uffd_resident_low_limit_bytes = uffd_resident_limit_bytes;
        }
    }
    if (migration_chunk_bytes < page_size) {
        migration_chunk_bytes = page_size;
    }
    migration_chunk_bytes = align_up_size(migration_chunk_bytes, page_size);
    if (migration_chunk_bytes == 0) {
        runtime_config_error = 1;
        return -1;
    }
    if (max_rss_enabled && max_rss_auto) {
        max_rss_bytes = detect_auto_max_rss_bytes(sample_process_rss_bytes());
        stats_snapshot.max_rss = max_rss_bytes;
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

    if (MAI_LIKELY(size < threshold_bytes || size == 0 || mlockall_future_active)) {
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

    if (MAI_LIKELY(total < threshold_bytes || total == 0 || mlockall_future_active)) {
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
            if (size != old_size) {
                stop_record_access_trace_locked(record);
                clear_record_hint_locked(record);
            }
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
        AllocationRecord* record = NULL;
        if (ensure_memory_cap_headroom_locked(0) == 0) {
            record = managed_alloc_locked(size, alignment, call_site);
        }
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

static int replace_fast_optional(gpointer address, gpointer replacement,
                                 gpointer* original, int* replaced,
                                 const char* name) {
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

    if (verbose_logging) {
        fprintf(stderr,
                "MAI: skipping optional replacement for %s: fast=%d regular=%d\n",
                name, ret, regular_ret);
    }
    return 0;
}

static int replace_regular_optional(gpointer address, gpointer replacement,
                                    gpointer* original, int* replaced,
                                    const char* name) {
    GumReplaceReturn ret;

    if (!address) {
        return 0;
    }

    ret = gum_interceptor_replace(malloc_interceptor, address, replacement, NULL, original);
    if (ret == GUM_REPLACE_OK) {
        *replaced = 1;
        return 0;
    }

    if (verbose_logging) {
        fprintf(stderr, "MAI: skipping optional replacement for %s: %d\n", name, ret);
    }
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
        replace_regular_optional(posix_memalign_addr, (gpointer)frida_posix_memalign,
                                 (gpointer*)&original_posix_memalign,
                                 &posix_memalign_replaced, "posix_memalign");
        replace_fast_optional(memalign_addr, (gpointer)frida_memalign,
                              (gpointer*)&original_memalign, &memalign_replaced,
                              "memalign");
        replace_fast_optional(valloc_addr, (gpointer)frida_valloc,
                              (gpointer*)&original_valloc, &valloc_replaced, "valloc");
        replace_fast_optional(pvalloc_addr, (gpointer)frida_pvalloc,
                              (gpointer*)&original_pvalloc, &pvalloc_replaced, "pvalloc");
        replace_fast_optional(malloc_usable_size_addr, (gpointer)frida_malloc_usable_size,
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
    (void)start_background_heartbeat();
    if (verbose_logging) {
        fprintf(stderr,
                "MAI: enabled path=%s threshold=%zu arena_size=%zu target_rss=%zu "
                "max_rss=%zu reclaim=%d file_dedicated_min=%zu "
                "auto_large_alloc_cap_percent=%zu "
                "allocator_hooks=%s\n",
                mai_path, threshold_bytes, arena_size_bytes, target_rss_bytes,
                max_rss_bytes, reclaim_policy, file_dedicated_min_bytes,
                auto_large_alloc_cap_percent,
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
    stop_background_heartbeat();
    stop_uffd_pager();
    revert_replacements();

    pthread_mutex_lock(&runtime_lock);
    stop_all_access_traces_locked();
    pthread_mutex_unlock(&runtime_lock);
    restore_access_trace_handler();

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
