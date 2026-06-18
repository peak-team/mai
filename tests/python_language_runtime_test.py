#!/usr/bin/env python3

import ctypes
import gc
import os
import sys


class MaiStats(ctypes.Structure):
    _fields_ = [
        ("enabled", ctypes.c_int),
        ("configured", ctypes.c_int),
        ("config_error", ctypes.c_int),
        ("threshold", ctypes.c_size_t),
        ("arena_size", ctypes.c_size_t),
        ("target_rss", ctypes.c_size_t),
        ("current_rss_bytes", ctypes.c_size_t),
        ("high_water_rss_bytes", ctypes.c_size_t),
        ("arena_segments", ctypes.c_size_t),
        ("arena_bytes", ctypes.c_size_t),
        ("managed_bytes_total", ctypes.c_size_t),
        ("pass_through_bytes_total", ctypes.c_size_t),
        ("live_managed_bytes", ctypes.c_size_t),
        ("high_water_managed_bytes", ctypes.c_size_t),
        ("managed_allocations", ctypes.c_size_t),
        ("pass_through_allocations", ctypes.c_size_t),
        ("managed_frees", ctypes.c_size_t),
        ("reclaim_calls", ctypes.c_size_t),
        ("policy_reclaim_calls", ctypes.c_size_t),
        ("reclaimed_bytes", ctypes.c_size_t),
        ("mmap_calls", ctypes.c_size_t),
        ("munmap_calls", ctypes.c_size_t),
        ("mremap_calls", ctypes.c_size_t),
        ("brk_calls", ctypes.c_size_t),
        ("sbrk_calls", ctypes.c_size_t),
        ("profile_sites", ctypes.c_size_t),
        ("hotness_samples", ctypes.c_size_t),
        ("hotness_sampled_pages", ctypes.c_size_t),
        ("hotness_resident_pages", ctypes.c_size_t),
        ("allocator_hook_mode", ctypes.c_size_t),
        ("allocator_libc_patches", ctypes.c_size_t),
        ("allocator_preload_calls", ctypes.c_size_t),
        ("allocator_frida_calls", ctypes.c_size_t),
        ("excluded_ranges", ctypes.c_size_t),
        ("excluded_bytes", ctypes.c_size_t),
        ("exclusion_events", ctypes.c_size_t),
        ("exclusion_release_events", ctypes.c_size_t),
        ("reclaim_skipped_excluded", ctypes.c_size_t),
        ("reclaim_skipped_excluded_bytes", ctypes.c_size_t),
        ("safety_hook_patches", ctypes.c_size_t),
        ("max_rss", ctypes.c_size_t),
        ("memory_cap_reclaim_calls", ctypes.c_size_t),
        ("memory_cap_failures", ctypes.c_size_t),
    ]


def fail(message):
    print(message, file=sys.stderr)
    return 1


def load_runtime():
    runtime = ctypes.CDLL(None)
    runtime.mai_get_stats.argtypes = [ctypes.POINTER(MaiStats)]
    runtime.mai_get_stats.restype = ctypes.c_int
    runtime.malloc_usable_size.argtypes = [ctypes.c_void_p]
    runtime.malloc_usable_size.restype = ctypes.c_size_t
    return runtime


def load_stats(runtime):
    stats = MaiStats()
    if runtime.mai_get_stats(ctypes.byref(stats)) != 0:
        raise RuntimeError("mai_get_stats failed")
    return stats


def check_managed_delta(before, after, size, label):
    if (
        after.managed_allocations <= before.managed_allocations
        or after.managed_bytes_total < before.managed_bytes_total + size
        or after.live_managed_bytes < before.live_managed_bytes + size
        or after.arena_segments == 0
    ):
        return fail(f"{label} allocation was not managed by MAI")
    return 0


def mode_raw(runtime, alloc_size):
    raw_malloc = ctypes.pythonapi.PyMem_RawMalloc
    raw_malloc.argtypes = [ctypes.c_size_t]
    raw_malloc.restype = ctypes.c_void_p
    raw_realloc = ctypes.pythonapi.PyMem_RawRealloc
    raw_realloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    raw_realloc.restype = ctypes.c_void_p
    raw_free = ctypes.pythonapi.PyMem_RawFree
    raw_free.argtypes = [ctypes.c_void_p]
    raw_free.restype = None

    before = load_stats(runtime)
    ptr = raw_malloc(alloc_size)
    if not ptr:
        return fail("PyMem_RawMalloc failed")

    current = ptr
    try:
        ctypes.memset(current, 0x5A, alloc_size)
        after_alloc = load_stats(runtime)
        rc = check_managed_delta(before, after_alloc, alloc_size, "PyMem_RawMalloc")
        if rc != 0:
            return rc
        if runtime.malloc_usable_size(current) < alloc_size:
            return fail("malloc_usable_size did not recognize PyMem_RawMalloc block")

        grown_size = alloc_size + 4096
        grown = raw_realloc(current, grown_size)
        if not grown:
            return fail("PyMem_RawRealloc failed")
        current = grown

        data = (ctypes.c_ubyte * alloc_size).from_address(current)
        if data[0] != 0x5A or data[alloc_size - 1] != 0x5A:
            return fail("PyMem_RawRealloc did not preserve contents")

        ctypes.memset(current + alloc_size, 0x6B, grown_size - alloc_size)
        after_realloc = load_stats(runtime)
        rc = check_managed_delta(before, after_realloc, grown_size, "PyMem_RawRealloc")
        if rc != 0:
            return rc
    finally:
        raw_free(current)

    final = load_stats(runtime)
    if final.managed_frees <= before.managed_frees:
        return fail("PyMem_RawFree did not release a MAI-managed block")
    if final.live_managed_bytes != before.live_managed_bytes:
        return fail("PyMem_RawFree leaked MAI-managed live bytes")
    return 0


def mode_numpy(runtime, alloc_size):
    try:
        import numpy as np
    except ImportError:
        print("NumPy is not installed; skipping optional NumPy runtime test")
        return 77

    before = load_stats(runtime)
    array = np.empty(alloc_size, dtype=np.uint8)
    array[0] = 0x2A
    array[-1] = 0x7E

    data_ptr = int(array.__array_interface__["data"][0])
    if runtime.malloc_usable_size(data_ptr) < alloc_size:
        return fail("malloc_usable_size did not recognize NumPy data buffer")

    after = load_stats(runtime)
    rc = check_managed_delta(before, after, alloc_size, "NumPy data")
    if rc != 0:
        return rc

    del array
    gc.collect()
    return 0


def main():
    if len(sys.argv) != 2:
        return fail("usage: python_language_runtime_test.py raw|numpy")

    runtime = load_runtime()
    alloc_size = int(os.environ.get("MAI_TEST_ALLOC_SIZE", "2097152"))

    if sys.argv[1] == "raw":
        return mode_raw(runtime, alloc_size)
    if sys.argv[1] == "numpy":
        return mode_numpy(runtime, alloc_size)
    return fail(f"unknown mode: {sys.argv[1]}")


if __name__ == "__main__":
    sys.exit(main())
