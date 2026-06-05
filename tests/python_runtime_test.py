#!/usr/bin/env python3

import ctypes
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


def load_stats(runtime):
    stats = MaiStats()
    if runtime.mai_get_stats(ctypes.byref(stats)) != 0:
        raise RuntimeError("mai_get_stats failed")
    return stats


def main():
    plugin_path = os.environ.get("MAI_TEST_PLUGIN")
    if not plugin_path:
        return fail("MAI_TEST_PLUGIN is not set")
    alloc_size = int(os.environ.get("MAI_TEST_ALLOC_SIZE", "8192"))

    runtime = ctypes.CDLL(None)
    runtime.mai_get_stats.argtypes = [ctypes.POINTER(MaiStats)]
    runtime.mai_get_stats.restype = ctypes.c_int

    plugin = ctypes.CDLL(plugin_path)
    plugin.mai_plugin_alloc.argtypes = [ctypes.c_size_t]
    plugin.mai_plugin_alloc.restype = ctypes.c_void_p
    plugin.mai_plugin_usable.argtypes = [ctypes.c_void_p]
    plugin.mai_plugin_usable.restype = ctypes.c_size_t
    plugin.mai_plugin_free.argtypes = [ctypes.c_void_p]
    plugin.mai_plugin_free.restype = None

    before = load_stats(runtime)

    ptr = plugin.mai_plugin_alloc(alloc_size)
    if not ptr:
        return fail("plugin allocation from Python failed")

    try:
        if plugin.mai_plugin_usable(ptr) < alloc_size:
            return fail("malloc_usable_size did not recognize Python-loaded allocation")
        data = (ctypes.c_ubyte * alloc_size).from_address(ptr)
        if data[0] != 0x3C or data[alloc_size - 1] != 0x3C:
            return fail("Python-loaded plugin allocation contents were wrong")

        after = load_stats(runtime)
        if (
            after.managed_allocations <= before.managed_allocations
            or after.managed_bytes_total < before.managed_bytes_total + alloc_size
            or after.live_managed_bytes < before.live_managed_bytes + alloc_size
            or after.arena_segments == 0
        ):
            return fail("Python-loaded plugin allocation was not managed")
    finally:
        plugin.mai_plugin_free(ptr)

    final = load_stats(runtime)
    if (
        final.managed_frees <= before.managed_frees
        or final.live_managed_bytes != before.live_managed_bytes
    ):
        return fail("Python-loaded plugin free leaked managed bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
