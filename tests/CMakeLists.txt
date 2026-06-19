if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    return()
endif()

set(MAI_TEST_SCRATCH "${CMAKE_CURRENT_BINARY_DIR}/scratch")
set(MAI_TEST_INVALID "${CMAKE_CURRENT_BINARY_DIR}/invalid-path")
file(MAKE_DIRECTORY "${MAI_TEST_SCRATCH}")

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.12")
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        set(MAI_PYTHON_EXECUTABLE "${Python3_EXECUTABLE}")
    endif()
else()
    find_package(PythonInterp 3 QUIET)
    if(PYTHONINTERP_FOUND)
        set(MAI_PYTHON_EXECUTABLE "${PYTHON_EXECUTABLE}")
    endif()
endif()

add_executable(mai_runtime_test runtime_test.c)
target_compile_features(mai_runtime_test PRIVATE c_std_11)
target_include_directories(mai_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_runtime_test PRIVATE Threads::Threads ${DL_LIBRARY})

add_library(mai_runtime_plugin SHARED runtime_plugin.c)
target_compile_features(mai_runtime_plugin PRIVATE c_std_11)

add_library(mai_local_allocator_plugin SHARED local_allocator_plugin.c)
target_compile_features(mai_local_allocator_plugin PRIVATE c_std_11)
set_target_properties(mai_local_allocator_plugin PROPERTIES
    LINK_FLAGS "-Wl,-Bsymbolic-functions"
)

add_library(mai_exclusion_plugin SHARED exclusion_plugin.c)
target_compile_features(mai_exclusion_plugin PRIVATE c_std_11)
set_target_properties(mai_exclusion_plugin PROPERTIES
    LINK_FLAGS "-Wl,-Bsymbolic-functions"
)

add_executable(mai_cxx_runtime_test cxx_runtime_test.cpp)
target_compile_features(mai_cxx_runtime_test PRIVATE cxx_std_17)
target_include_directories(mai_cxx_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_cxx_runtime_test PRIVATE mai ${DL_LIBRARY})

add_executable(mai_benchmark benchmark_test.c)
target_compile_features(mai_benchmark PRIVATE c_std_11)
target_include_directories(mai_benchmark PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_benchmark PRIVATE Threads::Threads ${DL_LIBRARY})

function(add_mai_runtime_test name mode)
    add_test(
        NAME ${name}
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=4K"
            "MAI_ARENA_SIZE=1M"
            ${ARGN}
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            $<TARGET_FILE:mai_runtime_test>
            ${mode}
    )
endfunction()

add_mai_runtime_test(mai_small_pass_through small)
add_mai_runtime_test(mai_pass_through_stats_default_off pass_through_stats_default_off)
add_mai_runtime_test(mai_direct_preload_symbols preload_symbols)
add_mai_runtime_test(mai_missing_safety_runtime_symbols missing_safety_symbols)
add_mai_runtime_test(mai_large_managed large)
add_mai_runtime_test(mai_calloc calloc)
add_mai_runtime_test(mai_realloc realloc)
add_mai_runtime_test(mai_alignment alignment "MAI_STATS=1")
add_mai_runtime_test(mai_many_allocations many)
add_mai_runtime_test(mai_multithreaded thread)
add_mai_runtime_test(
    mai_multithreaded_small_pass_through_stats
    thread_small_stats
    "MAI_STATS=1"
)
add_mai_runtime_test(mai_mmap_brk_diagnostics diagnostics)

add_test(
    NAME mai_direct_preload_path_stats
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_PATH_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        preload_path_stats
)

add_test(
    NAME mai_forced_frida_allocator_mode
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_ALLOCATOR_HOOKS=frida"
        "MAI_PATH_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        frida_hook_mode
)

add_test(
    NAME mai_scratch_env_discovery
    COMMAND ${CMAKE_COMMAND} -E env
        --unset=MAI_PATH
        --unset=PBS_JOBFS
        --unset=TMPDIR
        --unset=LOCAL_SCRATCH
        --unset=SCRATCH
        --unset=JOBSCRATCH
        "SLURM_TMPDIR=${MAI_TEST_SCRATCH}"
        "MAI_ENABLE=1"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        large
)

add_test(
    NAME mai_unprivileged_runtime
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        unprivileged
)
set_tests_properties(mai_unprivileged_runtime PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_dlopen_allocations
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_TEST_PLUGIN=$<TARGET_FILE:mai_runtime_plugin>"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        dlopen
)

add_test(
    NAME mai_dlopen_local_allocator_symbols
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_TEST_LOCAL_ALLOCATOR_PLUGIN=$<TARGET_FILE:mai_local_allocator_plugin>"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        dlopen_local_allocator
)

add_test(
    NAME mai_dlopen_local_allocator_fallback_path_stats
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_PATH_STATS=1"
        "MAI_TEST_LOCAL_ALLOCATOR_PLUGIN=$<TARGET_FILE:mai_local_allocator_plugin>"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        dlopen_local_allocator
)

add_test(
    NAME mai_dlopen_safety_exclusion_symbols
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "MAI_TEST_EXCLUSION_PLUGIN=$<TARGET_FILE:mai_exclusion_plugin>"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        dlopen_exclusions
)

add_test(
    NAME mai_cxx_new_delete
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_cxx_runtime_test>
)

if(MAI_PYTHON_EXECUTABLE)
    add_test(
        NAME mai_python_ctypes_dlopen
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=1M"
            "MAI_ARENA_SIZE=8M"
            "MAI_TEST_ALLOC_SIZE=2097152"
            "MAI_TEST_PLUGIN=$<TARGET_FILE:mai_runtime_plugin>"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            ${MAI_PYTHON_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/python_runtime_test.py
    )

    add_test(
        NAME mai_python_raw_allocator
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=1M"
            "MAI_ARENA_SIZE=8M"
            "MAI_TEST_ALLOC_SIZE=2097152"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            ${MAI_PYTHON_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/python_language_runtime_test.py
            raw
    )

    add_test(
        NAME mai_python_numpy_array_optional
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=1M"
            "MAI_ARENA_SIZE=8M"
            "MAI_TEST_ALLOC_SIZE=2097152"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            ${MAI_PYTHON_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/python_language_runtime_test.py
            numpy
    )
    set_tests_properties(mai_python_numpy_array_optional PROPERTIES SKIP_RETURN_CODE 77)

    add_test(
        NAME mai_source_policy_no_privileged_kernel_dependencies
        COMMAND ${MAI_PYTHON_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/source_policy_test.py
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/include
    )
endif()

include(CheckLanguage)
check_language(Fortran)
if(CMAKE_Fortran_COMPILER)
    enable_language(Fortran)
    add_executable(mai_fortran_runtime_test fortran_runtime_test.f90)
    target_link_libraries(mai_fortran_runtime_test PRIVATE mai)
    add_test(
        NAME mai_fortran_runtime_allocations
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=4K"
            "MAI_ARENA_SIZE=1M"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            $<TARGET_FILE:mai_fortran_runtime_test>
    )
endif()

find_package(MPI COMPONENTS C QUIET)
if(MPI_C_FOUND)
    add_executable(mai_mpi_runtime_test mpi_runtime_test.c)
    target_compile_features(mai_mpi_runtime_test PRIVATE c_std_11)
    target_include_directories(mai_mpi_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(mai_mpi_runtime_test PRIVATE MPI::MPI_C ${DL_LIBRARY})
    add_test(
        NAME mai_real_mpi_alloc_mem_exclusion
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=4K"
            "MAI_ARENA_SIZE=1M"
            "UCX_TLS=self"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            $<TARGET_FILE:mai_mpi_runtime_test>
    )
    set_tests_properties(mai_real_mpi_alloc_mem_exclusion PROPERTIES SKIP_RETURN_CODE 77)
endif()

add_test(
    NAME mai_reclaim_dontneed
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        reclaim
)

add_test(
    NAME mai_reclaim_pageout
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=pageout"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        reclaim
)

add_test(
    NAME mai_sufficient_memory_fast_path
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_MAX_RSS=off"
        "MAI_RECLAIM_POLICY=none"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        sufficient_memory_fast_path
)

add_test(
    NAME mai_predictive_range_api
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        predictive_range_api
)

add_test(
    NAME mai_intrusive_access_trace
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        access_trace
)

add_test(
    NAME mai_adaptive_heartbeat
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        adaptive_heartbeat
)

add_test(
    NAME mai_heartbeat_busy_tick_no_migration
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        heartbeat_busy_no_migration
)

add_test(
    NAME mai_heartbeat_chunk_size_sensitivity
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=2M"
        "MAI_MIGRATION_CHUNK=4K"
        "MAI_RECLAIM_POLICY=donthneed"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        heartbeat_chunk_sensitivity
)

add_test(
    NAME mai_access_trace_concurrent_stress
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=none"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        access_trace_concurrent_stress
)

add_test(
    NAME mai_heartbeat_round_robin_fairness
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_RECLAIM_POLICY=none"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        heartbeat_round_robin_fairness
)

add_test(
    NAME mai_target_rss_policy_reclaim
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_TARGET_RSS=8K"
        "MAI_RECLAIM_POLICY=donthneed"
        "MAI_RECLAIM_SELECTION=largest"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        target_rss
)

add_test(
    NAME mai_target_rss_policy_reclaim_all
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_TARGET_RSS=8K"
        "MAI_RECLAIM_POLICY=donthneed"
        "MAI_RECLAIM_SELECTION=all"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        target_rss
)

add_test(
    NAME mai_target_rss_policy_reclaim_adaptive
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_TARGET_RSS=8K"
        "MAI_RECLAIM_POLICY=donthneed"
        "MAI_RECLAIM_SELECTION=adaptive"
        "MAI_HOTNESS_SAMPLE_PAGES=4"
        "MAI_EXPECT_ADAPTIVE_RECLAIM=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        target_rss
)

add_test(
    NAME mai_memory_cap_auto_detected
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        memory_cap_auto
)

add_test(
    NAME mai_memory_cap_off
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_MAX_RSS=off"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        memory_cap_off
)

add_test(
    NAME mai_memory_cap_chunked_calloc
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_BACKEND=file"
        "MAI_MAX_RSS=32M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        memory_cap_chunked_calloc
)

add_test(
    NAME mai_backend_auto_pressure_prefers_file
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        backend_auto_pressure_file
)

add_test(
    NAME mai_file_large_allocations_use_dedicated_segments
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_FILE_DEDICATED_MIN=4M"
        "MAI_BACKEND=file"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        file_dedicated_segments
)

add_test(
    NAME mai_legacy_stats_abi
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        legacy_stats_abi
)

add_test(
    NAME mai_uffd_pager_auto_probe
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_UFFD_PAGER=auto"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_probe
)

add_test(
    NAME mai_uffd_pager_required_probe
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_probe
)
set_tests_properties(mai_uffd_pager_required_probe PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_auto_register_fallback
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=auto"
        "MAI_UFFD_TEST_REGISTER_FAIL=1"
        "MAI_MIGRATION_CHUNK=2M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_auto_register_fallback
)

add_test(
    NAME mai_uffd_pager_faults
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_EXPECT_EVICTIONS=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_MIGRATION_CHUNK=2M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_faults
)
set_tests_properties(mai_uffd_pager_faults PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_record_protect_pressure
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_EXPECT_EVICTIONS=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_RECORD_PROTECT_EPOCHS=8"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=2q"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_record_protect_policy
)
set_tests_properties(mai_uffd_pager_record_protect_pressure
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_active_record_pressure
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=2M"
        "MAI_UFFD_PREFETCH_CHUNKS=1"
        "MAI_ACTIVE_RECORD_EPOCHS=16"
        "MAI_ACTIVE_RECORD_SLACK_CHUNKS=2"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=legacy"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_active_record_policy
)
set_tests_properties(mai_uffd_pager_active_record_pressure
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_active_record_prefetch_guard
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=64M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=24M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=12M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=10M"
        "MAI_UFFD_PREFETCH_CHUNKS=8"
        "MAI_ACTIVE_RECORD_EPOCHS=32"
        "MAI_ACTIVE_RECORD_SLACK_CHUNKS=1"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=legacy"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_active_record_prefetch_guard
)
set_tests_properties(mai_uffd_pager_active_record_prefetch_guard
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_adaptive_policy_throttle
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=64M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=4M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=markov"
        "MAI_POLICY_ADAPTIVE_CONTROL=1"
        "MAI_POLICY_ADAPTIVE_WINDOW_FAULTS=2"
        "MAI_POLICY_ADAPTIVE_MIGRATION_BUDGET_CHUNKS=1"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_adaptive_policy_throttle
)
set_tests_properties(mai_uffd_pager_adaptive_policy_throttle
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_adaptive_legacy_noop
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=64M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=4M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=legacy"
        "MAI_POLICY_ADAPTIVE_CONTROL=1"
        "MAI_POLICY_ADAPTIVE_WINDOW_FAULTS=2"
        "MAI_POLICY_ADAPTIVE_MIGRATION_BUDGET_CHUNKS=1"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_adaptive_legacy_noop
)
set_tests_properties(mai_uffd_pager_adaptive_legacy_noop
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_clean_shadow_skip
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=64M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_RESIDENT_LIMIT=2M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=2M"
        "MAI_UFFD_PREFETCH_CHUNKS=1"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_UFFD_CLEAN_SHADOW=1"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_clean_shadow_skip
)
set_tests_properties(mai_uffd_pager_clean_shadow_skip
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_clean_shadow_dirty
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=64M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_RESIDENT_LIMIT=2M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=2M"
        "MAI_UFFD_PREFETCH_CHUNKS=1"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_UFFD_CLEAN_SHADOW=1"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_clean_shadow_dirty
)
set_tests_properties(mai_uffd_pager_clean_shadow_dirty
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_clean_shadow_fallback
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=64M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_RESIDENT_LIMIT=2M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=2M"
        "MAI_UFFD_PREFETCH_CHUNKS=1"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_UFFD_CLEAN_SHADOW=1"
        "MAI_UFFD_CLEAN_SHADOW_FORCE_NO_COPY_WP=1"
        "MAI_UFFD_ALLOW_SKIP=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_clean_shadow_fallback
)
set_tests_properties(mai_uffd_pager_clean_shadow_fallback
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_spatial_prefetch
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=32M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=64M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_spatial_prefetch
)
set_tests_properties(mai_uffd_pager_spatial_prefetch PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_async_prefetch
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_UFFD_ASYNC_PREFETCH=1"
        "MAI_UFFD_ASYNC_SLACK_CHUNKS=2"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=legacy"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_async_prefetch
)
set_tests_properties(mai_uffd_pager_async_prefetch PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_stride_policy
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=32M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=32M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=24M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=stride"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_stride_policy
)
set_tests_properties(mai_uffd_pager_stride_policy PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_stride_policy_single_stream
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=stride"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "MAI_UFFD_STRIDE_ACTIVE_STREAMS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_stride_policy
)
set_tests_properties(mai_uffd_pager_stride_policy_single_stream
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_legacy_single_stride_negative
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=legacy"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "MAI_UFFD_STRIDE_ACTIVE_STREAMS=1"
        "MAI_UFFD_EXPECT_NO_USEFUL_PREFETCH=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_stride_policy
)
set_tests_properties(mai_uffd_pager_legacy_single_stride_negative
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_lfu_hotset_scan
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=lfu"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_lfu_hotset_scan
)
set_tests_properties(mai_uffd_pager_lfu_hotset_scan
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_lruk_hotset_scan
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=lruk"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_lruk_hotset_scan
)
set_tests_properties(mai_uffd_pager_lruk_hotset_scan
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_car_hotset_scan
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=car"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_car_hotset_scan
)
set_tests_properties(mai_uffd_pager_car_hotset_scan
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_tinylfu_hotset_scan
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=8M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=6M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=tinylfu"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_tinylfu_hotset_scan
)
set_tests_properties(mai_uffd_pager_tinylfu_hotset_scan
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_successor_policy
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=32M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=16M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=12M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=markov"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_successor_policy
)
set_tests_properties(mai_uffd_pager_successor_policy
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_spatial_mask_policy
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=128M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=32M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=16M"
        "MAI_UFFD_RESIDENT_LOW_LIMIT=12M"
        "MAI_UFFD_PREFETCH_CHUNKS=4"
        "MAI_MIGRATION_CHUNK=2M"
        "MAI_MIGRATION_POLICY=spatial"
        "MAI_SPATIAL_REGION_CHUNKS=8"
        "MAI_POLICY_OBSERVE_PREFETCH_WRITES=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_spatial_mask_policy
)
set_tests_properties(mai_uffd_pager_spatial_mask_policy
    PROPERTIES SKIP_RETURN_CODE 77)

add_test(
    NAME mai_uffd_pager_concurrent_stress
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=32M"
        "MAI_BACKEND=auto"
        "MAI_MAX_RSS=16M"
        "MAI_UFFD_PAGER=required"
        "MAI_UFFD_ALLOW_SKIP=1"
        "MAI_UFFD_RESIDENT_LIMIT=24M"
        "MAI_MIGRATION_CHUNK=2M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        uffd_pager_concurrent_stress
)
set_tests_properties(mai_uffd_pager_concurrent_stress PROPERTIES SKIP_RETURN_CODE 77)

if(MAI_ENABLE_DOCKER_TESTS)
    add_test(
        NAME mai_docker_cgroup_memory_limit
        COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/docker_memory_limit_test.sh
            $<TARGET_FILE:mai>
            $<TARGET_FILE:mai_runtime_test>
    )
    set_tests_properties(mai_docker_cgroup_memory_limit PROPERTIES
        SKIP_RETURN_CODE 77
        LABELS docker
    )
endif()

add_test(
    NAME mai_backing_file_creation_failure
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=8388608T"
        "MAI_BACKEND=file"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        backing_failure
)

add_test(
    NAME mai_profile_call_sites
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_PROFILE=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        profile
)

add_test(
    NAME mai_hotness_sampling
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_PROFILE=1"
        "MAI_HOTNESS=1"
        "MAI_HOTNESS_SAMPLE_PAGES=8"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        hotness
)

add_test(
    NAME mai_hotness_exit_report
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "MAI_HOTNESS=1"
        "MAI_HOTNESS_SAMPLE_PAGES=8"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        hotness_live_exit
)
set_tests_properties(mai_hotness_exit_report PROPERTIES
    PASS_REGULAR_EXPRESSION "MAI hotness report:.*resident="
)

add_test(
    NAME mai_missing_path_disables
    COMMAND ${CMAKE_COMMAND} -E env
        --unset=MAI_PATH
        --unset=SLURM_TMPDIR
        --unset=PBS_JOBFS
        --unset=TMPDIR
        --unset=LOCAL_SCRATCH
        --unset=SCRATCH
        --unset=JOBSCRATCH
        "MAI_ENABLE=1"
        "MAI_THRESHOLD=4K"
        "MAI_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        disabled
)

add_test(
    NAME mai_invalid_path_disables
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_INVALID}"
        "MAI_THRESHOLD=4K"
        "MAI_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        disabled
)

add_test(
    NAME mai_invalid_reclaim_selection_disables
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_RECLAIM_SELECTION=invalid"
        "MAI_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        disabled
)

add_test(
    NAME mai_invalid_hotness_sample_disables
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_HOTNESS=1"
        "MAI_HOTNESS_SAMPLE_PAGES=bad"
        "MAI_STATS=1"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_runtime_test>
        disabled
)

add_test(
    NAME mai_benchmark_smoke
    COMMAND $<TARGET_FILE:mai_benchmark> single 1000 64
)
set_tests_properties(mai_benchmark_smoke PROPERTIES
    PASS_REGULAR_EXPRESSION "mode=single .*ns_per_op="
)

add_test(
    NAME mai_benchmark_calloc_smoke
    COMMAND $<TARGET_FILE:mai_benchmark> single_calloc 1000 64
)
set_tests_properties(mai_benchmark_calloc_smoke PROPERTIES
    PASS_REGULAR_EXPRESSION "mode=single_calloc .*ns_per_op="
)

add_test(
    NAME mai_benchmark_direct_preload_path_verified
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=1G"
        "MAI_ARENA_SIZE=1M"
        "MAI_PATH_STATS=1"
        "MAI_BENCH_EXPECT_PATH=preload"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_benchmark>
        single
        10000
        64
)
set_tests_properties(mai_benchmark_direct_preload_path_verified PROPERTIES
    PASS_REGULAR_EXPRESSION "preload_delta=[1-9][0-9]* frida_delta=0"
)

add_test(
    NAME mai_benchmark_forced_frida_path_verified
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=1G"
        "MAI_ARENA_SIZE=1M"
        "MAI_ALLOCATOR_HOOKS=frida"
        "MAI_PATH_STATS=1"
        "MAI_BENCH_ALLOCATOR=libc"
        "MAI_BENCH_EXPECT_PATH=frida"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_benchmark>
        single
        10000
        64
)
set_tests_properties(mai_benchmark_forced_frida_path_verified PROPERTIES
    PASS_REGULAR_EXPRESSION "preload_delta=0 frida_delta=[1-9][0-9]*"
)

add_test(
    NAME mai_benchmark_forced_frida_default_allocator_rejected
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=1G"
        "MAI_ARENA_SIZE=1M"
        "MAI_ALLOCATOR_HOOKS=frida"
        "MAI_PATH_STATS=1"
        "MAI_BENCH_EXPECT_PATH=frida"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_benchmark>
        single
        10000
        64
)
set_tests_properties(mai_benchmark_forced_frida_default_allocator_rejected PROPERTIES
    WILL_FAIL TRUE
)
