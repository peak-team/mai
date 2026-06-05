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

add_executable(mai_cxx_runtime_test cxx_runtime_test.cpp)
target_compile_features(mai_cxx_runtime_test PRIVATE cxx_std_17)
target_include_directories(mai_cxx_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_cxx_runtime_test PRIVATE mai ${DL_LIBRARY})

add_executable(mai_benchmark benchmark_test.c)
target_compile_features(mai_benchmark PRIVATE c_std_11)
target_link_libraries(mai_benchmark PRIVATE Threads::Threads)

function(add_mai_runtime_test name mode)
    add_test(
        NAME ${name}
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=4K"
            "MAI_ARENA_SIZE=1M"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            $<TARGET_FILE:mai_runtime_test>
            ${mode}
    )
endfunction()

add_mai_runtime_test(mai_small_pass_through small)
add_mai_runtime_test(mai_large_managed large)
add_mai_runtime_test(mai_calloc calloc)
add_mai_runtime_test(mai_realloc realloc)
add_mai_runtime_test(mai_alignment alignment)
add_mai_runtime_test(mai_many_allocations many)
add_mai_runtime_test(mai_multithreaded thread)
add_mai_runtime_test(mai_multithreaded_small_pass_through_stats thread_small_stats)
add_mai_runtime_test(mai_mmap_brk_diagnostics diagnostics)

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
        NAME mai_fortran_iso_c_binding_malloc
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ENABLE=1"
            "MAI_PATH=${MAI_TEST_SCRATCH}"
            "MAI_THRESHOLD=4K"
            "MAI_ARENA_SIZE=1M"
            "LD_PRELOAD=$<TARGET_FILE:mai>"
            $<TARGET_FILE:mai_fortran_runtime_test>
    )
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
    NAME mai_backing_file_creation_failure
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=8388608T"
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
