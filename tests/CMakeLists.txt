if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    return()
endif()

set(MAI_TEST_SCRATCH "${CMAKE_CURRENT_BINARY_DIR}/scratch")
set(MAI_TEST_INVALID "${CMAKE_CURRENT_BINARY_DIR}/invalid-path")
file(MAKE_DIRECTORY "${MAI_TEST_SCRATCH}")

add_executable(mai_runtime_test runtime_test.c)
target_compile_features(mai_runtime_test PRIVATE c_std_11)
target_include_directories(mai_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_runtime_test PRIVATE Threads::Threads ${DL_LIBRARY})

add_library(mai_runtime_plugin SHARED runtime_plugin.c)
target_compile_features(mai_runtime_plugin PRIVATE c_std_11)

add_executable(mai_cxx_runtime_test cxx_runtime_test.cpp)
target_compile_features(mai_cxx_runtime_test PRIVATE cxx_std_17)
target_include_directories(mai_cxx_runtime_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_cxx_runtime_test PRIVATE mai ${DL_LIBRARY})

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
add_mai_runtime_test(mai_mmap_brk_diagnostics diagnostics)

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
    NAME mai_cxx_new_delete
    COMMAND ${CMAKE_COMMAND} -E env
        "MAI_ENABLE=1"
        "MAI_PATH=${MAI_TEST_SCRATCH}"
        "MAI_THRESHOLD=4K"
        "MAI_ARENA_SIZE=1M"
        "LD_PRELOAD=$<TARGET_FILE:mai>"
        $<TARGET_FILE:mai_cxx_runtime_test>
)

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
