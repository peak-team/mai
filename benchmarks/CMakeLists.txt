if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    return()
endif()

add_executable(mai_access_pattern_benchmark access_pattern_benchmark.c)
target_compile_features(mai_access_pattern_benchmark PRIVATE c_std_11)
target_include_directories(mai_access_pattern_benchmark PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_access_pattern_benchmark PRIVATE Threads::Threads ${DL_LIBRARY})

if(BUILD_TESTING)
    add_test(
        NAME mai_stream_kernel_pipeline_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_STREAM_PIPELINE_CYCLES=4"
            "MAI_STREAM_PIPELINE_GROUP_ITERATIONS=2"
            "MAI_STREAM_PIPELINE_SCALAR=0.125"
            "MAI_STREAM_TILE=2M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            stream_kernel_pipeline
            16M
    )
    set_tests_properties(mai_stream_kernel_pipeline_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=stream_kernel_pipeline .*logical_mib=1280\\.000 .*stream_pipeline_kernels=4 .*stream_pipeline_groups=3 .*stream_pipeline_group_iterations=2 .*stream_pipeline_matrix_bytes=16777216 .*stream_pipeline_scalar=0\\.125000"
    )

    add_test(
        NAME mai_stream_kernel_pipeline_random_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_STREAM_PIPELINE_CYCLES=5"
            "MAI_STREAM_PIPELINE_GROUP_ITERATIONS=2"
            "MAI_STREAM_PIPELINE_ORDER=random_no_repeat"
            "MAI_STREAM_PIPELINE_SEED=7"
            "MAI_STREAM_PIPELINE_SCALAR=0.125"
            "MAI_STREAM_TILE=2M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            stream_kernel_pipeline
            16M
    )
    set_tests_properties(mai_stream_kernel_pipeline_random_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=stream_kernel_pipeline .*logical_mib=1600\\.000 .*stream_pipeline_order=random_no_repeat .*stream_pipeline_seed=7 .*stream_pipeline_prediction=none"
    )
endif()
