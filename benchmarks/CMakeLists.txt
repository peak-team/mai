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

    add_test(
        NAME mai_policy_multistream_stride_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_STREAMS=4"
            "MAI_BENCH_POLICY_PASSES=2"
            "MAI_BENCH_POLICY_STRIDE_UNIT=2M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_multistream_stride
            32M
    )
    set_tests_properties(mai_policy_multistream_stride_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_multistream_stride .*logical_mib=128\\.000 .*stream_pipeline_groups=4 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=strided_streams .*stream_pipeline_prediction=stride"
    )

    add_test(
        NAME mai_policy_hotset_scan_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_HOTSET=4M"
            "MAI_BENCH_POLICY_HOTSET_UNIT=2M"
            "MAI_BENCH_POLICY_HOT_ROUNDS=2"
            "MAI_BENCH_POLICY_SCAN_PASSES=2"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_hotset_scan
            16M
    )
    set_tests_properties(mai_policy_hotset_scan_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_hotset_scan .*logical_mib=48\\.000 .*stream_pipeline_group_visits=6 .*stream_pipeline_groups=2 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=hotset_scan .*stream_pipeline_prediction=admission_lfu"
    )

    add_test(
        NAME mai_policy_successor_cycle_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PASSES=2"
            "MAI_BENCH_POLICY_SUCCESSOR_UNIT=2M"
            "MAI_BENCH_POLICY_SUCCESSOR_MULTIPLIER=5"
            "MAI_BENCH_POLICY_SUCCESSOR_ADDEND=3"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_successor_cycle
            32M
    )
    set_tests_properties(mai_policy_successor_cycle_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_successor_cycle .*logical_mib=128\\.000 .*stream_pipeline_group_visits=2 .*stream_pipeline_groups=16 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=successor_cycle .*stream_pipeline_prediction=successor"
    )

    add_test(
        NAME mai_policy_spatial_region_mask_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PASSES=2"
            "MAI_BENCH_POLICY_SPATIAL_UNIT=2M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_spatial_region_mask
            32M
    )
    set_tests_properties(mai_policy_spatial_region_mask_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_spatial_region_mask .*logical_mib=48\\.000 .*stream_pipeline_group_visits=3 .*stream_pipeline_groups=2 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=spatial_region_mask .*stream_pipeline_prediction=spatial"
    )

    add_test(
        NAME mai_policy_spatial_interleaved_mask_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PASSES=2"
            "MAI_BENCH_POLICY_SPATIAL_UNIT=2M"
            "MAI_BENCH_POLICY_SPATIAL_REGION_UNITS=8"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_spatial_interleaved_mask
            32M
    )
    set_tests_properties(mai_policy_spatial_interleaved_mask_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_spatial_interleaved_mask .*logical_mib=48\\.000 .*stream_pipeline_group_visits=3 .*stream_pipeline_groups=2 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=spatial_interleaved_mask .*stream_pipeline_prediction=spatial"
    )

    add_test(
        NAME mai_policy_spatial_interleaved_small_width_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PASSES=2"
            "MAI_BENCH_POLICY_SPATIAL_UNIT=2M"
            "MAI_BENCH_POLICY_SPATIAL_REGION_UNITS=4"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_spatial_interleaved_mask
            32M
    )
    set_tests_properties(mai_policy_spatial_interleaved_small_width_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_spatial_interleaved_mask .*logical_mib=96\\.000 .*stream_pipeline_group_visits=3 .*stream_pipeline_groups=4 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=spatial_interleaved_mask .*stream_pipeline_prediction=spatial"
    )
endif()
