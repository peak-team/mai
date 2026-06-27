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
        NAME mai_submatrix_stream_pipeline_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_SUBMATRIX_SIZE=2M"
            "MAI_BENCH_SUBMATRIX_CYCLES=5"
            "MAI_BENCH_SUBMATRIX_GROUP_ITERATIONS=1"
            "MAI_BENCH_SUBMATRIX_ORDER=hotset"
            "MAI_BENCH_SUBMATRIX_HOT_GROUPS=1"
            "MAI_BENCH_SUBMATRIX_HOT_PROBABILITY=0.75"
            "MAI_BENCH_SUBMATRIX_SEED=3"
            "MAI_BENCH_SUBMATRIX_INIT_ALL=1"
            "MAI_BENCH_STREAM_TILE=1M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            submatrix_stream_pipeline
            24M
    )
    set_tests_properties(mai_submatrix_stream_pipeline_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=submatrix_stream_pipeline .*logical_mib=100\\.000 .*stream_pipeline_groups=4 .*stream_pipeline_total_matrix_bytes=25165824 .*stream_pipeline_order=submatrix_hotset .*stream_pipeline_prediction=submatrix_hot_cold"
    )

    add_test(
        NAME mai_multi_alloc_matrix_pipeline_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_MATRIX_ALLOC_SIZE=2M"
            "MAI_BENCH_SUBMATRIX_CYCLES=5"
            "MAI_BENCH_SUBMATRIX_GROUP_ITERATIONS=1"
            "MAI_BENCH_SUBMATRIX_ORDER=sequential"
            "MAI_BENCH_SUBMATRIX_INIT_ALL=1"
            "MAI_BENCH_STREAM_TILE=1M"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            multi_alloc_matrix_pipeline
            24M
    )
    set_tests_properties(mai_multi_alloc_matrix_pipeline_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=multi_alloc_matrix_pipeline .*logical_mib=100\\.000 .*stream_mapping_kind=multi_malloc .*stream_pipeline_groups=4 .*stream_pipeline_total_matrix_bytes=25165824 .*stream_pipeline_order=submatrix_sequential"
    )

    add_test(
        NAME mai_pure_workload_disables_active_api_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_BENCH_PURE_WORKLOAD=1"
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_ACCESS_STRIDE_PAGES=16"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            sparse
            16M
    )
    set_tests_properties(mai_pure_workload_disables_active_api_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=sparse .*touches=512"
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
        NAME mai_policy_phase_shift_hotset_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PHASE_HOTSET=4M"
            "MAI_BENCH_POLICY_PHASE_UNIT=2M"
            "MAI_BENCH_POLICY_PHASE_WARM_ROUNDS=3"
            "MAI_BENCH_POLICY_PHASE_ACTIVE_ROUNDS=2"
            "MAI_BENCH_POLICY_PHASE_SCAN_PASSES=2"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_phase_shift_hotset
            16M
    )
    set_tests_properties(mai_policy_phase_shift_hotset_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_phase_shift_hotset .*logical_mib=52\\.000 .*stream_pipeline_group_visits=4 .*stream_pipeline_groups=2 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=phase_shift_hotset .*stream_pipeline_prediction=reuse_distance .*stream_pipeline_reclaim_lag=3 .*stream_pipeline_reclaim_horizon=2"
    )

    add_test(
        NAME mai_policy_recency_frequency_pivot_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_PIVOT_HOTSET=4M"
            "MAI_BENCH_POLICY_PIVOT_UNIT=2M"
            "MAI_BENCH_POLICY_PIVOT_WARM_ROUNDS=2"
            "MAI_BENCH_POLICY_PIVOT_BURST_GROUPS=2"
            "MAI_BENCH_POLICY_PIVOT_BURST_ROUNDS=2"
            "MAI_BENCH_POLICY_PIVOT_RETURN_ROUNDS=2"
            "MAI_BENCH_POLICY_PIVOT_SCAN_PASSES=2"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_recency_frequency_pivot
            16M
    )
    set_tests_properties(mai_policy_recency_frequency_pivot_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_recency_frequency_pivot .*logical_mib=104\\.000 .*stream_pipeline_group_visits=6 .*stream_pipeline_groups=3 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=recency_frequency_pivot .*stream_pipeline_prediction=car_adaptive .*stream_pipeline_reclaim_lag=2 .*stream_pipeline_reclaim_horizon=2"
    )

    add_test(
        NAME mai_policy_long_tail_admission_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_LONGTAIL_HOTSET=4M"
            "MAI_BENCH_POLICY_LONGTAIL_MEDIUM=4M"
            "MAI_BENCH_POLICY_LONGTAIL_UNIT=2M"
            "MAI_BENCH_POLICY_LONGTAIL_WARM_ROUNDS=2"
            "MAI_BENCH_POLICY_LONGTAIL_MEDIUM_ROUNDS=1"
            "MAI_BENCH_POLICY_LONGTAIL_COLD_PASSES=2"
            "MAI_BENCH_POLICY_LONGTAIL_PHASE_ROUNDS=2"
            "MAI_BENCH_POLICY_LONGTAIL_SEED=7"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_long_tail_admission
            24M
    )
    set_tests_properties(mai_policy_long_tail_admission_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_long_tail_admission .*logical_mib=88\\.000 .*stream_pipeline_group_visits=6 .*stream_pipeline_groups=3 .*stream_pipeline_group_iterations=4 .*stream_pipeline_order=long_tail_admission .*stream_pipeline_seed=7 .*stream_pipeline_prediction=tinylfu_admission .*stream_pipeline_reclaim_lag=2 .*stream_pipeline_reclaim_horizon=2 .*stream_pipeline_unique_cold_visits=24"
    )

    add_test(
        NAME mai_policy_best_offset_lag_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_OFFSET_UNIT=2M"
            "MAI_BENCH_POLICY_OFFSET_CHUNKS=4"
            "MAI_BENCH_POLICY_OFFSET_LOOKAHEAD=3"
            "MAI_BENCH_POLICY_OFFSET_PASSES=2"
            "MAI_BENCH_POLICY_OFFSET_SEED=5"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_best_offset_lag
            32M
    )
    set_tests_properties(mai_policy_best_offset_lag_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_best_offset_lag .*logical_mib=32\\.000 .*stream_pipeline_group_visits=4 .*stream_pipeline_groups=4 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=best_offset_lag .*stream_pipeline_seed=5 .*stream_pipeline_prediction=best_offset .*stream_pipeline_reclaim_lag=3 .*stream_pipeline_reclaim_horizon=4"
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
        NAME mai_policy_signature_context_cycle_smoke
        COMMAND ${CMAKE_COMMAND} -E env
            "MAI_ACCESS_EXPECT_MANAGED=0"
            "MAI_BENCH_POLICY_SIGNATURE_UNIT=2M"
            "MAI_BENCH_POLICY_SIGNATURE_REGION_UNITS=8"
            "MAI_BENCH_POLICY_SIGNATURE_PASSES=2"
            "MAI_BENCH_POLICY_SIGNATURE_SEED=7"
            $<TARGET_FILE:mai_access_pattern_benchmark>
            policy_signature_context_cycle
            32M
    )
    set_tests_properties(mai_policy_signature_context_cycle_smoke PROPERTIES
        PASS_REGULAR_EXPRESSION "mode=policy_signature_context_cycle .*logical_mib=80\\.000 .*stream_pipeline_group_visits=4 .*stream_pipeline_groups=2 .*stream_pipeline_group_iterations=2 .*stream_pipeline_order=signature_context_cycle .*stream_pipeline_seed=7 .*stream_pipeline_prediction=signature_history .*stream_pipeline_reclaim_horizon=8"
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
