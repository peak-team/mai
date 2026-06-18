if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    return()
endif()

add_executable(mai_access_pattern_benchmark access_pattern_benchmark.c)
target_compile_features(mai_access_pattern_benchmark PRIVATE c_std_11)
target_include_directories(mai_access_pattern_benchmark PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(mai_access_pattern_benchmark PRIVATE ${DL_LIBRARY})
