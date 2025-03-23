# Add all source files
FILE(GLOB sources_mai
    mai.c
    malloc_interceptor.c
)

add_library(mai 
    SHARED 
        ${sources_mai}
)

target_include_directories(mai
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
        ${FRIDA_GUM_INCLUDE_DIRS}
)

target_link_libraries(mai
    PRIVATE
       ${FRIDA_GUM_LIBRARIES}
        Threads::Threads
        ${DL_LIBRARY}
        ${RT_LIBRARY}
        ${RESOLV_LIBRARY}
        ${M_LIBRARY}
)

install (TARGETS mai DESTINATION lib)
