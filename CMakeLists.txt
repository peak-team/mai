cmake_minimum_required(VERSION 3.9)

project(mai C)

# Set build type to Release by default if CMAKE_BUILD_TYPE is not given
set(default_build_type "Debug")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()
message(STATUS "CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")

cmake_host_system_information(RESULT N_CPU QUERY NUMBER_OF_PHYSICAL_CORES)
message(STATUS "N_CPU =  ${N_CPU}")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(CMAKE_BUILD_TYPE MATCHES "Release")
    add_compile_options("SHELL: -Wall -O3")
elseif(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_options("SHELL: -Wall -O0 -g")
endif()
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

find_package(Threads REQUIRED)
find_library(DL_LIBRARY dl)
find_library(RESOLV_LIBRARY resolv)
message(STATUS "M_LIBRARY    = ${M_LIBRARY}")
message(STATUS "RESOLV_LIBRARY   = ${RESOLV_LIBRARY}")
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    find_library(RT_LIBRARY rt)
    find_library(M_LIBRARY m)
    message(STATUS "DL_LIBRARY   = ${DL_LIBRARY}")
    message(STATUS "RT_LIBRARY   = ${RT_LIBRARY}")
endif()

# Find or download frida-gum
if(NOT FRIDA_GUM_LIBRARIES OR NOT FRIDA_GUM_INCLUDE_DIRS)
    message(STATUS "Fetching frida-gum")
    include(cmake/frida-gum.cmake)
    fetch_frida_gum(
        ${PROJECT_SOURCE_DIR}/cmake
        ${PROJECT_BINARY_DIR}/frida-gum
    )
    message(STATUS "FRIDA_GUM_LIBRARIES   = ${FRIDA_GUM_LIBRARIES}")
    message(STATUS "FRIDA_GUM_INCLUDE_DIRS = ${FRIDA_GUM_INCLUDE_DIRS}")
endif()

add_subdirectory(src)


