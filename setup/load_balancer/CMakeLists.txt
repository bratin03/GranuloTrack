cmake_minimum_required(VERSION 3.16)
project(GranuloTrackLoadBalancer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Handle Boost policy (CMP0167: FindBoost module removed in CMake 3.30+)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Default build type = Release (if not specified)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type" FORCE)
endif()

# Find required packages
find_package(Threads REQUIRED)

# Find libev manually since pkg-config doesn't work on Ubuntu
find_library(LIBEV_LIBRARIES NAMES ev)
find_path(LIBEV_INCLUDE_DIRS NAMES ev.h)

if(LIBEV_LIBRARIES AND LIBEV_INCLUDE_DIRS)
    message(STATUS "Found libev: ${LIBEV_LIBRARIES}")
else()
    message(FATAL_ERROR "libev not found. Please install libev-dev package.")
endif()

# Find nlohmann/json (header-only)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Find Abseil (absl::flat_hash_map, etc.)
find_package(absl REQUIRED)

# Find Boost (boost::system)
find_package(Boost CONFIG QUIET COMPONENTS system)
if(NOT Boost_FOUND)
    find_package(Boost REQUIRED COMPONENTS system)
endif()

# Find Intel TBB for parallel processing
find_package(TBB QUIET)
if(TBB_FOUND)
    message(STATUS "Found Intel TBB: ${TBB_VERSION}")
    set(USE_TBB ON)
else()
    message(STATUS "Intel TBB not found - using standard threading")
    set(USE_TBB OFF)
endif()

# Find spdlog for async logging
find_package(spdlog REQUIRED)

# Find simdjson for ultra-fast JSON parsing
find_package(simdjson REQUIRED)

# Find FastFloat (header-only)
find_path(FASTFLOAT_INCLUDE_DIRS NAMES fast_float/fast_float.h)
if(FASTFLOAT_INCLUDE_DIRS)
    message(STATUS "Found FastFloat: ${FASTFLOAT_INCLUDE_DIRS}")
else()
    message(STATUS "FastFloat not found in system, using local copy")
    set(FASTFLOAT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/third_party/fast_float/include")
endif()

# Include directories
include_directories(${LIBEV_INCLUDE_DIRS})
include_directories(include)
include_directories(${FASTFLOAT_INCLUDE_DIRS})

# Add executable
add_executable(load_balancer
    src/main.cpp
    src/load_balancer.cpp
    src/server_manager.cpp
    src/http_handler.cpp
    src/config_parser.cpp
    src/connection_pool.cpp
)

# Link libraries
target_link_libraries(load_balancer
    ${LIBEV_LIBRARIES}
    Threads::Threads
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    simdjson::simdjson
    absl::flat_hash_map
    absl::flat_hash_set
    absl::strings
    Boost::system
    -lssl
    -lcrypto
)

# Add glog if available
if(glog_FOUND)
    target_link_libraries(load_balancer glog::glog)
endif()

# Add Intel TBB if available
if(USE_TBB)
    target_link_libraries(load_balancer TBB::tbb)
    target_compile_definitions(load_balancer PRIVATE USE_TBB=1)
endif()

# Common warnings and portability flags
target_compile_options(load_balancer PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wfloat-equal
    -Wnull-dereference
    -Wold-style-cast
    -Woverloaded-virtual
    -Wnon-virtual-dtor
    -Wcast-align
    -Wformat=2
)

# Build-type-specific flags
set(CMAKE_CXX_FLAGS_DEBUG          "-O0 -g -fno-omit-frame-pointer -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -march=native -flto=auto -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")

# Install target
install(TARGETS load_balancer DESTINATION bin)
