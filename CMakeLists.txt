# =============================================================================
# wallet_core - Multi-Chain Wallet Core Library
# =============================================================================
cmake_minimum_required(VERSION 3.18)
project(wallet_core VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# C++ Standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler Warnings
# ---------------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# Required Dependencies
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
find_package(Protobuf REQUIRED)

# ---------------------------------------------------------------------------
# Collect all source files under src/
# ---------------------------------------------------------------------------
file(GLOB_RECURSE WALLET_CORE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

# ---------------------------------------------------------------------------
# Static Library Target
# ---------------------------------------------------------------------------
add_library(wallet_core STATIC ${WALLET_CORE_SOURCES})

target_include_directories(wallet_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(wallet_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::boost
        protobuf::libprotobuf
)

# ---------------------------------------------------------------------------
# Testing (optional)
# ---------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
