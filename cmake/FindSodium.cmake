# FindSodium.cmake - Find module for libsodium
#
# This module defines:
#   Sodium_FOUND        - True if libsodium is found
#   Sodium_INCLUDE_DIRS - Include directories for libsodium
#   Sodium_LIBRARIES    - Libraries to link against
#   Sodium::Sodium      - Imported target
#
# Usage:
#   find_package(Sodium)
#   target_link_libraries(my_target Sodium::Sodium)

include(FindPackageHandleStandardArgs)

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        $ENV{SODIUM_ROOT}/include
    PATH_SUFFIXES sodium
)

find_library(Sodium_LIBRARY
    NAMES sodium libsodium
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/homebrew/lib
        $ENV{SODIUM_ROOT}/lib
)

find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
)

if(Sodium_FOUND AND NOT TARGET Sodium::Sodium)
    add_library(Sodium::Sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::Sodium PROPERTIES
        IMPORTED_LOCATION "${Sodium_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
