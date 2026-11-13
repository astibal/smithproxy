# The default transport is built from the pinned source submodule. Configuration
# never downloads dependencies or silently falls back to another QUIC backend.
option(SMITHPROXY_ENABLE_NGTCP2 "Build the bundled ngtcp2 QUIC backend" ON)
if(NOT SMITHPROXY_ENABLE_NGTCP2)
    message(STATUS "QUIC backend: OpenSSL (explicit ngtcp2 opt-out)")
    return()
endif()

find_package(OpenSSL 3.5 REQUIRED)
set(SMITHPROXY_NGTCP2_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/ext/ngtcp2")
if(NOT EXISTS "${SMITHPROXY_NGTCP2_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "The pinned ngtcp2 source submodule is missing. Run "
        "'git submodule update --init --recursive' before configuring Smithproxy. "
        "Source archives must include populated submodules.")
endif()
if(CMAKE_VERSION VERSION_LESS 3.20)
    message(FATAL_ERROR "Bundled ngtcp2 requires CMake 3.20 or newer.")
endif()

# Keep upstream's generic options local: in particular, its tests and TLS
# backends must not change Smithproxy's BUILD_TESTING or other dependencies.
function(smithproxy_add_ngtcp2)
    set(smithproxy_build_testing "${BUILD_TESTING}")
    set(ENABLE_LIB_ONLY ON)
    set(ENABLE_STATIC_LIB ON)
    set(ENABLE_SHARED_LIB OFF)
    set(ENABLE_OPENSSL ON)
    set(ENABLE_GNUTLS OFF)
    set(ENABLE_BORINGSSL OFF)
    set(ENABLE_PICOTLS OFF)
    set(ENABLE_WOLFSSL OFF)
    set(ENABLE_JEMALLOC OFF)
    set(ENABLE_ASAN OFF)
    set(ENABLE_DEBUG OFF)
    set(ENABLE_WERROR OFF)
    set(BUILD_TESTING OFF)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # EXCLUDE_FROM_ALL also keeps upstream install rules out of our install:
    # no system ngtcp2 headers, libraries or pkg-config files are replaced.
    add_subdirectory("${SMITHPROXY_NGTCP2_SOURCE_DIR}"
        "${PROJECT_BINARY_DIR}/ext/ngtcp2" EXCLUDE_FROM_ALL)

    # Upstream uses cmake_dependent_option, which writes this shared cache
    # entry even with a local override. Preserve our caller's test selection.
    set(BUILD_TESTING "${smithproxy_build_testing}" CACHE BOOL "Build Smithproxy tests" FORCE)
endfunction()
smithproxy_add_ngtcp2()

if(NOT TARGET ngtcp2_crypto_ossl_static)
    message(FATAL_ERROR
        "The bundled ngtcp2 OpenSSL adapter could not be built. "
        "OpenSSL must provide the TLS-only QUIC API (OpenSSL 3.5 or newer).")
endif()

add_library(smithproxy_ngtcp2 INTERFACE)
target_link_libraries(smithproxy_ngtcp2 INTERFACE ngtcp2_crypto_ossl_static)
target_include_directories(smithproxy_ngtcp2 INTERFACE
    "${SMITHPROXY_NGTCP2_SOURCE_DIR}/crypto/includes")

# The static dependency's license travels with installed Smithproxy binaries.
install(FILES "${SMITHPROXY_NGTCP2_SOURCE_DIR}/COPYING"
    DESTINATION "share/smithproxy/docs/licenses" RENAME "LICENSE.ngtcp2")
message(STATUS "QUIC backend: pinned ngtcp2 submodule (static), external OpenSSL")
