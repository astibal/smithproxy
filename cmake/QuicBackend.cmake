# This is a required backend unless the builder deliberately opts out. Never
# turn a missing ngtcp2 package into a successful OpenSSL-only configuration.
option(SMITHPROXY_ENABLE_NGTCP2 "Build the default ngtcp2 QUIC backend" ON)
if(NOT SMITHPROXY_ENABLE_NGTCP2)
    message(STATUS "QUIC backend: OpenSSL (explicit ngtcp2 opt-out)")
    return()
endif()

find_package(OpenSSL 3.5 REQUIRED)
find_path(NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2.h)
find_path(NGTCP2_CRYPTO_INCLUDE_DIR ngtcp2/ngtcp2_crypto_ossl.h)
find_library(NGTCP2_LIBRARY ngtcp2)
find_library(NGTCP2_CRYPTO_LIBRARY ngtcp2_crypto_ossl)
if(NOT NGTCP2_INCLUDE_DIR OR NOT NGTCP2_CRYPTO_INCLUDE_DIR OR
   NOT NGTCP2_LIBRARY OR NOT NGTCP2_CRYPTO_LIBRARY)
    message(FATAL_ERROR
        "Default QUIC requires ngtcp2 >= 1.26 and its OpenSSL crypto adapter. "
        "Install the development packages for libngtcp2 and libngtcp2_crypto_ossl "
        "(a GnuTLS adapter is not interchangeable), or supply CMAKE_PREFIX_PATH. "
        "Only an explicit -DSMITHPROXY_ENABLE_NGTCP2=OFF selects OpenSSL QUIC.")
endif()

# ngtcp2 1.26 includes upstream fixes for retransmission/fragmentation limits
# and false-positive glitch detection under loss or reordering (#1919, #1988,
# #2393). Older releases can abort legitimate high-throughput connections.
# Check headers and linkage together: older distro packages may provide the core
# library without the TLS-only OpenSSL adapter used by our A:B transport.
include(CheckCXXSourceCompiles)
include(CMakePushCheckState)
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_INCLUDES ${NGTCP2_INCLUDE_DIR} ${NGTCP2_CRYPTO_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${NGTCP2_CRYPTO_LIBRARY} ${NGTCP2_LIBRARY}
    OpenSSL::SSL OpenSSL::Crypto)
unset(SMITHPROXY_NGTCP2_USABLE CACHE)
check_cxx_source_compiles("
#include <ngtcp2/version.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#if NGTCP2_VERSION_NUM < 0x011a00
#error Smithproxy requires ngtcp2 1.26 or newer
#endif
int main() {
    ngtcp2_crypto_ossl_ctx* ctx = nullptr;
    return ngtcp2_crypto_ossl_ctx_new(&ctx, nullptr);
}" SMITHPROXY_NGTCP2_USABLE)
cmake_pop_check_state()
if(NOT SMITHPROXY_NGTCP2_USABLE)
    message(FATAL_ERROR "ngtcp2/OpenSSL adapter headers or linkage are incompatible; see CMakeError.log. No backend fallback was selected.")
endif()
message(STATUS "QUIC backend: ngtcp2 (default); OpenSSL QUIC requires explicit selection")
