cmake_minimum_required(VERSION 3.18)
project(quic_transport_experiment LANGUAGES CXX)
# Standalone lab target: consume an existing Smithproxy build's support libraries
# without adding ngtcp2 or certificate bypasses to any production target.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
get_filename_component(SMITHPROXY_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(SMITHPROXY_BUILD_DIR "" CACHE PATH "Existing Smithproxy build with socle and qpack")
find_package(OpenSSL 3.5 REQUIRED)
find_package(Threads REQUIRED)
find_path(NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2.h REQUIRED)
find_path(NGTCP2_CRYPTO_INCLUDE_DIR ngtcp2/ngtcp2_crypto_ossl.h REQUIRED)
find_library(NGTCP2_LIBRARY ngtcp2 REQUIRED)
find_library(NGTCP2_CRYPTO_LIBRARY ngtcp2_crypto_ossl REQUIRED)
add_executable(quic_transport_experiment connection.cpp node.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/multiflow/mfflowcom.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/multiflow/mfproxy.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/quic/wire.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/quic/h3capture.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/quic/spq1.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/quic/openssl.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/proxy/quic/hooks.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/service/quic/quicservice.cpp
    ${SMITHPROXY_SOURCE_DIR}/src/service/quic/worker_dispatcher.cpp)
target_include_directories(quic_transport_experiment PRIVATE
    ${SMITHPROXY_SOURCE_DIR} ${SMITHPROXY_SOURCE_DIR}/src
    ${SMITHPROXY_SOURCE_DIR}/src/ext ${SMITHPROXY_SOURCE_DIR}/src/ext/ls-qpack
    ${SMITHPROXY_SOURCE_DIR}/socle ${SMITHPROXY_SOURCE_DIR}/socle/common
    ${NGTCP2_INCLUDE_DIR} ${NGTCP2_CRYPTO_INCLUDE_DIR})
target_compile_definitions(quic_transport_experiment PRIVATE MEMPOOL_NOEXCEPT USE_HPACK USE_HTTP2 USE_LMHPP USE_PAM)
target_compile_options(quic_transport_experiment PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)
target_link_libraries(quic_transport_experiment PRIVATE
    ${SMITHPROXY_BUILD_DIR}/src/ext/ls-qpack/libsmithproxy_qpack.a
    ${SMITHPROXY_BUILD_DIR}/socle_lib/libsocle_lib.a
    ${SMITHPROXY_BUILD_DIR}/socle_common_lib/libsocle_common_lib.a
    ${NGTCP2_CRYPTO_LIBRARY} ${NGTCP2_LIBRARY} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
