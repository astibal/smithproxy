# Build facts are generated outside the source tree. Runtime versions and
# loaded paths are collected separately so updates are visible in status.
find_package(OpenSSL REQUIRED)
foreach(component SSL CRYPTO)
    if(OPENSSL_${component}_LIBRARY MATCHES "\\.a$")
        set(SX_OPENSSL_${component}_LINKAGE "static")
    else()
        set(SX_OPENSSL_${component}_LINKAGE "dynamic")
    endif()
endforeach()
set(SX_NGTCP2_COMMIT "unknown")
if(SMITHPROXY_ENABLE_NGTCP2 AND EXISTS "${SMITHPROXY_NGTCP2_SOURCE_DIR}/.git")
    execute_process(COMMAND git rev-parse HEAD
        WORKING_DIRECTORY "${SMITHPROXY_NGTCP2_SOURCE_DIR}"
        OUTPUT_VARIABLE SX_NGTCP2_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE commit_result ERROR_QUIET)
    if(NOT commit_result EQUAL 0)
        set(SX_NGTCP2_COMMIT "unknown")
    endif()
endif()
configure_file("${PROJECT_SOURCE_DIR}/src/service/dependency_build_info.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/dependency_build_info.hpp" @ONLY)
include_directories("${PROJECT_BINARY_DIR}/generated")
link_libraries(${CMAKE_DL_LIBS})
