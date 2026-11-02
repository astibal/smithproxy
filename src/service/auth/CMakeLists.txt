cmake_minimum_required(VERSION 3.18)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(smithproxy_auth LANGUAGES CXX)
    include(CTest)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(AUTH_CURL REQUIRED IMPORTED_TARGET libcurl)
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json REQUIRED)
endif()

add_library(smithproxy_auth_client STATIC pap.cpp broker_client.cpp)
target_include_directories(smithproxy_auth_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../..")
target_compile_features(smithproxy_auth_client PUBLIC cxx_std_17)
target_link_libraries(smithproxy_auth_client PUBLIC PkgConfig::AUTH_CURL nlohmann_json::nlohmann_json)

add_executable(smithproxy-auth-check check_main.cpp)
target_link_libraries(smithproxy-auth-check PRIVATE smithproxy_auth_client)

if(BUILD_TESTING)
    find_package(GTest REQUIRED)
    add_executable(sx_gtests_pap tests/pap_test.cpp tests/broker_client_test.cpp)
    target_link_libraries(sx_gtests_pap PRIVATE smithproxy_auth_client GTest::gtest_main pthread)
    add_test(NAME unit.pap COMMAND sx_gtests_pap)
    set_tests_properties(unit.pap PROPERTIES LABELS "native;unit;auth" TIMEOUT 30)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME integration.auth_client COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/broker_client_integration.py"
        $<TARGET_FILE:smithproxy-auth-check>)
    set_tests_properties(integration.auth_client PROPERTIES LABELS "native;integration;auth" TIMEOUT 30)
endif()

# Keyway is built and distributed independently; this package owns only the client.
install(TARGETS smithproxy-auth-check RUNTIME DESTINATION bin)

set(SMITHPROXY_KEYWAY_EXECUTABLE "" CACHE FILEPATH "External Keyway binary for integration tests")
set(SMITHPROXY_KEYWAY_TEST_PAM_MODULE "" CACHE FILEPATH "External Keyway test-only PAM module")
if(BUILD_TESTING AND TARGET smithproxy AND
   SMITHPROXY_KEYWAY_EXECUTABLE AND SMITHPROXY_KEYWAY_TEST_PAM_MODULE)
    if(NOT EXISTS "${SMITHPROXY_KEYWAY_EXECUTABLE}" OR
       NOT EXISTS "${SMITHPROXY_KEYWAY_TEST_PAM_MODULE}")
        message(FATAL_ERROR "Keyway integration paths must name existing build artifacts")
    endif()
    add_test(NAME integration.proxy_auth COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/proxy_integration.py"
        $<TARGET_FILE:smithproxy> "${SMITHPROXY_KEYWAY_EXECUTABLE}"
        "${SMITHPROXY_KEYWAY_TEST_PAM_MODULE}")
    set_tests_properties(integration.proxy_auth PROPERTIES LABELS "native;integration;auth" TIMEOUT 90)
endif()
