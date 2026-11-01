cmake_minimum_required(VERSION 3.18)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(smithproxy_auth LANGUAGES CXX)
    include(CTest)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(AUTH_CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(AUTH_CONFIG REQUIRED IMPORTED_TARGET libconfig++)
pkg_check_modules(AUTH_HTTP REQUIRED IMPORTED_TARGET libmicrohttpd)
find_library(AUTH_PAM pam REQUIRED)
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json REQUIRED)
endif()
set(LMHPP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ext/lmhpp/include" CACHE PATH "lmhttp header directory")

add_library(smithproxy_auth_client STATIC pap.cpp broker_client.cpp)
target_include_directories(smithproxy_auth_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../..")
target_compile_features(smithproxy_auth_client PUBLIC cxx_std_17)
target_link_libraries(smithproxy_auth_client PUBLIC PkgConfig::AUTH_CURL nlohmann_json::nlohmann_json)

add_executable(smithproxy-auth-broker broker_main.cpp pam_backend.cpp)
target_include_directories(smithproxy-auth-broker PRIVATE "${LMHPP_INCLUDE_DIR}")
target_compile_features(smithproxy-auth-broker PRIVATE cxx_std_17)
target_link_libraries(smithproxy-auth-broker PRIVATE PkgConfig::AUTH_CONFIG PkgConfig::AUTH_HTTP
    nlohmann_json::nlohmann_json ${AUTH_PAM} pthread)

add_executable(smithproxy-auth-check check_main.cpp)
target_link_libraries(smithproxy-auth-check PRIVATE smithproxy_auth_client)

if(BUILD_TESTING)
    find_package(GTest REQUIRED)
    add_executable(sx_gtests_pap tests/pap_test.cpp tests/broker_client_test.cpp)
    target_link_libraries(sx_gtests_pap PRIVATE smithproxy_auth_client GTest::gtest_main pthread)
    add_test(NAME unit.pap COMMAND sx_gtests_pap)
    set_tests_properties(unit.pap PROPERTIES LABELS "native;unit;auth" TIMEOUT 30)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_library(auth_test_pam MODULE tests/pam_module.cpp)
    target_link_libraries(auth_test_pam PRIVATE ${AUTH_PAM})
    set_target_properties(auth_test_pam PROPERTIES PREFIX "")
    add_test(NAME integration.auth_broker COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/broker_integration.py"
        $<TARGET_FILE:smithproxy-auth-broker> $<TARGET_FILE:smithproxy-auth-check>
        $<TARGET_FILE:auth_test_pam>)
    set_tests_properties(integration.auth_broker PROPERTIES LABELS "native;integration;auth" TIMEOUT 60)
endif()

# PAM policy and configuration examples are deliberately not installed into /etc.
install(TARGETS smithproxy-auth-broker smithproxy-auth-check RUNTIME DESTINATION bin)

if(BUILD_TESTING AND TARGET smithproxy)
    add_test(NAME integration.proxy_auth COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/proxy_integration.py"
        $<TARGET_FILE:smithproxy> $<TARGET_FILE:smithproxy-auth-broker>
        $<TARGET_FILE:auth_test_pam>)
    set_tests_properties(integration.proxy_auth PROPERTIES LABELS "native;integration;auth" TIMEOUT 90)
endif()
