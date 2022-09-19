cmake_minimum_required(VERSION 3.0)

include(${CMAKE_CURRENT_SOURCE_DIR}/helpers.cmake)

SET(SOCLE_DIR "socle")
SET(SOCLE_COMMON_DIR "socle/common")
SET(SMITHD_DIR "src/service/smithd")

project(smithproxy CXX)

SET(CMAKE_SOURCE_DIR "src/")
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")

set(USE_PYTHON "N")
set(USE_LMHPP "Y")
set(USE_UNWIND "Y")
set(USE_REDIS "N")

set(OPT_MEMPOOL_NOEXCEPT "Y")
set(OPT_MEMPOOL_DISABLE "N")
set(OPT_DEBUG_ASAN_LEAKS "N")
set(OPT_DEBUG_ASAN_THREADS "N")

set(USE_EXPERIMENT "N")
set(USE_EXTRA_DEBUG "N")


#### experimental, tempo variables

set(USE_HTTP2_ENGINE "Y")
###

if("${USE_EXPERIMENT}" STREQUAL "Y")
    message(" >> !!! EXPERIMENTS ENABLED !!!" )
    add_definitions(-DUSE_EXPERIMENT)
endif()

if("${USE_EXTRA_DEBUG}" STREQUAL "Y")
    message(" >> !!! EXTRA_DEBUG ENABLED !!!" )
    add_definitions(-DEXTRA_DEBUG)
endif()

if("${OPT_MEMPOOL_NOEXCEPT}" STREQUAL "Y")
    message(" >> mempool cannot throw" )
    add_definitions(-DMEMPOOL_NOEXCEPT)
endif()


if("${OPT_MEMPOOL_DISABLE}" STREQUAL "Y")
    message(" >> mempool not used" )
    add_definitions(-DMEMPOOL_DISABLE)
endif()

if("${USE_HTTP2_ENGINE}" STREQUAL "Y")
    message(" >> http2 enabled" )
    add_definitions(-DUSE_HTTP2)
    add_definitions(-DUSE_HPACK)
endif()


create_git_hooks()

include_directories ("${SOCLE_DIR}")
include_directories ("${SOCLE_COMMON_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}/src/")
include_directories ("${PROJECT_SOURCE_DIR}/src/ext")
include_directories ("${SMITHD_DIR}")

add_subdirectory(${SOCLE_DIR} socle_lib)
add_subdirectory(${SOCLE_COMMON_DIR} socle_common_lib)


find_package (LibConfig REQUIRED)
if (LIBCONFIGPP_FOUND)
    include_directories(${LIBCONFIGPP_INCLUDE_DIRS})
endif (LIBCONFIGPP_FOUND)


if("${USE_LMHPP}" STREQUAL "Y")
    find_package (LibMicroHttpd)
    if (LIBMICROHTTPD_FOUND)
        include_directories(${LIBMICROHTTPD_INCLUDE_DIR})
        message(">> microhttpd includes: " ${LIBMICROHTTPD_INCLUDE_DIR})
        # libmicrohttpd/lmhpp use
        add_definitions(-DUSE_LMHPP)
    else()
        set(USE_LMHPP "N")
        message(">> microhttpd not found")
    endif (LIBMICROHTTPD_FOUND)
else()
    message(">> libmicrohttpd DISABLED")
endif()

find_package(PythonLibs 3 REQUIRED)

if("${USE_PYTHON}" STREQUAL "Y")
    if(PYTHONLIBS_FOUND)
        include_directories(${PYTHON_INCLUDE_DIRS})
        message(">> python includes: " ${PYTHON_INCLUDE_DIRS})
        add_definitions(-DUSE_PYTHON)
    else()
        message(">> python not found")
        set(USE_PYTHON "N")
    endif(PYTHONLIBS_FOUND)
else()
    message(">> python DISABLED")
endif()

if("${USE_REDIS}" STREQUAL "Y")
    message(">> redis option enabled" )
    find_package (hiredis)
    if(HIREDIS_FOUND)
        message(">> redis found" )
        include_directories(${HIREDIS_INCLUDE_DIR})
        add_definitions(-DUSE_REDIS)
    else()
        message(">> redis not found, DISABLED" )
    endif()
else()
    message(">> redis DISABLED")
endif()

if("${USE_UNWIND}" STREQUAL "Y")
    IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
        SET(UNWIND_LIB "unwind")
        add_definitions(-DUSE_UNWIND)
    ENDIF()
else()
    message(">> unwind DISABLED")
endif()

if(UNIX)
    IF(NOT CMAKE_BUILD_TYPE)
        SET(CMAKE_BUILD_TYPE Debug)
    ENDIF(NOT CMAKE_BUILD_TYPE)

    # Pedantic complains about designated initializers (C++20)
    # SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wconversion -Wpedantic -Wno-unused-parameter -Wno-psabi -std=c++17")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-psabi -std=c++17")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -g3 -fno-stack-protector")

    IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
        if("${OPT_DEBUG_ASAN_THREADS}" STREQUAL "Y")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fPIE -pie")
        elseif("${OPT_DEBUG_ASAN_LEAKS}" STREQUAL "Y")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fPIE -pie")
        endif()
    ENDIF()

    IF (CMAKE_BUILD_TYPE STREQUAL "Release")
        message(">>> release: enabling optimizations (smithproxy)")
        SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fstack-protector-strong -O3 -flto -s -DBUILD_RELEASE")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    ENDIF()

    SET(CMAKE_AR  "gcc-ar")
    SET(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
    SET(CMAKE_CXX_ARCHIVE_FINISH   true)

    # detect Alpine - and disable backtrace_* function use
    if(EXISTS "/etc/alpine-release")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBC_MUSL")
    endif()
endif()


if(EXISTS "${PROJECT_SOURCE_DIR}/.git")
    execute_process(
            COMMAND git rev-parse --abbrev-ref HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE SX_GIT_BRANCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND git log -1 --format=%h
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE SX_GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND git describe --tags --dirty
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE SX_GIT_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

else(EXISTS "${PROJECT_SOURCE_DIR}/.git")
    set(SX_GIT_BRANCH "")
    set(SX_GIT_COMMIT_HASH "")
    set(SX_GIT_VERSION "")

endif(EXISTS "${PROJECT_SOURCE_DIR}/.git")

message(STATUS "Git current smithproxy branch: ${SX_GIT_BRANCH}")
message(STATUS "Git commit smithrproxy hash: ${SX_GIT_COMMIT_HASH}")
message(STATUS "Git commit smithrproxy version: ${SX_GIT_VERSION}")

message(STATUS "Generating smithproxy_version.h")

configure_file(
        ${PROJECT_SOURCE_DIR}/src/smithproxy_version.h.in
        ${PROJECT_SOURCE_DIR}/src/smithproxy_version.h
)
message(STATUS "compiler flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "compiler debug flags: ${CMAKE_CXX_FLAGS_DEBUG}")

add_executable(smithproxy

        src/main.cpp
        src/smithlog.cpp
        src/service/cfgapi/cfgapi.cpp
        src/staticcontent.cpp

        src/proxy/mitmhost.cpp
        src/proxy/mitmproxy.cpp
        src/proxy/mitmcom.hpp
        src/proxy/mitmcom.cpp
        src/proxy/filterproxy.cpp
        src/proxy/ocspinvoker.cpp
        src/proxy/ocspinvoker.hpp
        src/proxy/proxymaker.hpp
        src/proxy/proxymaker.cpp

        src/proxy/socks5/sockshostcx.cpp
        src/proxy/socks5/socksproxy.cpp

        src/policy/policy.cpp
        src/policy/authfactory.hpp
        src/policy/authfactory4.cpp
        src/policy/inspectors.cpp
        src/policy/addrobj.cpp
        src/policy/authfactory6.cpp
        src/policy/loadb.cpp
        src/policy/profiles.hpp
        src/policy/profiles.cpp
        src/policy/cfgelement.hpp

        src/inspect/sxsignature.hpp
        src/inspect/pyinspector.hpp
        src/inspect/sigfactory.hpp
        src/inspect/engine.hpp
        src/inspect/dnsinspector.hpp
        src/inspect/dnsinspector.cpp
        src/inspect/dns.cpp
        src/inspect/kb/kb.hpp

        src/inspect/engine/http.hpp
        src/inspect/engine/http.cpp

        src/shm/shmauth.cpp


        src/async/asyncsocket.hpp
        src/async/asyncdns.hpp

        src/service/daemon.cpp
        src/service/netservice.cpp
        src/service/dnsupd/smithdnsupd.cpp
        src/service/core/smithproxy.hpp
        src/service/core/smithproxy.cpp
        src/service/cmd/cmdserver.cpp
        src/service/cfgapi/cfgvalue.hpp
        src/service/cfgapi/cfgvalue.cpp
        src/service/cmd/cligen.hpp
        src/service/cmd/cligen.cpp
        src/service/cmd/clistate.hpp
        src/service/cmd/clistate.cpp
        src/service/cmd/diag/diag_cmds.hpp
        src/service/cmd/diag/diag_cmds.cpp
        src/service/core/service.cpp
        src/service/core/service.hpp
        src/service/httpd/httpd.cpp
        src/service/httpd/jsonize.cpp

        src/utils/fs.hpp
        src/utils/fs.cpp
        src/utils/str.hpp
        src/utils/str.cpp
        src/utils/mem.hpp
        src/utils/mem.cpp
        src/utils/tenants.hpp
        src/utils/tenants.cpp

        socle/common/mempool/malloc_allocator.hpp

        src/ext/libcidr/cidr.cpp
        src/ext/nltemplate/nltemplate.cpp
        src/ext/libcli/libcli.cpp
        src/ext/lmhpp/include/lmhttpd.hpp
        src/ext/hpack/hpack.hpp)


add_executable(smithd
        ${SMITHD_DIR}/smithd.cpp
        ${SMITHD_DIR}/smithdcx.cpp

        src/service/daemon.cpp
        src/service/netservice.cpp
        src/smithlog.cpp
        src/inspect/dns.cpp
        src/ext/libcidr/cidr.cpp
        src/policy/addrobj.cpp
        src/async/asyncocsp.hpp
        src/utils/fs.hpp
        src/utils/fs.cpp
        src/utils/str.hpp
        src/utils/str.cpp
        src/utils/mem.hpp
        src/utils/mem.cpp socle/common/mempool/malloc_allocator.hpp)

add_executable(smithdc
        ${SMITHD_DIR}/smithdc.cpp
        ${SMITHD_DIR}/smithdcx.cpp
        src/smithlog.cpp
        src/utils/fs.hpp
        src/utils/fs.cpp
        src/utils/mem.hpp
        src/utils/mem.cpp socle/common/mempool/malloc_allocator.hpp)

find_package(GTest)
if(GTEST_FOUND)
    add_executable(sx_gtests
            src/inspect/dns.cpp
            src/utils/str.cpp

            src/utils/tests/str_test.cpp
            src/inspect/tests/dns_tests.cpp
            src/inspect/tests/node_tests.cpp
            src/ext/libcidr/cidr.cpp

            src/policy/policy.cpp
            src/policy/tests/addrobj_test.cpp
            src/policy/tests/policy_test.cpp

            src/utils/tenants.cpp
            src/tests/test_misc.cpp

            src/ext/hpack/hpack.hpp
            src/ext/hpack/hpack_tests.cpp

            socle/traflog/tests/test_pcapapi.cpp
            socle/traflog/tests/test_pcapng.cpp
            socle/tests/test_tls.cpp
            socle/tests/tests_peering.cpp
            socle/common/tests/cache_tests.cpp
            socle/common/tests/mempool_tests.cpp
            socle/common/tests/string_tests.cpp
            socle/common/tests/inet_tests.cpp)

    target_link_libraries(sx_gtests gtest gtest_main socle_lib pthread crypto ssl)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

if (LIBCONFIGPP_FOUND)
    target_link_libraries (smithproxy ${LIBCONFIGPP_LIBRARIES})
    target_link_libraries (smithd ${LIBCONFIGPP_LIBRARIES})
endif (LIBCONFIGPP_FOUND)

target_link_libraries (smithproxy crypt)

if((CMAKE_SYSTEM_PROCESSOR MATCHES "arm") OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64"))
    target_link_libraries (smithproxy atomic)
    target_link_libraries (smithd atomic)
    target_link_libraries (smithdc atomic)
endif()

target_link_libraries(smithproxy socle_lib pthread ssl crypto rt ${UNWIND_LIB})

if("${USE_LMHPP}" STREQUAL "Y")
    target_link_libraries(smithproxy microhttpd)
else()
    message(">> libmicrohttpd not used")
endif()


if("${USE_PYTHON}" STREQUAL "Y")
    target_link_libraries(smithproxy ${PYTHON_LIBRARIES})
else()
    message(">> python not used")
endif()

if("${USE_HTTP2_ENGINE}" STREQUAL "Y")
    # target_link_libraries(smithproxy z)
endif()

if(HIREDIS_FOUND)
    target_link_libraries(smithproxy ${HIREDIS_LIBRARIES})
endif()

target_link_libraries(smithd socle_lib pthread ssl crypto rt ${UNWIND_LIB})
target_link_libraries(smithdc socle_lib pthread ssl crypto rt ${UNWIND_LIB})


include(${CMAKE_CURRENT_SOURCE_DIR}/install.cmake)

if("${USE_EXPERIMENT}" STREQUAL "Y")
    message(" >> !!! EXPERIMENTS ENABLED !!!" )
    message(" >> - software you built and install contain code which is probably not for general use" )
endif()

