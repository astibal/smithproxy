cmake_minimum_required(VERSION 2.8)

include(${CMAKE_CURRENT_SOURCE_DIR}/helpers.cmake)

SET(SOCLE_DIR "socle")
SET(SOCLE_COMMON_DIR "socle/common")
SET(SMITHD_DIR "src/service/smithd")

project(smithproxy CXX)

SET(CMAKE_SOURCE_DIR "src/")
SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")

include_directories ("${SOCLE_DIR}")
include_directories ("${SOCLE_COMMON_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}/src/")
include_directories ("${PROJECT_SOURCE_DIR}/src/ext")
include_directories ("${SMITHD_DIR}")

add_subdirectory(${SOCLE_DIR} socle_lib)
add_subdirectory(${SOCLE_COMMON_DIR} socle_common_lib)

if(UNIX)
    IF(NOT CMAKE_BUILD_TYPE)
        SET(CMAKE_BUILD_TYPE Debug)
    ENDIF(NOT CMAKE_BUILD_TYPE)

    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-psabi -std=c++17")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -fno-stack-protector")

    IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fPIE -pie")
        # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fPIE -pie")
    ENDIF()

    IF (CMAKE_BUILD_TYPE STREQUAL "Release")
        message(">>> release: enabling optimizations (smithproxy)")
        SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -flto=${CPUs} -s -DBUILD_RELEASE")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto=${CPUs}")
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
        ${CMAKE_SOURCE_DIR}/smithproxy_version.h.in
        ${PROJECT_SOURCE_DIR}/src/smithproxy_version.h
)

add_executable(smithproxy

        src/main.cpp
        src/proxy/mitmhost.cpp
        src/proxy/mitmproxy.cpp
        src/service/cfgapi/cfgapi.cpp
        src/policy/policy.cpp
        src/service/daemon.cpp
        src/proxy/socks5/sockshostcx.cpp
        src/proxy/socks5/socksproxy.cpp
        src/cli/cmdserver.cpp
        src/shm/shmauth.cpp
        src/inspect/dns.cpp
        src/policy/inspectors.cpp
        src/policy/addrobj.cpp
        src/service/netservice.cpp
        src/staticcontent.cpp
        src/policy/authfactory6.cpp
        src/smithlog.cpp
        src/proxy/filters/filterproxy.cpp
        src/service/dnsupd/smithdnsupd.cpp
        src/policy/loadb.cpp
        src/service/core/smithproxy.hpp
        src/service/core/smithproxy.cpp

        src/ext/libcidr/cidr.cpp
        src/ext/cxxopts/cxxopts.hpp
        src/ext/nltemplate/nltemplate.cpp
        src/ext/libcli/libcli.cpp

        src/policy/authfactory.hpp
        src/policy/authfactory4.cpp
        src/inspect/sxsignature.hpp
        src/inspect/pyinspector.hpp
        src/inspect/sigfactory.hpp
        src/async/asyncsocket.hpp
        src/async/asyncdns.hpp
        src/inspect/dnsinspector.hpp
        src/inspect/dnsinspector.cpp
        src/cli/clihelp.hpp
        src/cli/clihelp.cpp
        src/cli/cligen.hpp
        src/cli/cligen.cpp
        src/service/core/service.cpp
        src/service/core/service.hpp
        src/cli/diag/diag_cmds.hpp
        src/cli/diag/diag_cmds.cpp
        src/proxy/ocspinvoker.cpp
        src/proxy/ocspinvoker.hpp)


set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

find_package (LibConfig REQUIRED)
if (LIBCONFIGPP_FOUND)
    include_directories(${LIBCONFIGPP_INCLUDE_DIRS})
    target_link_libraries (smithproxy ${LIBCONFIGPP_LIBRARIES})
endif (LIBCONFIGPP_FOUND)

target_link_libraries (smithproxy crypt)

find_package(PythonLibs 3 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})

if((CMAKE_SYSTEM_PROCESSOR MATCHES "arm") OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64"))
    target_link_libraries (smithproxy atomic)
endif()

target_link_libraries(smithproxy socle_lib pthread ssl crypto rt unwind ${PYTHON_LIBRARIES})

#include(${CMAKE_CURRENT_SOURCE_DIR}/install.cmake)
