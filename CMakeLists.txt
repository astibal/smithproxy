cmake_minimum_required(VERSION 2.8)

SET(SOCLE_DIR "../socle")
SET(SOCLE_COMMON_DIR "../socle/common")

project(smithproxy CXX)
include_directories ("${SOCLE_DIR}")
include_directories ("${SOCLE_COMMON_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")

add_subdirectory(${SOCLE_DIR} socle_lib)
add_subdirectory(${SOCLE_COMMON_DIR} socle_common_lib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g  -Wall -std=c++11")
endif()

add_executable(smithproxy smithproxy.cpp mitmhost.cpp mitmproxy.cpp cfgapi.cpp cidr.cpp policy.cpp daemon.cpp sockshostcx.cpp socksproxy.cpp cmdserver.cpp cfgapi_auth.cpp)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

find_package (LibConfig REQUIRED)
if (LIBCONFIGPP_FOUND)
  include_directories(${LIBCONFIGPP_INCLUDE_DIRS})
  target_link_libraries (smithproxy ${LIBCONFIGPP_LIBRARIES})
endif (LIBCONFIGPP_FOUND)

find_package (LibCli REQUIRED)
if (LIBCLI_FOUND)
  include_directories(${LIBCLI_INCLUDE_DIR})
  target_link_libraries (smithproxy ${LIBCLI_LIBRARY})
endif (LIBCLI_FOUND)


target_link_libraries(smithproxy socle_lib pthread ssl crypto rt)

if(UNIX)
    install(TARGETS smithproxy DESTINATION bin)
    install(FILES man/smithproxy.1 DESTINATION share/man/man1)
    install(FILES etc/smithproxy.cfg DESTINATION /etc/smithproxy)
    install(FILES etc/smithproxy.startup.cfg DESTINATION /etc/smithproxy)
    install(FILES etc/smithproxy.startup.sh DESTINATION /etc/smithproxy)
    install(FILES etc/smithproxy.init DESTINATION /etc/init.d RENAME smithproxy)
    file(GLOB def_certs "etc/certs/default/*.pem")
    install(FILES ${def_certs} DESTINATION /etc/smithproxy/certs/default)
    install(FILES man/TESTING_README.txt DESTINATION share/smithproxy)
endif()
