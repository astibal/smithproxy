cmake_minimum_required(VERSION 2.8)

SET(SOCLE_DIR "../socle")
SET(SOCLE_COMMON_DIR "../socle/common")

project(cabala CXX)
include_directories ("${SOCLE_DIR}")
include_directories ("${SOCLE_COMMON_DIR}")
#include_directories ("${SOCLE_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")

add_subdirectory(${SOCLE_DIR} socle_lib)
add_subdirectory(${SOCLE_COMMON_DIR} socle_common_lib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
endif()

add_executable(smithproxy  smithproxy.cpp)

target_link_libraries(smithproxy socle_lib socle_common_lib pthread ssl crypto)

if(UNIX)
	install(TARGETS smithproxy DESTINATION bin)
        install(FILES man/smithproxy.1 DESTINATION share/man/man1)
endif()
