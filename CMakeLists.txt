cmake_minimum_required(VERSION 2.8)

SET(CABALA_DIR "/home/astib/pro/cabala")

project(cabala CXX)
include_directories ("${CABALA_DIR}/proxylib")
include_directories ("${CABALA_DIR}/toollib")
#include_directories ("${CABALA_DIR}")
include_directories ("${PROJECT_SOURCE_DIR}")

add_subdirectory(${CABALA_DIR}/proxylib proxylib)
add_subdirectory(${CABALA_DIR}/toollib toollib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
endif()

add_executable(smithproxy  smithproxy.cpp)

target_link_libraries(smithproxy proxylib toollib pthread ssl crypto)

if(UNIX)
	install(TARGETS smithproxy DESTINATION bin)
endif()
