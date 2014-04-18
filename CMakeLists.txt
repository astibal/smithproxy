cmake_minimum_required(VERSION 2.8)

SET(CABALA_DIR "/home/astib/pro/cabala")

project(cabala CXX)
include_directories ("${CABALA_DIR}/proxylib")
include_directories ("${CABALA_DIR}/toollib")
include_directories ("${CABALA_DIR}")
add_subdirectory(${CABALA_DIR}/proxylib proxylib)
add_subdirectory(${CABALA_DIR}/toollib toollib)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
endif()

add_executable(tmitm  tmitm.cpp)

target_link_libraries(tmitm proxylib toollib pthread ssl crypto)

# set_target_properties(tmitm PROPERTIES LINK_FLAGS "-static") 

if(UNIX)
	install(TARGETS tmitm DESTINATION bin)
	#install(FILES doc/cabala.1 DESTINATION share/man/man1)
endif()
