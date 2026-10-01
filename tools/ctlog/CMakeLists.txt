cmake_minimum_required(VERSION 3.14)
project(sx_ctlog CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json 3.0 REQUIRED)

add_executable(sx_ctlog sx_ctlog.cpp)
target_link_libraries(sx_ctlog PRIVATE OpenSSL::Crypto CURL::libcurl nlohmann_json::nlohmann_json)
target_compile_options(sx_ctlog PRIVATE -Wall -Wextra -Wpedantic)
