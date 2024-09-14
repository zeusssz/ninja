cmake_minimum_required(VERSION 3.10)
project(Raven)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)
include_directories(include/external_libs/nlohmann)
include_directories(include/external_libs/z3)
include_directories(include/external_libs/curl)

add_executable(Raven
    src/main.cpp
    src/analysis.cpp
    src/api_client.cpp
    src/utils.cpp
)

find_package(CURL REQUIRED)
find_package(Z3 REQUIRED)
target_link_libraries(Raven PRIVATE CURL::libcurl Z3::libz3)
