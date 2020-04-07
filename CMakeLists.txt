cmake_minimum_required(VERSION 3.5)

project(libsecp256k1-cxx LANGUAGES C CXX)

add_subdirectory(src)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(main main.cpp)

target_link_libraries(main secp256k1-cxx)
