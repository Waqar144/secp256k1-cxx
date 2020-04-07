cmake_minimum_required(VERSION 3.5)

project(libsecp256k1-cxx LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(libsecp256k1-cxx main.cpp)
