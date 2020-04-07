include_directories(include)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DHAVE_CONFIG_H=1)

add_library(libsecp256k1 src/secp256k1.c include/secp256k1.h)
