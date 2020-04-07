include_directories(include)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

#add_compile_definitions(HAVE_CONFIG_H=1)
add_definitions(-DHAVE_CONFIG_H=1)

add_library(libsecp256k1 src/secp256k1.c include/secp256k1.h)

#add_library(libsecp256k1
#                src/ecdsa.h
#                src/ecdsa_impl.h
#                src/eckey.h
#                src/ecmult.h
#                src/ecmult_const.h
#                src/ecmult_const_impl.h
#                src/ecmult_gen.h
#                src/ecmult_gen_impl.h
#                src/ecmult_impl.h
#                src/field.h
#                src/field_10x26.h
#                src/field_10x26_impl.h
#                src/field_5x52.h
#                src/field_5x52_impl.h
#                src/field_5x52_int128_impl.h
#                src/field_impl.h
#                src/group.h
#                src/group_impl.h
#                src/hash.h
#                src/hash_impl.h
#                src/num.h
#                src/num_impl.h
#                src/scalar.h
#                src/scalar_4x64.h
#                src/scalar_4x64_impl.h
#                src/scalar_8x32.h
#                src/scalar_8x32_impl.h
#                src/scalar_impl.h
#                src/scalar_low.h
#                src/scalar_low_impl.h
#                src/scratch.h
#                src/util.h
#                src/secp256k1.c
#                include/secp256k1.h
#                include/secp256k1_ecdh.h
#                include/secp256k1_preallocated.h
#                include/secp256k1_recovery.h)
