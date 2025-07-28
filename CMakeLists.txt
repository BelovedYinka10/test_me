cmake_minimum_required(VERSION 3.5)
project(kyber C)

set(SOURCES
    kyber_wrapper.c
    ref/kem.c
    ref/indcpa.c
    ref/ntt.c
    ref/poly.c
    ref/polyvec.c
    ref/verify.c
    ref/cbd.c
    ref/randombytes.c
    ref/symmetric-shake.c
    ref/reduce.c
    ref/fips202.c
)

include_directories(ref)

# Kyber512 (K=2)
add_library(kyber512 SHARED ${SOURCES})
target_compile_definitions(kyber512 PRIVATE KYBER_K=2)

# Kyber768 (K=3)
add_library(kyber768 SHARED ${SOURCES})
target_compile_definitions(kyber768 PRIVATE KYBER_K=3)

# Kyber1024 (K=4)
add_library(kyber1024 SHARED ${SOURCES})
target_compile_definitions(kyber1024 PRIVATE KYBER_K=4)
