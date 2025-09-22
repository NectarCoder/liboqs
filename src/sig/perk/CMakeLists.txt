cmake_minimum_required(VERSION 3.0)

# Build the PERK reference implementation as OBJECT library(s)
set(PERK_REF_SOURCES
    perk_128_fast_3/api.h
    perk_128_fast_3/keygen.c
    perk_128_fast_3/keygen.h
    perk_128_fast_3/sign.c
    perk_128_fast_3/verify.c
    perk_128_fast_3/verify.h
    perk_128_fast_3/signature.c
    perk_128_fast_3/signature.h
    perk_128_fast_3/arithmetic.c
    perk_128_fast_3/arithmetic.h
    perk_128_fast_3/common.c
    perk_128_fast_3/common.h
    perk_128_fast_3/parsing.c
    perk_128_fast_3/parsing.h
    perk_128_fast_3/permutation.c
    perk_128_fast_3/permutation.h
    perk_128_fast_3/symmetric.c
    perk_128_fast_3/symmetric.h
    perk_128_fast_3/theta_tree.c
    perk_128_fast_3/theta_tree.h
    perk_128_fast_3/parameters.h
    perk_128_fast_3/verbose.c
    perk_128_fast_3/verbose.h
)

# Per-variant glue that constructs the OQS_SIG and wrappers
list(APPEND PERK_REF_SOURCES
    sig_perk_perk_128_fast_3.c
)

add_library(perk_perk_128_fast_3_ref OBJECT ${PERK_REF_SOURCES})
target_include_directories(perk_perk_128_fast_3_ref PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3/lib/XKCP
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3/lib/cryptocode
)

# Ensure per-variant compile-time macro is defined so the glue constructors
# (guarded by #if defined(OQS_ENABLE_SIG_perk_perk_128_fast_3)) are compiled.
target_compile_definitions(perk_perk_128_fast_3_ref PUBLIC OQS_ENABLE_SIG_perk_perk_128_fast_3)

# also include subdirectories that contain helper headers
target_include_directories(perk_perk_128_fast_3_ref PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3/lib/randombytes
    ${CMAKE_CURRENT_SOURCE_DIR}/perk_128_fast_3/lib/djbsort
)

set(PERK_OBJS ${PERK_OBJS} $<TARGET_OBJECTS:perk_perk_128_fast_3_ref> PARENT_SCOPE)
