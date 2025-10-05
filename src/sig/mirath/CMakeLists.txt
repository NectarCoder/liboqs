# SPDX-License-Identifier: MIT

set(_MIRATH_OBJS "")
set(MIRATH_TCITH_1A_FAST_LIB_SOURCES
    mirath_tcith_1a_fast/common/fips202.c
    mirath_tcith_1a_fast/common/hash.c
    mirath_tcith_1a_fast/common/KeccakHash.c
    mirath_tcith_1a_fast/common/KeccakP-1600-opt64.c
    mirath_tcith_1a_fast/common/prng.c
    mirath_tcith_1a_fast/common/random.c
)
if(OQS_ENABLE_SIG_mirath_tcith_1a_fast)
    set(MIRATH_TCITH_1A_FAST_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/namespace_mirath_tcith_1a_fast.h)
    # Main MIRATH algorithm sources (without lib dependencies)
    set(MIRATH_TCITH_1A_FAST_SOURCES
        ${MIRATH_TCITH_1A_FAST_LIB_SOURCES}
        mirath_tcith_1a_fast/main.c
        mirath_tcith_1a_fast/mirath_ggm_tree.c
        mirath_tcith_1a_fast/mirath_keygen.c
        mirath_tcith_1a_fast/mirath_matrix_ff.c
        mirath_tcith_1a_fast/mirath_parsing.c
        mirath_tcith_1a_fast/mirath_sign.c
        mirath_tcith_1a_fast/mirath_tcith.c
        mirath_tcith_1a_fast/mirath_verify.c
        mirath_tcith_1a_fast/sign.c
    )

    add_library(mirath_tcith_1a_fast_ref OBJECT ${MIRATH_TCITH_1A_FAST_SOURCES})
    
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/common
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/arith
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/q_16
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/q_16/mu_fast)
    target_compile_options(mirath_tcith_1a_fast_ref PRIVATE "-include" ${MIRATH_TCITH_1A_FAST_NAMESPACE_HEADER})
    
    
    # Add the glue code as a separate object for the MIRATH_1a_fast variant
    add_library(mirath_tcith_1a_fast_glue OBJECT sig_mirath_1a_fast.c)
    target_include_directories(mirath_tcith_1a_fast_glue PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/common
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/arith
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/q_16
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast/q_16/mu_fast)
    target_compile_options(mirath_tcith_1a_fast_glue PRIVATE "-include" ${MIRATH_TCITH_1A_FAST_NAMESPACE_HEADER})
    set(_MIRATH_OBJS ${_MIRATH_OBJS} $<TARGET_OBJECTS:mirath_tcith_1a_fast_ref> $<TARGET_OBJECTS:mirath_tcith_1a_fast_glue>)
endif()

set(MIRATH_OBJS ${_MIRATH_OBJS} PARENT_SCOPE)