# SPDX-License-Identifier: MIT

set(_MIRATH_OBJS "")
set(MIRATH_TCITH_1A_SHORT_LIB_SOURCES
    mirath_tcith_1a_short/common/hash_sha2_128.c
    mirath_tcith_1a_short/common/KeccakHash.c
    mirath_tcith_1a_short/common/KeccakP-1600-opt64.c
    
)
if(OQS_ENABLE_SIG_mirath_tcith_1a_short)
    set(MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/namespace_mirath_tcith_1a_short.h)
    # Main MIRATH algorithm sources (without lib dependencies)
    set(MIRATH_TCITH_1A_SHORT_SOURCES
        ${MIRATH_TCITH_1A_SHORT_LIB_SOURCES}
        mirath_tcith_1a_short/main.c
        mirath_tcith_1a_short/mirath_ggm_tree.c
        mirath_tcith_1a_short/mirath_keygen.c
        mirath_tcith_1a_short/mirath_matrix_ff.c
        mirath_tcith_1a_short/mirath_parsing.c
        mirath_tcith_1a_short/mirath_sign.c
        mirath_tcith_1a_short/mirath_tcith.c
        mirath_tcith_1a_short/mirath_verify.c
        mirath_tcith_1a_short/PQCgenKAT_sign.c
        mirath_tcith_1a_short/rng.c
        mirath_tcith_1a_short/sign.c
    )

    add_library(mirath_tcith_1a_short_ref OBJECT ${MIRATH_TCITH_1A_SHORT_SOURCES})
    
    target_include_directories(mirath_tcith_1a_short_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/common
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/reference
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/arith)
    target_compile_options(mirath_tcith_1a_short_ref PRIVATE "-include" ${MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER})
    
    
    # Add the glue code as a separate object for the MIRATH_1a_short variant
    add_library(mirath_tcith_1a_short_glue OBJECT sig_mirath_1a_short.c)
    target_include_directories(mirath_tcith_1a_short_glue PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/common
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/reference
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/arith)
    target_compile_options(mirath_tcith_1a_short_glue PRIVATE "-include" ${MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER})
    set(_MIRATH_OBJS ${_MIRATH_OBJS} $<TARGET_OBJECTS:mirath_tcith_1a_short_ref> $<TARGET_OBJECTS:mirath_tcith_1a_short_glue>)
endif()

////////////////1-b///////////////////////












//////////////////3-b///////////////////////




//////////////////5-a///////////////////////





/////////////////5-b///////////////////////






set(MIRATH_OBJS ${_MIRATH_OBJS} PARENT_SCOPE)