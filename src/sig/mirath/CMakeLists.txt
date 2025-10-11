# SPDX-License-Identifier: MIT

set(_MIRATH_OBJS "")
set(_MIRATH_LIBS "")

if(OQS_ENABLE_SIG_mirath_tcith_1a_short)
    set(MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/namespace_mirath_tcith_1a_short.h)

    set(MIRATH_TCITH_1A_SHORT_LIB_SOURCES
        mirath_tcith_1a_short/rng.c
        mirath_tcith_1a_short/hash_sha3_128.c
    mirath_tcith_1a_short/lib/xkcp/KeccakHash.c
    mirath_tcith_1a_short/lib/xkcp/KeccakP-1600-opt64.c
    )

    set(MIRATH_TCITH_1A_SHORT_SOURCES
        ${MIRATH_TCITH_1A_SHORT_LIB_SOURCES}
        mirath_tcith_1a_short/mirath_ggm_tree.c
        mirath_tcith_1a_short/mirath_keygen.c
        mirath_tcith_1a_short/mirath_matrix_ff.c
        mirath_tcith_1a_short/sign.c
        mirath_tcith_1a_short/lib/tcith/mirath_parsing.c
        mirath_tcith_1a_short/lib/tcith/mirath_sign.c
        mirath_tcith_1a_short/lib/tcith/mirath_tcith.c
        mirath_tcith_1a_short/lib/tcith/mirath_verify.c
    )

    add_library(mirath_tcith_1a_short_ref OBJECT ${MIRATH_TCITH_1A_SHORT_SOURCES})
    target_include_directories(mirath_tcith_1a_short_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/lib
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/lib/arith
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/lib/tcith
    ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short/lib/xkcp)
    target_compile_options(mirath_tcith_1a_short_ref PRIVATE "-include" ${MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER})

    add_library(mirath_tcith_1a_short_glue OBJECT sig_mirath_tcith_1a_short.c)
    target_include_directories(mirath_tcith_1a_short_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_short)
    target_compile_options(mirath_tcith_1a_short_glue PRIVATE "-include" ${MIRATH_TCITH_1A_SHORT_NAMESPACE_HEADER})

    set(_MIRATH_OBJS ${_MIRATH_OBJS}
        $<TARGET_OBJECTS:mirath_tcith_1a_short_ref>
        $<TARGET_OBJECTS:mirath_tcith_1a_short_glue>)
endif()

set(MIRATH_OBJS ${_MIRATH_OBJS} PARENT_SCOPE)
set(MIRATH_LIBS ${_MIRATH_LIBS} PARENT_SCOPE)
