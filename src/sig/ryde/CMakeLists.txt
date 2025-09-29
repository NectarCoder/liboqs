# SPDX-License-Identifier: MIT

set(_RYDE_OBJS "")

# RYDE library dependencies with XKCP (namespaced to avoid conflicts)
set(RYDE_LIB_SOURCES
    ryde1f/lib/rng/rng.c
    ryde1f/lib/xkcp/KeccakHash.c
    ryde1f/lib/xkcp/KeccakHashtimes4.c
    ryde1f/lib/xkcp/KeccakSponge.c
    ryde1f/lib/xkcp/KeccakSpongetimes4.c
    ryde1f/lib/xkcp/SimpleFIPS202.c
    ryde1f/lib/xkcp/opt64/KeccakP-1600-opt64.c
    ryde1f/lib/xkcp/opt64/KeccakP-1600-times4-on1.c
)

if(OQS_ENABLE_SIG_ryde_1f)
    set(RYDE1F_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/ryde1f/namespace_ryde1f.h)

    # Main RYDE1F algorithm sources (without glue code)
    set(RYDE1F_SOURCES
        ${RYDE_LIB_SOURCES}
        ryde1f/binary_matrix.c
        ryde1f/field_53.c
        ryde1f/field_matrix.c
        ryde1f/field_vector.c
        ryde1f/ggm_tree.c
        ryde1f/hash_sha3_256.c
        ryde1f/hash_sha3_x4_256.c
        ryde1f/keygen.c
        ryde1f/parsing.c
        ryde1f/sign.c
        ryde1f/tcith_sign.c
        ryde1f/tcith_verify.c
        ryde1f/tcith.c
    )

    add_library(ryde1f_ref OBJECT ${RYDE1F_SOURCES})
    target_include_directories(ryde1f_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/rng
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp/avx2
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp/opt64)
    target_compile_options(ryde1f_ref PRIVATE "-include" ${RYDE1F_NAMESPACE_HEADER})

    # Add the glue code as a separate object for the ryde1f variant
    add_library(ryde1f_glue OBJECT sig_ryde1f.c)
    target_include_directories(ryde1f_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/ryde1f)
    target_compile_options(ryde1f_glue PRIVATE "-include" ${RYDE1F_NAMESPACE_HEADER})

    set(_RYDE_OBJS ${_RYDE_OBJS} $<TARGET_OBJECTS:ryde1f_ref> $<TARGET_OBJECTS:ryde1f_glue>)
endif()

set(RYDE_OBJS ${_RYDE_OBJS} PARENT_SCOPE)