# SPDX-License-Identifier: MIT

set(_RYDE_OBJS "")

if(OQS_ENABLE_SIG_ryde_1f)
    set(RYDE1F_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/ryde1f/namespace_ryde1f.h)

    # RYDE-1F library dependencies with XKCP (namespaced to avoid conflicts)
    set(RYDE1F_LIB_SOURCES
        ryde1f/lib/rng/rng.c
        ryde1f/lib/xkcp/KeccakHash.c
        ryde1f/lib/xkcp/KeccakHashtimes4.c
        ryde1f/lib/xkcp/KeccakSponge.c
        ryde1f/lib/xkcp/KeccakSpongetimes4.c
        ryde1f/lib/xkcp/SimpleFIPS202.c
        ryde1f/lib/xkcp/opt64/KeccakP-1600-opt64.c
        ryde1f/lib/xkcp/opt64/KeccakP-1600-times4-on1.c
    )

    # Main RYDE1F algorithm sources (without glue code)
    set(RYDE1F_SOURCES
        ${RYDE1F_LIB_SOURCES}
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

if(OQS_ENABLE_SIG_ryde_1s)
    set(RYDE1S_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/ryde1s/namespace_ryde1s.h)

    # RYDE-1S library dependencies with XKCP (namespaced to avoid conflicts)
    set(RYDE1S_LIB_SOURCES
        ryde1s/lib/rng/rng.c
        ryde1s/lib/xkcp/KeccakHash.c
        ryde1s/lib/xkcp/KeccakHashtimes4.c
        ryde1s/lib/xkcp/KeccakSponge.c
        ryde1s/lib/xkcp/KeccakSpongetimes4.c
        ryde1s/lib/xkcp/SimpleFIPS202.c
        ryde1s/lib/xkcp/opt64/KeccakP-1600-opt64.c
        ryde1s/lib/xkcp/opt64/KeccakP-1600-times4-on1.c
    )

    # Main RYDE1S algorithm sources (without glue code)
    set(RYDE1S_SOURCES
        ${RYDE1S_LIB_SOURCES}
        ryde1s/binary_matrix.c
        ryde1s/field_53.c
        ryde1s/field_matrix.c
        ryde1s/field_vector.c
        ryde1s/ggm_tree.c
        ryde1s/hash_sha3_256.c
        ryde1s/hash_sha3_x4_256.c
        ryde1s/keygen.c
        ryde1s/parsing.c
        ryde1s/sign.c
        ryde1s/tcith_sign.c
        ryde1s/tcith_verify.c
        ryde1s/tcith.c
    )

    add_library(ryde1s_ref OBJECT ${RYDE1S_SOURCES})
    target_include_directories(ryde1s_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s/lib
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s/lib/rng
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s/lib/xkcp
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s/lib/xkcp/avx2
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s/lib/xkcp/opt64)
    target_compile_options(ryde1s_ref PRIVATE "-include" ${RYDE1S_NAMESPACE_HEADER})

    # Add the glue code as a separate object for the ryde1s variant
    add_library(ryde1s_glue OBJECT sig_ryde1s.c)
    target_include_directories(ryde1s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/ryde1s)
    target_compile_options(ryde1s_glue PRIVATE "-include" ${RYDE1S_NAMESPACE_HEADER})

    set(_RYDE_OBJS ${_RYDE_OBJS} $<TARGET_OBJECTS:ryde1s_ref> $<TARGET_OBJECTS:ryde1s_glue>)
endif()

set(RYDE_OBJS ${_RYDE_OBJS} PARENT_SCOPE)