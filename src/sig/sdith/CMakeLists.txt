# SPDX-License-Identifier: MIT

set(_SDITH_OBJS "")
set(_SDITH_LIBS "")

# sdith_cat1_short bundled dependencies (namespaced to avoid conflicts)
set(SDITH_CAT1_SHORT_LIB_SOURCES
    sdith_cat1_short/lib/aes/aes_ansi_ref.c
    sdith_cat1_short/lib/aes/aes128_ctrle_ref.c
    sdith_cat1_short/lib/aes/aes128_ctrle_special_ref.c
    sdith_cat1_short/lib/aes/rijndael256_ctrle_ref.c
    sdith_cat1_short/lib/aes/rijndael256_ctrle_special_ref.c
    sdith_cat1_short/lib/aes/rijndael256.c

    sdith_cat1_short/lib/sha3/KeccakHash.c
    sdith_cat1_short/lib/sha3/KeccakHashtimes4.c
    sdith_cat1_short/lib/sha3/KeccakSponge.c
    sdith_cat1_short/lib/sha3/KeccakSpongetimes4.c

    sdith_cat1_short/lib/sha3/opt64/KeccakP-1600-opt64.c
    sdith_cat1_short/lib/sha3/opt64/KeccakP-1600-times4-on1.c

    sdith_cat1_short/lib/sha3/plain32/KeccakP-1600-inplace32BI.c
    sdith_cat1_short/lib/sha3/plain32/KeccakP-1600-times4-on1.c
)

if(OQS_ENABLE_SIG_sdith_cat1_short)
    set(SDITH_CAT1_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/namespace_sdith_cat1_short.h)

    set(SDITH_CAT1_SHORT_SOURCES
        ${SDITH_CAT1_SHORT_LIB_SOURCES}
        sdith_cat1_short/common.c
        sdith_cat1_short/gf128.c
        sdith_cat1_short/gf192.c
        sdith_cat1_short/gf256.c
        sdith_cat1_short/ggm.c
        sdith_cat1_short/rng.c
        sdith_cat1_short/rsd.c
        sdith_cat1_short/matrix_transpose_f2.c
        sdith_cat1_short/matrix_vector_products_f2.c
        sdith_cat1_short/piop_circuit.c
        sdith_cat1_short/PQCgenKAT_sign.c
        sdith_cat1_short/sdith_prng.c
        sdith_cat1_short/sdith_signature_parameters.c
        sdith_cat1_short/sdith_signature.c
        sdith_cat1_short/sign.c
        sdith_cat1_short/vole_expansion.c
        sdith_cat1_short/vole_to_piop.c
    )

    add_library(sdith_cat1_short_ref OBJECT ${SDITH_CAT1_SHORT_SOURCES})
    target_include_directories(sdith_cat1_short_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/lib
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/lib/aes
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/lib/sha3/opt64
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short/lib/sha3/plain32
       )

    target_compile_options(sdith_cat1_short_ref PRIVATE "-include" ${SDITH_CAT1_SHORT_NAMESPACE_HEADER})

    add_library(sdith_cat1_short_glue OBJECT sig_sdith_cat1_short.c)
    target_include_directories(sdith_cat1_short_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/sdith_cat1_short)
    target_compile_options(sdith_cat1_short_glue PRIVATE "-include" ${SDITH_CAT1_SHORT_NAMESPACE_HEADER})

    set(_SDITH_OBJS ${_SDITH_OBJS} $<TARGET_OBJECTS:sdith_cat1_short_ref> $<TARGET_OBJECTS:sdith_cat1_short_glue>)
endif()


list(REMOVE_DUPLICATES _SDITH_LIBS)

set(SDITH_OBJS ${_SDITH_OBJS} PARENT_SCOPE)
set(SDITH_LIBS ${_SDITH_LIBS} PARENT_SCOPE)