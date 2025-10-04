# SPDX-License-Identifier: MIT

set(_FAEST_OBJS "")
set(_FAEST_LIBS "")

# FAEST-128s bundled dependencies (namespaced to avoid conflicts)
set(FAEST_128S_LIB_SOURCES
    faest_128s/lib/KeccakHash.c
    faest_128s/lib/KeccakHashtimes4.c
    faest_128s/lib/KeccakP-1600-opt64.c
    faest_128s/lib/KeccakP-1600-times4-on1.c
    faest_128s/lib/KeccakSponge.c
    faest_128s/lib/KeccakSpongetimes4.c
)

if(OQS_ENABLE_SIG_faest_128s)
    set(FAEST_128S_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/faest_128s/namespace_faest_128s.h)

    set(FAEST_128S_SOURCES
        ${FAEST_128S_LIB_SOURCES}
        faest_128s/aes.c
        faest_128s/bavc.c
        faest_128s/compat.c
        faest_128s/crypto_sign.c
        faest_128s/faest.c
        faest_128s/faest_128s.c
        faest_128s/faest_aes.c
        faest_128s/fields.c
        faest_128s/instances.c
        faest_128s/owf.c
        faest_128s/random_oracle.c
        faest_128s/randomness.c
        faest_128s/rng.c
        faest_128s/universal_hashing.c
        faest_128s/utils.c
        faest_128s/vole.c
    )

    add_library(faest_128s_ref OBJECT ${FAEST_128S_SOURCES})
    target_include_directories(faest_128s_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/faest_128s
        ${CMAKE_CURRENT_LIST_DIR}/faest_128s/lib)
    target_compile_options(faest_128s_ref PRIVATE "-include" ${FAEST_128S_NAMESPACE_HEADER})

    add_library(faest_128s_glue OBJECT sig_faest_128s.c)
    target_include_directories(faest_128s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/faest_128s)
    target_compile_options(faest_128s_glue PRIVATE "-include" ${FAEST_128S_NAMESPACE_HEADER})

    set(_FAEST_OBJS ${_FAEST_OBJS} $<TARGET_OBJECTS:faest_128s_ref> $<TARGET_OBJECTS:faest_128s_glue>)
endif()

set(FAEST_OBJS ${_FAEST_OBJS} PARENT_SCOPE)
set(FAEST_LIBS ${_FAEST_LIBS} PARENT_SCOPE)