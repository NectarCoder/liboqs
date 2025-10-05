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

set(FAEST_192S_LIB_SOURCES
    faest_192s/lib/KeccakHash.c
    faest_192s/lib/KeccakHashtimes4.c
    faest_192s/lib/KeccakP-1600-opt64.c
    faest_192s/lib/KeccakP-1600-times4-on1.c
    faest_192s/lib/KeccakSponge.c
    faest_192s/lib/KeccakSpongetimes4.c
)

set(FAEST_256S_LIB_SOURCES
    faest_256s/lib/KeccakHash.c
    faest_256s/lib/KeccakHashtimes4.c
    faest_256s/lib/KeccakP-1600-opt64.c
    faest_256s/lib/KeccakP-1600-times4-on1.c
    faest_256s/lib/KeccakSponge.c
    faest_256s/lib/KeccakSpongetimes4.c
)

set(FAEST_EM_128S_LIB_SOURCES
    faest_em_128s/lib/KeccakHash.c
    faest_em_128s/lib/KeccakHashtimes4.c
    faest_em_128s/lib/KeccakP-1600-opt64.c
    faest_em_128s/lib/KeccakP-1600-times4-on1.c
    faest_em_128s/lib/KeccakSponge.c
    faest_em_128s/lib/KeccakSpongetimes4.c
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
    target_compile_definitions(faest_128s_ref PRIVATE OQS_FAEST_DISABLE_VECTOR_ATTR)

    add_library(faest_128s_glue OBJECT sig_faest_128s.c)
    target_include_directories(faest_128s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/faest_128s)
    target_compile_options(faest_128s_glue PRIVATE "-include" ${FAEST_128S_NAMESPACE_HEADER})

    set(_FAEST_OBJS ${_FAEST_OBJS} $<TARGET_OBJECTS:faest_128s_ref> $<TARGET_OBJECTS:faest_128s_glue>)
endif()

if(OQS_ENABLE_SIG_faest_192s)
    set(FAEST_192S_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/faest_192s/namespace_faest_192s.h)

    set(FAEST_192S_SOURCES
        ${FAEST_192S_LIB_SOURCES}
        faest_192s/aes.c
        faest_192s/bavc.c
        faest_192s/compat.c
        faest_192s/crypto_sign.c
        faest_192s/faest.c
        faest_192s/faest_192s.c
        faest_192s/faest_aes.c
        faest_192s/fields.c
        faest_192s/instances.c
        faest_192s/owf.c
        faest_192s/random_oracle.c
        faest_192s/randomness.c
        faest_192s/rng.c
        faest_192s/universal_hashing.c
        faest_192s/utils.c
        faest_192s/vole.c
    )

    add_library(faest_192s_ref OBJECT ${FAEST_192S_SOURCES})
    target_include_directories(faest_192s_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/faest_192s
        ${CMAKE_CURRENT_LIST_DIR}/faest_192s/lib)
    target_compile_options(faest_192s_ref PRIVATE "-include" ${FAEST_192S_NAMESPACE_HEADER})
    target_compile_definitions(faest_192s_ref PRIVATE OQS_FAEST_DISABLE_VECTOR_ATTR)

    add_library(faest_192s_glue OBJECT sig_faest_192s.c)
    target_include_directories(faest_192s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/faest_192s)
    target_compile_options(faest_192s_glue PRIVATE "-include" ${FAEST_192S_NAMESPACE_HEADER})

    set(_FAEST_OBJS ${_FAEST_OBJS} $<TARGET_OBJECTS:faest_192s_ref> $<TARGET_OBJECTS:faest_192s_glue>)
endif()

if(OQS_ENABLE_SIG_faest_256s)
    set(FAEST_256S_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/faest_256s/namespace_faest_256s.h)

    set(FAEST_256S_SOURCES
        ${FAEST_256S_LIB_SOURCES}
        faest_256s/aes.c
        faest_256s/bavc.c
        faest_256s/compat.c
        faest_256s/crypto_sign.c
        faest_256s/faest.c
        faest_256s/faest_256s.c
        faest_256s/faest_aes.c
        faest_256s/fields.c
        faest_256s/instances.c
        faest_256s/owf.c
        faest_256s/random_oracle.c
        faest_256s/randomness.c
        faest_256s/rng.c
        faest_256s/universal_hashing.c
        faest_256s/utils.c
        faest_256s/vole.c
    )

    add_library(faest_256s_ref OBJECT ${FAEST_256S_SOURCES})
    target_include_directories(faest_256s_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/faest_256s
        ${CMAKE_CURRENT_LIST_DIR}/faest_256s/lib)
    target_compile_options(faest_256s_ref PRIVATE "-include" ${FAEST_256S_NAMESPACE_HEADER})
    target_compile_definitions(faest_256s_ref PRIVATE OQS_FAEST_DISABLE_VECTOR_ATTR)

    add_library(faest_256s_glue OBJECT sig_faest_256s.c)
    target_include_directories(faest_256s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/faest_256s)
    target_compile_options(faest_256s_glue PRIVATE "-include" ${FAEST_256S_NAMESPACE_HEADER})

    set(_FAEST_OBJS ${_FAEST_OBJS} $<TARGET_OBJECTS:faest_256s_ref> $<TARGET_OBJECTS:faest_256s_glue>)
endif()

if(OQS_ENABLE_SIG_faest_em_128s)
    set(FAEST_EM_128S_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/faest_em_128s/namespace_faest_em_128s.h)

    set(FAEST_EM_128S_SOURCES
        ${FAEST_EM_128S_LIB_SOURCES}
        faest_em_128s/aes.c
        faest_em_128s/bavc.c
        faest_em_128s/compat.c
        faest_em_128s/crypto_sign.c
        faest_em_128s/faest.c
        faest_em_128s/faest_em_128s.c
        faest_em_128s/faest_aes.c
        faest_em_128s/fields.c
        faest_em_128s/instances.c
        faest_em_128s/owf.c
        faest_em_128s/random_oracle.c
        faest_em_128s/randomness.c
        faest_em_128s/rng.c
        faest_em_128s/universal_hashing.c
        faest_em_128s/utils.c
        faest_em_128s/vole.c
    )

    add_library(faest_em_128s_ref OBJECT ${FAEST_EM_128S_SOURCES})
    target_include_directories(faest_em_128s_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/faest_em_128s
        ${CMAKE_CURRENT_LIST_DIR}/faest_em_128s/lib)
    target_compile_options(faest_em_128s_ref PRIVATE "-include" ${FAEST_EM_128S_NAMESPACE_HEADER})
    target_compile_definitions(faest_em_128s_ref PRIVATE OQS_FAEST_DISABLE_VECTOR_ATTR)

    add_library(faest_em_128s_glue OBJECT sig_faest_em_128s.c)
    target_include_directories(faest_em_128s_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/faest_em_128s)
    target_compile_options(faest_em_128s_glue PRIVATE "-include" ${FAEST_EM_128S_NAMESPACE_HEADER})

    set(_FAEST_OBJS ${_FAEST_OBJS} $<TARGET_OBJECTS:faest_em_128s_ref> $<TARGET_OBJECTS:faest_em_128s_glue>)
endif()

set(FAEST_OBJS ${_FAEST_OBJS} PARENT_SCOPE)
set(FAEST_LIBS ${_FAEST_LIBS} PARENT_SCOPE)