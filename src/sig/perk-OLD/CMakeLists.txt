# SPDX-License-Identifier: MIT

set(_PERK_OBJS "")
set(_PERK_LIBS "")

# PERK 128-fast-3 bundled dependencies (namespaced to avoid conflicts)
set(PERK_128_FAST_3_LIB_SOURCES
    perk_128_fast_3/lib/cryptocode/crypto_memset.c
    perk_128_fast_3/lib/djbsort/djbsort.c
    perk_128_fast_3/lib/djbsort/sort.c
    perk_128_fast_3/lib/randombytes/rng.c
    perk_128_fast_3/lib/XKCP/KeccakHash.c
    perk_128_fast_3/lib/XKCP/KeccakHashtimes4.c
    perk_128_fast_3/lib/XKCP/KeccakP-1600-opt64.c
    perk_128_fast_3/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_128_fast_3/lib/XKCP/KeccakSponge.c
    perk_128_fast_3/lib/XKCP/KeccakSpongetimes4.c
    perk_128_fast_3/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_128_fast_3)
    set(PERK_128_FAST_3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/namespace_perk_128_fast_3.h)

    set(PERK_128_FAST_3_SOURCES
        ${PERK_128_FAST_3_LIB_SOURCES}
        perk_128_fast_3/arithmetic.c
        perk_128_fast_3/common.c
        perk_128_fast_3/keygen.c
        perk_128_fast_3/parsing.c
        perk_128_fast_3/permutation.c
        perk_128_fast_3/sign.c
        perk_128_fast_3/signature.c
        perk_128_fast_3/symmetric.c
        perk_128_fast_3/theta_tree.c
        perk_128_fast_3/verbose.c
        perk_128_fast_3/verify.c
    )

    add_library(perk_128_fast_3_ref OBJECT ${PERK_128_FAST_3_SOURCES})
    target_include_directories(perk_128_fast_3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/XKCP)
    target_compile_options(perk_128_fast_3_ref PRIVATE "-include" ${PERK_128_FAST_3_NAMESPACE_HEADER})

    add_library(perk_128_fast_3_glue OBJECT sig_perk_128_fast_3.c)
    target_include_directories(perk_128_fast_3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_compile_options(perk_128_fast_3_glue PRIVATE "-include" ${PERK_128_FAST_3_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_128_fast_3_ref> $<TARGET_OBJECTS:perk_128_fast_3_glue>)
endif()


# PERK 128-short-3 bundled dependencies (namespaced to avoid conflicts)
set(PERK_128_SHORT_3_LIB_SOURCES
    perk_128_short_3/lib/cryptocode/crypto_memset.c
    perk_128_short_3/lib/djbsort/djbsort.c
    perk_128_short_3/lib/djbsort/sort.c
    perk_128_short_3/lib/randombytes/rng.c
    perk_128_short_3/lib/XKCP/KeccakHash.c
    perk_128_short_3/lib/XKCP/KeccakHashtimes4.c
    perk_128_short_3/lib/XKCP/KeccakP-1600-opt64.c
    perk_128_short_3/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_128_short_3/lib/XKCP/KeccakSponge.c
    perk_128_short_3/lib/XKCP/KeccakSpongetimes4.c
    perk_128_short_3/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_128_short_3)
    set(PERK_128_SHORT_3_SOURCES
        ${PERK_128_SHORT_3_LIB_SOURCES}
        perk_128_short_3/arithmetic.c
        perk_128_short_3/common.c
        perk_128_short_3/keygen.c
        perk_128_short_3/parsing.c
        perk_128_short_3/permutation.c
        perk_128_short_3/sign.c
        perk_128_short_3/signature.c
        perk_128_short_3/symmetric.c
        perk_128_short_3/theta_tree.c
        perk_128_short_3/verbose.c
        perk_128_short_3/verify.c
    )

    add_library(perk_128_short_3_ref OBJECT ${PERK_128_SHORT_3_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_128_short_3_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_128_short_3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/lib/XKCP)

    set(PERK_128_SHORT_3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3/namespace_perk_128_short_3.h)
    target_compile_options(perk_128_short_3_ref PRIVATE "-include" ${PERK_128_SHORT_3_NAMESPACE_HEADER})

    add_library(perk_128_short_3_glue OBJECT sig_perk_128_short_3.c)
    target_include_directories(perk_128_short_3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_3)
    target_compile_options(perk_128_short_3_glue PRIVATE "-include" ${PERK_128_SHORT_3_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_128_short_3_ref> $<TARGET_OBJECTS:perk_128_short_3_glue>)
endif()

#///////////////////////////////////////////////////////////////////
# PERK 128-short-5 bundled dependencies (namespaced to avoid conflicts)
set(PERK_128_SHORT_5_LIB_SOURCES
    perk_128_short_5/lib/cryptocode/crypto_memset.c
    perk_128_short_5/lib/djbsort/djbsort.c
    perk_128_short_5/lib/djbsort/sort.c
    perk_128_short_5/lib/randombytes/rng.c
    perk_128_short_5/lib/XKCP/KeccakHash.c
    perk_128_short_5/lib/XKCP/KeccakHashtimes4.c
    perk_128_short_5/lib/XKCP/KeccakP-1600-opt64.c
    perk_128_short_5/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_128_short_5/lib/XKCP/KeccakSponge.c
    perk_128_short_5/lib/XKCP/KeccakSpongetimes4.c
    perk_128_short_5/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_128_short_5)
    set(PERK_128_SHORT_5_SOURCES
        ${PERK_128_SHORT_5_LIB_SOURCES}
        perk_128_short_5/arithmetic.c
        perk_128_short_5/common.c
        perk_128_short_5/keygen.c
        perk_128_short_5/parsing.c
        perk_128_short_5/permutation.c
        perk_128_short_5/sign.c
        perk_128_short_5/signature.c
        perk_128_short_5/symmetric.c
        perk_128_short_5/theta_tree.c
        perk_128_short_5/verbose.c
        perk_128_short_5/verify.c
    )

    add_library(perk_128_short_5_ref OBJECT ${PERK_128_SHORT_5_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_128_short_5_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_128_short_5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/lib/XKCP)

    set(PERK_128_SHORT_5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5/namespace_perk_128_short_5.h)
    target_compile_options(perk_128_short_5_ref PRIVATE "-include" ${PERK_128_SHORT_5_NAMESPACE_HEADER})

    add_library(perk_128_short_5_glue OBJECT sig_perk_128_short_5.c)
    target_include_directories(perk_128_short_5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_128_short_5)
    target_compile_options(perk_128_short_5_glue PRIVATE "-include" ${PERK_128_SHORT_5_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_128_short_5_ref> $<TARGET_OBJECTS:perk_128_short_5_glue>)
endif()

#//////////////////////////////////////////////////////////////////

# PERK 192-short-3 bundled dependencies (namespaced to avoid conflicts)
set(PERK_192_SHORT_3_LIB_SOURCES
    perk_192_short_3/lib/cryptocode/crypto_memset.c
    perk_192_short_3/lib/djbsort/djbsort.c
    perk_192_short_3/lib/djbsort/sort.c
    perk_192_short_3/lib/randombytes/rng.c
    perk_192_short_3/lib/XKCP/KeccakHash.c
    perk_192_short_3/lib/XKCP/KeccakHashtimes4.c
    perk_192_short_3/lib/XKCP/KeccakP-1600-opt64.c
    perk_192_short_3/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_192_short_3/lib/XKCP/KeccakSponge.c
    perk_192_short_3/lib/XKCP/KeccakSpongetimes4.c
    perk_192_short_3/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_192_short_3)
    set(PERK_192_SHORT_3_SOURCES
        ${PERK_192_SHORT_3_LIB_SOURCES}
        perk_192_short_3/arithmetic.c
        perk_192_short_3/common.c
        perk_192_short_3/keygen.c
        perk_192_short_3/parsing.c
        perk_192_short_3/permutation.c
        perk_192_short_3/sign.c
        perk_192_short_3/signature.c
        perk_192_short_3/symmetric.c
        perk_192_short_3/theta_tree.c
        perk_192_short_3/verbose.c
        perk_192_short_3/verify.c
    )

    add_library(perk_192_short_3_ref OBJECT ${PERK_192_SHORT_3_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_192_short_3_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_192_short_3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/lib/XKCP)

    set(PERK_192_SHORT_3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3/namespace_perk_192_short_3.h)
    target_compile_options(perk_192_short_3_ref PRIVATE "-include" ${PERK_192_SHORT_3_NAMESPACE_HEADER})

    add_library(perk_192_short_3_glue OBJECT sig_perk_192_short_3.c)
    target_include_directories(perk_192_short_3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_3)
    target_compile_options(perk_192_short_3_glue PRIVATE "-include" ${PERK_192_SHORT_3_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_192_short_3_ref> $<TARGET_OBJECTS:perk_192_short_3_glue>)
endif()

#///////////////////////////////////////////////////////////////////

# PERK 192-short-5 bundled dependencies (namespaced to avoid conflicts)
set(PERK_192_SHORT_5_LIB_SOURCES
    perk_192_short_5/lib/cryptocode/crypto_memset.c
    perk_192_short_5/lib/djbsort/djbsort.c
    perk_192_short_5/lib/djbsort/sort.c
    perk_192_short_5/lib/randombytes/rng.c
    perk_192_short_5/lib/XKCP/KeccakHash.c
    perk_192_short_5/lib/XKCP/KeccakHashtimes4.c
    perk_192_short_5/lib/XKCP/KeccakP-1600-opt64.c
    perk_192_short_5/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_192_short_5/lib/XKCP/KeccakSponge.c
    perk_192_short_5/lib/XKCP/KeccakSpongetimes4.c
    perk_192_short_5/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_192_short_5)
    set(PERK_192_SHORT_5_SOURCES
        ${PERK_192_SHORT_5_LIB_SOURCES}
        perk_192_short_5/arithmetic.c
        perk_192_short_5/common.c
        perk_192_short_5/keygen.c
        perk_192_short_5/parsing.c
        perk_192_short_5/permutation.c
        perk_192_short_5/sign.c
        perk_192_short_5/signature.c
        perk_192_short_5/symmetric.c
        perk_192_short_5/theta_tree.c
        perk_192_short_5/verbose.c
        perk_192_short_5/verify.c
    )

    add_library(perk_192_short_5_ref OBJECT ${PERK_192_SHORT_5_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_192_short_5_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_192_short_5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/lib/XKCP)

    set(PERK_192_SHORT_5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5/namespace_perk_192_short_5.h)
    target_compile_options(perk_192_short_5_ref PRIVATE "-include" ${PERK_192_SHORT_5_NAMESPACE_HEADER})

    add_library(perk_192_short_5_glue OBJECT sig_perk_192_short_5.c)
    target_include_directories(perk_192_short_5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_192_short_5)
    target_compile_options(perk_192_short_5_glue PRIVATE "-include" ${PERK_192_SHORT_5_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_192_short_5_ref> $<TARGET_OBJECTS:perk_192_short_5_glue>)
endif()


#///////////////////////////////////////////////////////////////////

# PERK 256-short-3 bundled dependencies (namespaced to avoid conflicts)
set(PERK_256_SHORT_3_LIB_SOURCES
    perk_256_short_3/lib/cryptocode/crypto_memset.c
    perk_256_short_3/lib/djbsort/djbsort.c
    perk_256_short_3/lib/djbsort/sort.c
    perk_256_short_3/lib/randombytes/rng.c
    perk_256_short_3/lib/XKCP/KeccakHash.c
    perk_256_short_3/lib/XKCP/KeccakHashtimes4.c
    perk_256_short_3/lib/XKCP/KeccakP-1600-opt64.c
    perk_256_short_3/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_256_short_3/lib/XKCP/KeccakSponge.c
    perk_256_short_3/lib/XKCP/KeccakSpongetimes4.c
    perk_256_short_3/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_256_short_3)
    set(PERK_256_SHORT_3_SOURCES
        ${PERK_256_SHORT_3_LIB_SOURCES}
        perk_256_short_3/arithmetic.c
        perk_256_short_3/common.c
        perk_256_short_3/keygen.c
        perk_256_short_3/parsing.c
        perk_256_short_3/permutation.c
        perk_256_short_3/sign.c
        perk_256_short_3/signature.c
        perk_256_short_3/symmetric.c
        perk_256_short_3/theta_tree.c
        perk_256_short_3/verbose.c
        perk_256_short_3/verify.c
    )

    add_library(perk_256_short_3_ref OBJECT ${PERK_256_SHORT_3_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_256_short_3_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_256_short_3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/lib/XKCP)

    set(PERK_256_SHORT_3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3/namespace_perk_256_short_3.h)
    target_compile_options(perk_256_short_3_ref PRIVATE "-include" ${PERK_256_SHORT_3_NAMESPACE_HEADER})

    add_library(perk_256_short_3_glue OBJECT sig_perk_256_short_3.c)
    target_include_directories(perk_256_short_3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_3)
    target_compile_options(perk_256_short_3_glue PRIVATE "-include" ${PERK_256_SHORT_3_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_256_short_3_ref> $<TARGET_OBJECTS:perk_256_short_3_glue>)
endif()

#///////////////////////////////////////////////////////////////////

# PERK 256-short-5 bundled dependencies (namespaced to avoid conflicts)
set(PERK_256_SHORT_5_LIB_SOURCES
    perk_256_short_5/lib/cryptocode/crypto_memset.c
    perk_256_short_5/lib/djbsort/djbsort.c
    perk_256_short_5/lib/djbsort/sort.c
    perk_256_short_5/lib/randombytes/rng.c
    perk_256_short_5/lib/XKCP/KeccakHash.c
    perk_256_short_5/lib/XKCP/KeccakHashtimes4.c
    perk_256_short_5/lib/XKCP/KeccakP-1600-opt64.c
    perk_256_short_5/lib/XKCP/KeccakP-1600-times4-on1.c
    perk_256_short_5/lib/XKCP/KeccakSponge.c
    perk_256_short_5/lib/XKCP/KeccakSpongetimes4.c
    perk_256_short_5/lib/XKCP/SimpleFIPS202.c
)

if(OQS_ENABLE_SIG_perk_256_short_5)
    set(PERK_256_SHORT_5_SOURCES
        ${PERK_256_SHORT_5_LIB_SOURCES}
        perk_256_short_5/arithmetic.c
        perk_256_short_5/common.c
        perk_256_short_5/keygen.c
        perk_256_short_5/parsing.c
        perk_256_short_5/permutation.c
        perk_256_short_5/sign.c
        perk_256_short_5/signature.c
        perk_256_short_5/symmetric.c
        perk_256_short_5/theta_tree.c
        perk_256_short_5/verbose.c
        perk_256_short_5/verify.c
    )

    add_library(perk_256_short_5_ref OBJECT ${PERK_256_SHORT_5_SOURCES})

    find_library(GMP_LIB gmp)
    if(NOT GMP_LIB)
        message(FATAL_ERROR "GMP library not found. Please install libgmp-dev.")
    endif()
    target_link_libraries(perk_256_short_5_ref INTERFACE ${GMP_LIB})
    list(APPEND _PERK_LIBS ${GMP_LIB})

    target_include_directories(perk_256_short_5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/lib
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/lib/cryptocode
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/lib/djbsort
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/lib/randombytes
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/lib/XKCP)

    set(PERK_256_SHORT_5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5/namespace_perk_256_short_5.h)
    target_compile_options(perk_256_short_5_ref PRIVATE "-include" ${PERK_256_SHORT_5_NAMESPACE_HEADER})

    add_library(perk_256_short_5_glue OBJECT sig_perk_256_short_5.c)
    target_include_directories(perk_256_short_5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/perk_256_short_5)
    target_compile_options(perk_256_short_5_glue PRIVATE "-include" ${PERK_256_SHORT_5_NAMESPACE_HEADER})

    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_256_short_5_ref> $<TARGET_OBJECTS:perk_256_short_5_glue>)
endif()

#////////////////////////////////////////////////////////////////////

list(REMOVE_DUPLICATES _PERK_LIBS)

set(PERK_OBJS ${_PERK_OBJS} PARENT_SCOPE)
set(PERK_LIBS ${_PERK_LIBS} PARENT_SCOPE)