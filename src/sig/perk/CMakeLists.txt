# SPDX-License-Identifier: MIT

set(_PERK_OBJS "")

if(OQS_ENABLE_SIG_perk_128_fast_3)
    # Main PERK algorithm sources (without glue code)
    set(PERK_128_FAST_3_SOURCES
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

    # PERK library dependencies with XKCP (namespaced to avoid conflicts)
    set(PERK_LIB_SOURCES
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

    add_library(perk_128_fast_3_ref OBJECT ${PERK_128_FAST_3_SOURCES} ${PERK_LIB_SOURCES})
    
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/cryptocode)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/djbsort)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/randombytes)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/XKCP)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    # Add preprocessor definitions to avoid symbol conflicts with liboqs XKCP
    target_compile_definitions(perk_128_fast_3_ref PRIVATE 
        KeccakP1600_AddBytesInLane=PERK_KeccakP1600_AddBytesInLane
        KeccakP1600_AddLanes=PERK_KeccakP1600_AddLanes
        KeccakP1600_OverwriteBytesInLane=PERK_KeccakP1600_OverwriteBytesInLane
        KeccakP1600_OverwriteLanes=PERK_KeccakP1600_OverwriteLanes
        KeccakP1600_ExtractBytesInLane=PERK_KeccakP1600_ExtractBytesInLane
        KeccakP1600_ExtractLanes=PERK_KeccakP1600_ExtractLanes
        KeccakP1600_ExtractAndAddBytesInLane=PERK_KeccakP1600_ExtractAndAddBytesInLane
        KeccakP1600_ExtractAndAddLanes=PERK_KeccakP1600_ExtractAndAddLanes
        KeccakP1600_Permute_12rounds=PERK_KeccakP1600_Permute_12rounds
        KeccakP1600_Permute_24rounds=PERK_KeccakP1600_Permute_24rounds
        KeccakP1600_Initialize=PERK_KeccakP1600_Initialize
        KeccakP1600_StaticInitialize=PERK_KeccakP1600_StaticInitialize
        KeccakHash=PERK_KeccakHash
        KeccakHashInitialize=PERK_KeccakHashInitialize
        KeccakHashUpdate=PERK_KeccakHashUpdate
        KeccakHashFinal=PERK_KeccakHashFinal
        KeccakHashSqueeze=PERK_KeccakHashSqueeze
    )
    
    # Add the glue code as a separate object for the perk_128_fast_3 variant
    add_library(perk_128_fast_3_glue OBJECT sig_perk_128_fast_3.c)
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_include_directories(perk_128_fast_3_glue PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_128_fast_3_ref> $<TARGET_OBJECTS:perk_128_fast_3_glue>)
endif()

set(PERK_OBJS ${_PERK_OBJS} PARENT_SCOPE)