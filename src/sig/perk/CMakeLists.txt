# SPDX-License-Identifier: MIT

set(_PERK_OBJS "")

# Shared PERK library dependencies with XKCP (namespaced to avoid conflicts)
# All PERK variants use identical lib/ files, so we create one shared library
set(PERK_SHARED_LIB_SOURCES
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

# Create shared library only once if any PERK variant is enabled
if(OQS_ENABLE_SIG_perk_128_fast_3 OR OQS_ENABLE_SIG_perk_128_fast_5)
    add_library(perk_shared_lib OBJECT ${PERK_SHARED_LIB_SOURCES})
    
    target_include_directories(perk_shared_lib PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib)
    target_include_directories(perk_shared_lib PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/cryptocode)
    target_include_directories(perk_shared_lib PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/djbsort)
    target_include_directories(perk_shared_lib PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/randombytes)
    target_include_directories(perk_shared_lib PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/XKCP)
    target_include_directories(perk_shared_lib PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    # Comprehensive XKCP symbol namespacing to avoid conflicts with liboqs XKCP
    target_compile_definitions(perk_shared_lib PRIVATE 
        # Core Keccak functions
        KeccakP1600_StaticInitialize=PERK_KeccakP1600_StaticInitialize
        KeccakP1600_Initialize=PERK_KeccakP1600_Initialize
        KeccakP1600_AddByte=PERK_KeccakP1600_AddByte
        KeccakP1600_AddBytes=PERK_KeccakP1600_AddBytes
        KeccakP1600_OverwriteBytes=PERK_KeccakP1600_OverwriteBytes
        KeccakP1600_OverwriteWithZeroes=PERK_KeccakP1600_OverwriteWithZeroes
        KeccakP1600_Permute_Nrounds=PERK_KeccakP1600_Permute_Nrounds
        KeccakP1600_Permute_12rounds=PERK_KeccakP1600_Permute_12rounds
        KeccakP1600_Permute_24rounds=PERK_KeccakP1600_Permute_24rounds
        KeccakP1600_ExtractBytes=PERK_KeccakP1600_ExtractBytes
        KeccakP1600_ExtractAndAddBytes=PERK_KeccakP1600_ExtractAndAddBytes
        # Lane-based functions
        KeccakP1600_AddBytesInLane=PERK_KeccakP1600_AddBytesInLane
        KeccakP1600_AddLanes=PERK_KeccakP1600_AddLanes
        KeccakP1600_OverwriteBytesInLane=PERK_KeccakP1600_OverwriteBytesInLane
        KeccakP1600_OverwriteLanes=PERK_KeccakP1600_OverwriteLanes
        KeccakP1600_ExtractBytesInLane=PERK_KeccakP1600_ExtractBytesInLane
        KeccakP1600_ExtractLanes=PERK_KeccakP1600_ExtractLanes
        KeccakP1600_ExtractAndAddBytesInLane=PERK_KeccakP1600_ExtractAndAddBytesInLane
        KeccakP1600_ExtractAndAddLanes=PERK_KeccakP1600_ExtractAndAddLanes
        # High-level hash functions
        KeccakHash=PERK_KeccakHash
        KeccakHashInitialize=PERK_KeccakHashInitialize
        KeccakHashUpdate=PERK_KeccakHashUpdate
        KeccakHashFinal=PERK_KeccakHashFinal
        KeccakHashSqueeze=PERK_KeccakHashSqueeze
        # Sponge functions
        KeccakSponge=PERK_KeccakSponge
        KeccakSpongeInitialize=PERK_KeccakSpongeInitialize
        KeccakSpongeAbsorb=PERK_KeccakSpongeAbsorb
        KeccakSpongeAbsorbLastFewBits=PERK_KeccakSpongeAbsorbLastFewBits
        KeccakSpongeSqueeze=PERK_KeccakSpongeSqueeze
        # FIPS202 functions
        SHAKE128=PERK_SHAKE128
        SHAKE256=PERK_SHAKE256
        SHA3_224=PERK_SHA3_224
        SHA3_256=PERK_SHA3_256
        SHA3_384=PERK_SHA3_384
        SHA3_512=PERK_SHA3_512
        # Fast loop optimizations
        KeccakF1600_FastLoop_Absorb=PERK_KeccakF1600_FastLoop_Absorb
        KeccakP1600_12rounds_FastLoop_Absorb=PERK_KeccakP1600_12rounds_FastLoop_Absorb
        # Disable KECCAK_IMPL_NAMESPACE to prevent double-definition
        KECCAK_IMPL_NAMESPACE=PERK_KECCAK_IMPL_NAMESPACE
    )
endif()

if(OQS_ENABLE_SIG_perk_128_fast_3)
    # Main PERK algorithm sources (without lib dependencies)
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

    add_library(perk_128_fast_3_ref OBJECT ${PERK_128_FAST_3_SOURCES})
    
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/cryptocode)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/djbsort)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/randombytes)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/XKCP)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    # Apply same symbol namespacing to the algorithm sources
    target_compile_definitions(perk_128_fast_3_ref PRIVATE 
        # Core Keccak functions
        KeccakP1600_StaticInitialize=PERK_KeccakP1600_StaticInitialize
        KeccakP1600_Initialize=PERK_KeccakP1600_Initialize
        KeccakP1600_AddByte=PERK_KeccakP1600_AddByte
        KeccakP1600_AddBytes=PERK_KeccakP1600_AddBytes
        KeccakP1600_OverwriteBytes=PERK_KeccakP1600_OverwriteBytes
        KeccakP1600_OverwriteWithZeroes=PERK_KeccakP1600_OverwriteWithZeroes
        KeccakP1600_Permute_Nrounds=PERK_KeccakP1600_Permute_Nrounds
        KeccakP1600_Permute_12rounds=PERK_KeccakP1600_Permute_12rounds
        KeccakP1600_Permute_24rounds=PERK_KeccakP1600_Permute_24rounds
        KeccakP1600_ExtractBytes=PERK_KeccakP1600_ExtractBytes
        KeccakP1600_ExtractAndAddBytes=PERK_KeccakP1600_ExtractAndAddBytes
        # High-level hash functions
        KeccakHash=PERK_KeccakHash
        KeccakHashInitialize=PERK_KeccakHashInitialize
        KeccakHashUpdate=PERK_KeccakHashUpdate
        KeccakHashFinal=PERK_KeccakHashFinal
        KeccakHashSqueeze=PERK_KeccakHashSqueeze
        # FIPS202 functions
        SHAKE128=PERK_SHAKE128
        SHAKE256=PERK_SHAKE256
        SHA3_224=PERK_SHA3_224
        SHA3_256=PERK_SHA3_256
        SHA3_384=PERK_SHA3_384
        SHA3_512=PERK_SHA3_512
    )
    
    # Add the glue code as a separate object for the perk_128_fast_3 variant
    add_library(perk_128_fast_3_glue OBJECT sig_perk_128_fast_3.c)
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_include_directories(perk_128_fast_3_glue PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_shared_lib> $<TARGET_OBJECTS:perk_128_fast_3_ref> $<TARGET_OBJECTS:perk_128_fast_3_glue>)
endif()

set(PERK_OBJS ${_PERK_OBJS} PARENT_SCOPE)