# SPDX-License-Identifier: MIT

set(_PERK_OBJS "")

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
    # Main PERK algorithm sources (without lib dependencies)
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
    
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/cryptocode)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/djbsort)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/randombytes)
    target_include_directories(perk_128_fast_3_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3/lib/XKCP)
    
    # Apply same symbol namespacing to the algorithm sources
    target_compile_definitions(perk_128_fast_3_ref PRIVATE 
        # XKCP exposes StaticInitialize/AddByte as macros on little-endian builds,
        # so we leave those untouched to avoid macro redefinition warnings.
        # Core Keccak functions
    KeccakP1600_Initialize=PERK_128_FAST_3_KeccakP1600_Initialize
    KeccakP1600_AddBytes=PERK_128_FAST_3_KeccakP1600_AddBytes
    KeccakP1600_OverwriteBytes=PERK_128_FAST_3_KeccakP1600_OverwriteBytes
    KeccakP1600_OverwriteWithZeroes=PERK_128_FAST_3_KeccakP1600_OverwriteWithZeroes
    KeccakP1600_Permute_Nrounds=PERK_128_FAST_3_KeccakP1600_Permute_Nrounds
    KeccakP1600_Permute_12rounds=PERK_128_FAST_3_KeccakP1600_Permute_12rounds
    KeccakP1600_Permute_24rounds=PERK_128_FAST_3_KeccakP1600_Permute_24rounds
    KeccakP1600_ExtractBytes=PERK_128_FAST_3_KeccakP1600_ExtractBytes
    KeccakP1600_ExtractAndAddBytes=PERK_128_FAST_3_KeccakP1600_ExtractAndAddBytes
        # Lane-based functions
    KeccakP1600_AddBytesInLane=PERK_128_FAST_3_KeccakP1600_AddBytesInLane
    KeccakP1600_AddLanes=PERK_128_FAST_3_KeccakP1600_AddLanes
    KeccakP1600_OverwriteBytesInLane=PERK_128_FAST_3_KeccakP1600_OverwriteBytesInLane
    KeccakP1600_OverwriteLanes=PERK_128_FAST_3_KeccakP1600_OverwriteLanes
    KeccakP1600_ExtractBytesInLane=PERK_128_FAST_3_KeccakP1600_ExtractBytesInLane
    KeccakP1600_ExtractLanes=PERK_128_FAST_3_KeccakP1600_ExtractLanes
    KeccakP1600_ExtractAndAddBytesInLane=PERK_128_FAST_3_KeccakP1600_ExtractAndAddBytesInLane
    KeccakP1600_ExtractAndAddLanes=PERK_128_FAST_3_KeccakP1600_ExtractAndAddLanes
        # High-level hash functions
    KeccakHash=PERK_128_FAST_3_KeccakHash
    KeccakHashInitialize=PERK_128_FAST_3_KeccakHashInitialize
    KeccakHashUpdate=PERK_128_FAST_3_KeccakHashUpdate
    KeccakHashFinal=PERK_128_FAST_3_KeccakHashFinal
    KeccakHashSqueeze=PERK_128_FAST_3_KeccakHashSqueeze
        # Sponge functions
    KeccakSponge=PERK_128_FAST_3_KeccakSponge
    KeccakSpongeInitialize=PERK_128_FAST_3_KeccakSpongeInitialize
    KeccakSpongeAbsorb=PERK_128_FAST_3_KeccakSpongeAbsorb
    KeccakSpongeAbsorbLastFewBits=PERK_128_FAST_3_KeccakSpongeAbsorbLastFewBits
    KeccakSpongeSqueeze=PERK_128_FAST_3_KeccakSpongeSqueeze
        # FIPS202 functions
    SHAKE128=PERK_128_FAST_3_SHAKE128
    SHAKE256=PERK_128_FAST_3_SHAKE256
    SHA3_224=PERK_128_FAST_3_SHA3_224
    SHA3_256=PERK_128_FAST_3_SHA3_256
    SHA3_384=PERK_128_FAST_3_SHA3_384
    SHA3_512=PERK_128_FAST_3_SHA3_512
        # Fast loop optimizations
    KeccakF1600_FastLoop_Absorb=PERK_128_FAST_3_KeccakF1600_FastLoop_Absorb
    KeccakP1600_12rounds_FastLoop_Absorb=PERK_128_FAST_3_KeccakP1600_12rounds_FastLoop_Absorb
        # Disable KECCAK_IMPL_NAMESPACE to prevent double-definition
    KECCAK_IMPL_NAMESPACE=PERK_128_FAST_3_KECCAK_IMPL_NAMESPACE
    )
    
    # Add the glue code as a separate object for the perk_128_fast_3 variant
    add_library(perk_128_fast_3_glue OBJECT sig_perk_128_fast_3.c)
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(perk_128_fast_3_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/perk_128_fast_3)
    
    set(_PERK_OBJS ${_PERK_OBJS} $<TARGET_OBJECTS:perk_128_fast_3_ref> $<TARGET_OBJECTS:perk_128_fast_3_glue>)
endif()

set(PERK_OBJS ${_PERK_OBJS} PARENT_SCOPE)