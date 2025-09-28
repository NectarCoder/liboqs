# SPDX-License-Identifier: MIT

set(_RYDE_OBJS "")

# RYDE library dependencies with XKCP (namespaced to avoid conflicts)
set(RYDE_LIB_SOURCES
    ryde1f/lib/avx2/KeccakP-1600-times4-SIMD256.c
    ryde1f/lib/opt64/KeccakP-1600-opt64.c
    ryde1f/lib/opt64/KeccakP-1600-times4-on1.c
    ryde1f/lib/rng/rng.c
    ryde1f/lib/xkcp/KeccakHash.c
    ryde1f/lib/xkcp/KeccakHashtimes4.c
    ryde1f/lib/xkcp/KeccakSponge.c
    ryde1f/lib/xkcp/KeccakSpongetimes4.c
    ryde1f/lib/xkcp/SimpleFIPS202.c
    #src/common/sha3/xkcp_low/KeccakP-1600times4/avx2/KeccakP-1600-times4-SIMD256.c
)

if(OQS_ENABLE_SIG_ryde1f)
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
        ryde1f/PQCgenKAT_sign.c
        ryde1f/sign.c
        ryde1f/tcith_sign.c
        ryde1f/tcith_verify.c
        ryde1f/tcith.c
    )

    add_library(ryde1f_ref OBJECT ${RYDE1F_SOURCES})
    
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f)
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib)
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/rng)
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp)
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp/avx2)
    target_include_directories(ryde1f_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f/lib/xkcp/opt64)
    #target_include_directories(ryde1f_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    # Apply same symbol namespacing to the algorithm sources
    target_compile_definitions(ryde1f_ref PRIVATE 
        # XKCP exposes StaticInitialize/AddByte as macros on little-endian builds,
        # so we leave those untouched to avoid macro redefinition warnings.
        # Core Keccak functions
    KeccakP1600_Initialize=RYDE_KeccakP1600_Initialize
    KeccakP1600_AddBytes=RYDE_KeccakP1600_AddBytes
    KeccakP1600_OverwriteBytes=RYDE_KeccakP1600_OverwriteBytes
    KeccakP1600_OverwriteWithZeroes=RYDE_KeccakP1600_OverwriteWithZeroes
    KeccakP1600_Permute_Nrounds=RYDE_KeccakP1600_Permute_Nrounds
    KeccakP1600_Permute_12rounds=RYDE_KeccakP1600_Permute_12rounds
    KeccakP1600_Permute_24rounds=RYDE_KeccakP1600_Permute_24rounds
    KeccakP1600_ExtractBytes=RYDE_KeccakP1600_ExtractBytes
    KeccakP1600_ExtractAndAddBytes=RYDE_KeccakP1600_ExtractAndAddBytes
        # Lane-based functions
    KeccakP1600_AddBytesInLane=RYDE_KeccakP1600_AddBytesInLane
    KeccakP1600_AddLanes=RYDE_KeccakP1600_AddLanes
    KeccakP1600_OverwriteBytesInLane=RYDE_KeccakP1600_OverwriteBytesInLane
    KeccakP1600_OverwriteLanes=RYDE_KeccakP1600_OverwriteLanes
    KeccakP1600_ExtractBytesInLane=RYDE_KeccakP1600_ExtractBytesInLane
    KeccakP1600_ExtractLanes=RYDE_KeccakP1600_ExtractLanes
    KeccakP1600_ExtractAndAddBytesInLane=RYDE_KeccakP1600_ExtractAndAddBytesInLane
    KeccakP1600_ExtractAndAddLanes=RYDE_KeccakP1600_ExtractAndAddLanes
        # High-level hash functions
    KeccakHash=RYDE_KeccakHash
    KeccakHashInitialize=RYDE_KeccakHashInitialize
    KeccakHashUpdate=RYDE_KeccakHashUpdate
    KeccakHashFinal=RYDE_KeccakHashFinal
    KeccakHashSqueeze=RYDE_KeccakHashSqueeze
        # Sponge functions
    KeccakSponge=RYDE_KeccakSponge
    KeccakSpongeInitialize=RYDE_KeccakSpongeInitialize
    KeccakSpongeAbsorb=RYDE_KeccakSpongeAbsorb
    KeccakSpongeAbsorbLastFewBits=RYDE_KeccakSpongeAbsorbLastFewBits
    KeccakSpongeSqueeze=RYDE_KeccakSpongeSqueeze
        # FIPS202 functions
    SHAKE128=RYDE_SHAKE128
    SHAKE256=RYDE_SHAKE256
    SHA3_224=RYDE_SHA3_224
    SHA3_256=RYDE_SHA3_256
    SHA3_384=RYDE_SHA3_384
    SHA3_512=RYDE_SHA3_512
        # Fast loop optimizations
    KeccakF1600_FastLoop_Absorb=RYDE_KeccakF1600_FastLoop_Absorb
    KeccakP1600_12rounds_FastLoop_Absorb=RYDE_KeccakP1600_12rounds_FastLoop_Absorb
        # Disable KECCAK_IMPL_NAMESPACE to prevent double-definition
    KECCAK_IMPL_NAMESPACE=RYDE_KECCAK_IMPL_NAMESPACE
    )
    
    # Add the glue code as a separate object for the ryde1f variant
    add_library(ryde1f_glue OBJECT sig_ryde1f.c)
    target_include_directories(ryde1f_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(ryde1f_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ryde1f)

    set(_RYDE_OBJS ${_RYDE_OBJS} $<TARGET_OBJECTS:ryde1f_ref> $<TARGET_OBJECTS:ryde1f_glue>)
endif()

set(RYDE_OBJS ${_RYDE_OBJS} PARENT_SCOPE)