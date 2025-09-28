# SPDX-License-Identifier: MIT

set(_MIRATH_OBJS "")

if(OQS_ENABLE_SIG_mirath_tcith_1a_fast)
    # Main MIRATH algorithm sources (without lib dependencies)
    set(MIRATH_TCITH_1A_FAST_SOURCES
        mirath_tcith_1a_fast/main.c
        mirath_tcith_1a_fast/mirath_ggm_tree.c
        mirath_tcith_1a_fast/mirath_keygen.c
        mirath_tcith_1a_fast/mirath_matrix_ff.c
        mirath_tcith_1a_fast/mirath_parsing.c
        mirath_tcith_1a_fast/mirath_sign.c
        mirath_tcith_1a_fast/mirath_tcith.c
        mirath_tcith_1a_fast/verify.c
        mirath_tcith_1a_fast/sign.c
        )

    add_library(mirath_tcith_1a_fast_ref OBJECT ${MIRATH_TCITH_1A_FAST_SOURCES})
    
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast)
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcitH_1a_fast/common)
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcitH_1a_fast/parameters)
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcitH_1a_fast/arith)
    
    # Apply same symbol namespacing to the algorithm sources
    target_compile_definitions(mirath_tcith_1a_fast_ref PRIVATE 
        # XKCP exposes StaticInitialize/AddByte as macros on little-endian builds,
        # so we leave those untouched to avoid macro redefinition warnings.
        # Core Keccak functions
    KeccakP1600_Initialize=MIRATH_TCITH_1A_FAST_KeccakP1600_Initialize
    KeccakP1600_AddBytes=MIRATH_TCITH_1A_FAST_KeccakP1600_AddBytes
    KeccakP1600_OverwriteBytes=MIRATH_TCITH_1A_FAST_KeccakP1600_OverwriteBytes
    KeccakP1600_OverwriteWithZeroes=MIRATH_TCITH_1A_FAST_KeccakP1600_OverwriteWithZeroes
    KeccakP1600_Permute_Nrounds=MIRATH_TCITH_1A_FAST_KeccakP1600_Permute_Nrounds
    KeccakP1600_Permute_12rounds=MIRATH_TCITH_1A_FAST_KeccakP1600_Permute_12rounds
    KeccakP1600_Permute_24rounds=MIRATH_TCITH_1A_FAST_KeccakP1600_Permute_24rounds
    KeccakP1600_ExtractBytes=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractBytes
    KeccakP1600_ExtractAndAddBytes=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractAndAddBytes
        # Lane-based functions
    KeccakP1600_AddBytesInLane=MIRATH_TCITH_1A_FAST_KeccakP1600_AddBytesInLane
    KeccakP1600_AddLanes=MIRATH_TCITH_1A_FAST_KeccakP1600_AddLanes
    KeccakP1600_OverwriteBytesInLane=MIRATH_TCITH_1A_FAST_KeccakP1600_OverwriteBytesInLane
    KeccakP1600_OverwriteLanes=MIRATH_TCITH_1A_FAST_KeccakP1600_OverwriteLanes
    KeccakP1600_ExtractBytesInLane=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractBytesInLane
    KeccakP1600_ExtractLanes=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractLanes
    KeccakP1600_ExtractAndAddBytesInLane=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractAndAddBytesInLane
    KeccakP1600_ExtractAndAddLanes=MIRATH_TCITH_1A_FAST_KeccakP1600_ExtractAndAddLanes
        # High-level hash functions
    KeccakHash=MIRATH_TCITH_1A_FAST_KeccakHash
    KeccakHashInitialize=MIRATH_TCITH_1A_FAST_KeccakHashInitialize
    KeccakHashUpdate=MIRATH_TCITH_1A_FAST_KeccakHashUpdate
    KeccakHashFinal=MIRATH_TCITH_1A_FAST_KeccakHashFinal
    KeccakHashSqueeze=MIRATH_TCITH_1A_FAST_KeccakHashSqueeze
        # Sponge functions
    KeccakSponge=MIRATH_TCITH_1A_FAST_KeccakSponge
    KeccakSpongeInitialize=MIRATH_TCITH_1A_FAST_KeccakSpongeInitialize
    KeccakSpongeAbsorb=MIRATH_TCITH_1A_FAST_KeccakSpongeAbsorb
    KeccakSpongeAbsorbLastFewBits=MIRATH_TCITH_1A_FAST_KeccakSpongeAbsorbLastFewBits
    KeccakSpongeSqueeze=MIRATH_TCITH_1A_FAST_KeccakSpongeSqueeze
        # FIPS202 functions
    SHAKE128=MIRATH_TCITH_1A_FAST_SHAKE128
    SHAKE256=MIRATH_TCITH_1A_FAST_SHAKE256
    SHA3_224=MIRATH_TCITH_1A_FAST_SHA3_224
    SHA3_256=MIRATH_TCITH_1A_FAST_SHA3_256
    SHA3_384=MIRATH_TCITH_1A_FAST_SHA3_384
    SHA3_512=MIRATH_TCITH_1A_FAST_SHA3_512
        # Fast loop optimizations
    KeccakF1600_FastLoop_Absorb=MIRATH_TCITH_1A_FAST_KeccakF1600_FastLoop_Absorb
    KeccakP1600_12rounds_FastLoop_Absorb=MIRATH_TCITH_1A_FAST_KeccakP1600_12rounds_FastLoop_Absorb
        # Disable KECCAK_IMPL_NAMESPACE to prevent double-definition
    KECCAK_IMPL_NAMESPACE=MIRATH_TCITH_1A_FAST_KECCAK_IMPL_NAMESPACE
    )

    target_include_directories(mirath_tcith_1a_fast PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast)
    target_include_directories(mirath_tcith_1a_fast PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    
    # Add the glue code as a separate object for the MIRATH_1a_fast variant
    add_library(mirath_tcith_1a_fast_glue OBJECT sig_mirath_1a_fast.c)
    target_include_directories(mirath_tcith_1a_fast_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(mirath_tcith_1a_fast_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast)
    
    set(_MIRATH_OBJS ${_MIRATH_OBJS} $<TARGET_OBJECTS:mirath_tcith_1a_fast_ref> $<TARGET_OBJECTS:mirath_tcith_1a_fast_glue>)
endif()

set(MIRATH_OBJS ${_MIRATH_OBJS} PARENT_SCOPE)