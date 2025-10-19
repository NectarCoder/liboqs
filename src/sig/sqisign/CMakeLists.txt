# SPDX-License-Identifier: MIT

set(_SQISIGN_OBJS "")

# Common compile definitions for all SQIsign variants
add_compile_definitions(MINI_GMP)
add_compile_definitions(ENABLE_SIGN)
add_compile_definitions(SQISIGN_BUILD_TYPE_REF)
add_compile_definitions(SQISIGN_GF_IMPL_REF)
add_compile_definitions(RANDOMBYTES_C)

# Determine radix (32 or 64 bit) based on architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(SQISIGN_RADIX 64)
    add_compile_definitions(RADIX_64)
    add_compile_definitions(GMP_LIMB_BITS=64)
else()
    set(SQISIGN_RADIX 32)
    add_compile_definitions(RADIX_32)
    add_compile_definitions(GMP_LIMB_BITS=32)
endif()

# ============================================================================
# Mini-GMP Library (required for quaternion algebra)
# ============================================================================
set(MINI_GMP_SOURCES
    mini-gmp/mini-gmp.c
    mini-gmp/mini-gmp-extra.c
)

add_library(sqisign_mini_gmp OBJECT ${MINI_GMP_SOURCES})
target_include_directories(sqisign_mini_gmp PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
    ${CMAKE_CURRENT_LIST_DIR}/common/generic/include)
# Suppress warnings from mini-gmp (external code)
target_compile_options(sqisign_mini_gmp PRIVATE -w)

# ============================================================================
# Common Module (FIPS202, memory, tools, randombytes)
# ============================================================================
set(SQISIGN_COMMON_SOURCES
    common/generic/fips202.c
    common/generic/mem.c
    common/generic/tools.c
    common/generic/randombytes_system.c
    common/ref/aes_c.c
    common/ref/randombytes_ctrdrbg.c
)

add_library(sqisign_common OBJECT ${SQISIGN_COMMON_SOURCES})
target_include_directories(sqisign_common PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
    ${CMAKE_CURRENT_LIST_DIR}/common/ref/include
    ${CMAKE_CURRENT_LIST_DIR}/include)

# ============================================================================
# MP Module (multi-precision arithmetic wrapper)
# ============================================================================
set(SQISIGN_MP_SOURCES
    mp/ref/generic/mp.c
)

add_library(sqisign_mp OBJECT ${SQISIGN_MP_SOURCES})
target_include_directories(sqisign_mp PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
    ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include)

# ============================================================================
# Quaternion Module (quaternion algebra operations, uses mini-gmp)
# ============================================================================
set(SQISIGN_QUATERNION_SOURCES
    quaternion/ref/generic/intbig.c
    quaternion/ref/generic/algebra.c
    quaternion/ref/generic/ideal.c
    quaternion/ref/generic/dim4.c
    quaternion/ref/generic/dim2.c
    quaternion/ref/generic/integers.c
    quaternion/ref/generic/lattice.c
    quaternion/ref/generic/lat_ball.c
    quaternion/ref/generic/finit.c
    quaternion/ref/generic/printer.c
    quaternion/ref/generic/lll/rationals.c
    quaternion/ref/generic/lll/l2.c
    quaternion/ref/generic/lll/lll_verification.c
    quaternion/ref/generic/lll/lll_applications.c
    quaternion/ref/generic/normeq.c
    quaternion/ref/generic/hnf/ibz_division.c
    quaternion/ref/generic/hnf/hnf_internal.c
    quaternion/ref/generic/hnf/hnf.c
)

add_library(sqisign_quaternion OBJECT ${SQISIGN_QUATERNION_SOURCES})
target_include_directories(sqisign_quaternion PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
    ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
    ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/internal_quaternion_headers
    ${CMAKE_CURRENT_LIST_DIR}/mini-gmp)
target_compile_options(sqisign_quaternion PRIVATE -lm)

# ============================================================================
# HD Module (Hadamard splitting)
# ============================================================================
set(SQISIGN_HD_SOURCES_GENERIC
    hd/ref/lvlx/hd.c
    hd/ref/lvlx/theta_structure.c
    hd/ref/lvlx/theta_isogenies.c
)

# ============================================================================
# Variant-specific modules (lvl1 = sqisign-353, lvl3 = sqisign-529, lvl5 = sqisign-701)
# ============================================================================

# SQIsign-353 (Level 1 - NIST Security Level 1)
if(OQS_ENABLE_SIG_sqisign_353)
    # GF module for lvl1
    set(SQISIGN_GF_LVL1_SOURCES
        gf/ref/lvlx/fp.c
        gf/ref/lvlx/fp2.c
        gf/ref/lvl1/fp_p5248_${SQISIGN_RADIX}.c
    )
    add_library(sqisign_gf_lvl1 OBJECT ${SQISIGN_GF_LVL1_SOURCES})
    target_include_directories(sqisign_gf_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include)
    target_compile_definitions(sqisign_gf_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # Precomp module for lvl1
    set(SQISIGN_PRECOMP_LVL1_SOURCES
        precomp/ref/lvl1/e0_basis.c
        precomp/ref/lvl1/ec_params.c
        precomp/ref/lvl1/endomorphism_action.c
        precomp/ref/lvl1/hd_splitting_transforms.c
        precomp/ref/lvl1/quaternion_data.c
        precomp/ref/lvl1/torsion_constants.c
    )
    add_library(sqisign_precomp_lvl1 OBJECT ${SQISIGN_PRECOMP_LVL1_SOURCES})
    target_include_directories(sqisign_precomp_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp)
    target_compile_definitions(sqisign_precomp_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # EC module for lvl1
    set(SQISIGN_EC_LVL1_SOURCES
        ${SQISIGN_HD_SOURCES_GENERIC}
        ec/ref/lvlx/ec.c
        ec/ref/lvlx/ec_jac.c
        ec/ref/lvlx/xisog.c
        ec/ref/lvlx/xeval.c
        ec/ref/lvlx/isog_chains.c
        ec/ref/lvlx/basis.c
        ec/ref/lvlx/biextension.c
    )
    add_library(sqisign_ec_lvl1 OBJECT ${SQISIGN_EC_LVL1_SOURCES})
    target_include_directories(sqisign_ec_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include)
    target_compile_definitions(sqisign_ec_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # ID2ISO module for lvl1
    set(SQISIGN_ID2ISO_LVL1_SOURCES
        id2iso/ref/lvlx/dim2id2iso.c
        id2iso/ref/lvlx/id2iso.c
    )
    add_library(sqisign_id2iso_lvl1 OBJECT ${SQISIGN_ID2ISO_LVL1_SOURCES})
    target_include_directories(sqisign_id2iso_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include)
    target_compile_definitions(sqisign_id2iso_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # Verification module for lvl1
    set(SQISIGN_VERIFICATION_LVL1_SOURCES
        verification/ref/lvlx/common.c
        verification/ref/lvlx/encode_verification.c
        verification/ref/lvlx/verify.c
    )
    add_library(sqisign_verification_lvl1 OBJECT ${SQISIGN_VERIFICATION_LVL1_SOURCES})
    target_include_directories(sqisign_verification_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include)
    target_compile_definitions(sqisign_verification_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # Signature module for lvl1
    set(SQISIGN_SIGNATURE_LVL1_SOURCES
        signature/ref/lvlx/encode_signature.c
        signature/ref/lvlx/keygen.c
        signature/ref/lvlx/sign.c
    )
    add_library(sqisign_signature_lvl1 OBJECT ${SQISIGN_SIGNATURE_LVL1_SOURCES})
    target_include_directories(sqisign_signature_lvl1 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl1/include)
    target_compile_definitions(sqisign_signature_lvl1 PRIVATE SQISIGN_VARIANT=lvl1)

    # Main sqisign library for lvl1
    set(SQISIGN_353_SOURCES
        sqisign.c
    )
    add_library(sqisign_353_core OBJECT ${SQISIGN_353_SOURCES})
    target_include_directories(sqisign_353_core PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl1/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl1/include)
    target_compile_definitions(sqisign_353_core PRIVATE SQISIGN_VARIANT=lvl1)

    # NIST API wrapper for lvl1
    set(SQISIGN_353_NISTAPI_SOURCES
        nistapi/lvl1/api.c
    )
    add_library(sqisign_353_nistapi OBJECT ${SQISIGN_353_NISTAPI_SOURCES})
    target_include_directories(sqisign_353_nistapi PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl1)
    target_compile_definitions(sqisign_353_nistapi PRIVATE SQISIGN_VARIANT=lvl1 DISABLE_NAMESPACING)

    # OQS glue code for sqisign-353
    add_library(sqisign_353_glue OBJECT sig_sqisign_353.c)
    target_include_directories(sqisign_353_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl1
        ${CMAKE_CURRENT_LIST_DIR}/include)

    # Collect all objects for sqisign-353
    set(_SQISIGN_OBJS ${_SQISIGN_OBJS}
        $<TARGET_OBJECTS:sqisign_mini_gmp>
        $<TARGET_OBJECTS:sqisign_common>
        $<TARGET_OBJECTS:sqisign_mp>
        $<TARGET_OBJECTS:sqisign_quaternion>
        $<TARGET_OBJECTS:sqisign_gf_lvl1>
        $<TARGET_OBJECTS:sqisign_precomp_lvl1>
        $<TARGET_OBJECTS:sqisign_ec_lvl1>
        $<TARGET_OBJECTS:sqisign_id2iso_lvl1>
        $<TARGET_OBJECTS:sqisign_verification_lvl1>
        $<TARGET_OBJECTS:sqisign_signature_lvl1>
        $<TARGET_OBJECTS:sqisign_353_core>
        $<TARGET_OBJECTS:sqisign_353_glue>)
endif()

# SQIsign-529 (Level 3 - NIST Security Level 3)
if(OQS_ENABLE_SIG_sqisign_529)
    # GF module for lvl3
    set(SQISIGN_GF_LVL3_SOURCES
        gf/ref/lvlx/fp.c
        gf/ref/lvlx/fp2.c
        gf/ref/lvl3/fp_p65376_${SQISIGN_RADIX}.c
    )
    add_library(sqisign_gf_lvl3 OBJECT ${SQISIGN_GF_LVL3_SOURCES})
    target_include_directories(sqisign_gf_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include)
    target_compile_definitions(sqisign_gf_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # Precomp module for lvl3
    set(SQISIGN_PRECOMP_LVL3_SOURCES
        precomp/ref/lvl3/e0_basis.c
        precomp/ref/lvl3/ec_params.c
        precomp/ref/lvl3/endomorphism_action.c
        precomp/ref/lvl3/hd_splitting_transforms.c
        precomp/ref/lvl3/quaternion_data.c
        precomp/ref/lvl3/torsion_constants.c
    )
    add_library(sqisign_precomp_lvl3 OBJECT ${SQISIGN_PRECOMP_LVL3_SOURCES})
    target_include_directories(sqisign_precomp_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp)
    target_compile_definitions(sqisign_precomp_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # EC module for lvl3
    set(SQISIGN_EC_LVL3_SOURCES
        ${SQISIGN_HD_SOURCES_GENERIC}
        ec/ref/lvlx/ec.c
        ec/ref/lvlx/ec_jac.c
        ec/ref/lvlx/xisog.c
        ec/ref/lvlx/xeval.c
        ec/ref/lvlx/isog_chains.c
        ec/ref/lvlx/basis.c
        ec/ref/lvlx/biextension.c
    )
    add_library(sqisign_ec_lvl3 OBJECT ${SQISIGN_EC_LVL3_SOURCES})
    target_include_directories(sqisign_ec_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include)
    target_compile_definitions(sqisign_ec_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # ID2ISO module for lvl3
    set(SQISIGN_ID2ISO_LVL3_SOURCES
        id2iso/ref/lvlx/dim2id2iso.c
        id2iso/ref/lvlx/id2iso.c
    )
    add_library(sqisign_id2iso_lvl3 OBJECT ${SQISIGN_ID2ISO_LVL3_SOURCES})
    target_include_directories(sqisign_id2iso_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include)
    target_compile_definitions(sqisign_id2iso_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # Verification module for lvl3
    set(SQISIGN_VERIFICATION_LVL3_SOURCES
        verification/ref/lvlx/common.c
        verification/ref/lvlx/encode_verification.c
        verification/ref/lvlx/verify.c
    )
    add_library(sqisign_verification_lvl3 OBJECT ${SQISIGN_VERIFICATION_LVL3_SOURCES})
    target_include_directories(sqisign_verification_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include)
    target_compile_definitions(sqisign_verification_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # Signature module for lvl3
    set(SQISIGN_SIGNATURE_LVL3_SOURCES
        signature/ref/lvlx/encode_signature.c
        signature/ref/lvlx/keygen.c
        signature/ref/lvlx/sign.c
    )
    add_library(sqisign_signature_lvl3 OBJECT ${SQISIGN_SIGNATURE_LVL3_SOURCES})
    target_include_directories(sqisign_signature_lvl3 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl3/include)
    target_compile_definitions(sqisign_signature_lvl3 PRIVATE SQISIGN_VARIANT=lvl3)

    # Main sqisign library for lvl3
    set(SQISIGN_529_SOURCES
        sqisign.c
    )
    add_library(sqisign_529_core OBJECT ${SQISIGN_529_SOURCES})
    target_include_directories(sqisign_529_core PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl3/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl3/include)
    target_compile_definitions(sqisign_529_core PRIVATE SQISIGN_VARIANT=lvl3)

    # NIST API wrapper for lvl3
    set(SQISIGN_529_NISTAPI_SOURCES
        nistapi/lvl3/api.c
    )
    add_library(sqisign_529_nistapi OBJECT ${SQISIGN_529_NISTAPI_SOURCES})
    target_include_directories(sqisign_529_nistapi PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl3)
    target_compile_definitions(sqisign_529_nistapi PRIVATE SQISIGN_VARIANT=lvl3 DISABLE_NAMESPACING)

    # OQS glue code for sqisign-529
    add_library(sqisign_529_glue OBJECT sig_sqisign_529.c)
    target_include_directories(sqisign_529_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl3
        ${CMAKE_CURRENT_LIST_DIR}/include)

    # Collect all objects for sqisign-529
    set(_SQISIGN_OBJS ${_SQISIGN_OBJS}
        $<TARGET_OBJECTS:sqisign_mini_gmp>
        $<TARGET_OBJECTS:sqisign_common>
        $<TARGET_OBJECTS:sqisign_mp>
        $<TARGET_OBJECTS:sqisign_quaternion>
        $<TARGET_OBJECTS:sqisign_gf_lvl3>
        $<TARGET_OBJECTS:sqisign_precomp_lvl3>
        $<TARGET_OBJECTS:sqisign_ec_lvl3>
        $<TARGET_OBJECTS:sqisign_id2iso_lvl3>
        $<TARGET_OBJECTS:sqisign_verification_lvl3>
        $<TARGET_OBJECTS:sqisign_signature_lvl3>
        $<TARGET_OBJECTS:sqisign_529_core>
        $<TARGET_OBJECTS:sqisign_529_nistapi>
        $<TARGET_OBJECTS:sqisign_529_glue>)
endif()

# SQIsign-701 (Level 5 - NIST Security Level 5)
if(OQS_ENABLE_SIG_sqisign_701)
    # GF module for lvl5
    set(SQISIGN_GF_LVL5_SOURCES
        gf/ref/lvlx/fp.c
        gf/ref/lvlx/fp2.c
        gf/ref/lvl5/fp_p27500_${SQISIGN_RADIX}.c
    )
    add_library(sqisign_gf_lvl5 OBJECT ${SQISIGN_GF_LVL5_SOURCES})
    target_include_directories(sqisign_gf_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include)
    target_compile_definitions(sqisign_gf_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # Precomp module for lvl5
    set(SQISIGN_PRECOMP_LVL5_SOURCES
        precomp/ref/lvl5/e0_basis.c
        precomp/ref/lvl5/ec_params.c
        precomp/ref/lvl5/endomorphism_action.c
        precomp/ref/lvl5/hd_splitting_transforms.c
        precomp/ref/lvl5/quaternion_data.c
        precomp/ref/lvl5/torsion_constants.c
    )
    add_library(sqisign_precomp_lvl5 OBJECT ${SQISIGN_PRECOMP_LVL5_SOURCES})
    target_include_directories(sqisign_precomp_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp)
    target_compile_definitions(sqisign_precomp_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # EC module for lvl5
    set(SQISIGN_EC_LVL5_SOURCES
        ${SQISIGN_HD_SOURCES_GENERIC}
        ec/ref/lvlx/ec.c
        ec/ref/lvlx/ec_jac.c
        ec/ref/lvlx/xisog.c
        ec/ref/lvlx/xeval.c
        ec/ref/lvlx/isog_chains.c
        ec/ref/lvlx/basis.c
        ec/ref/lvlx/biextension.c
    )
    add_library(sqisign_ec_lvl5 OBJECT ${SQISIGN_EC_LVL5_SOURCES})
    target_include_directories(sqisign_ec_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include)
    target_compile_definitions(sqisign_ec_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # ID2ISO module for lvl5
    set(SQISIGN_ID2ISO_LVL5_SOURCES
        id2iso/ref/lvlx/dim2id2iso.c
        id2iso/ref/lvlx/id2iso.c
    )
    add_library(sqisign_id2iso_lvl5 OBJECT ${SQISIGN_ID2ISO_LVL5_SOURCES})
    target_include_directories(sqisign_id2iso_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include)
    target_compile_definitions(sqisign_id2iso_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # Verification module for lvl5
    set(SQISIGN_VERIFICATION_LVL5_SOURCES
        verification/ref/lvlx/common.c
        verification/ref/lvlx/encode_verification.c
        verification/ref/lvlx/verify.c
    )
    add_library(sqisign_verification_lvl5 OBJECT ${SQISIGN_VERIFICATION_LVL5_SOURCES})
    target_include_directories(sqisign_verification_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include)
    target_compile_definitions(sqisign_verification_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # Signature module for lvl5
    set(SQISIGN_SIGNATURE_LVL5_SOURCES
        signature/ref/lvlx/encode_signature.c
        signature/ref/lvlx/keygen.c
        signature/ref/lvlx/sign.c
    )
    add_library(sqisign_signature_lvl5 OBJECT ${SQISIGN_SIGNATURE_LVL5_SOURCES})
    target_include_directories(sqisign_signature_lvl5 PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl5/include)
    target_compile_definitions(sqisign_signature_lvl5 PRIVATE SQISIGN_VARIANT=lvl5)

    # Main sqisign library for lvl5
    set(SQISIGN_701_SOURCES
        sqisign.c
    )
    add_library(sqisign_701_core OBJECT ${SQISIGN_701_SOURCES})
    target_include_directories(sqisign_701_core PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mini-gmp
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/common/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/signature/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/verification/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/id2iso/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/quaternion/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/precomp/ref/lvl5/include
        ${CMAKE_CURRENT_LIST_DIR}/mp/ref/generic/include
        ${CMAKE_CURRENT_LIST_DIR}/ec/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/hd/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/include
        ${CMAKE_CURRENT_LIST_DIR}/gf/ref/lvl5/include)
    target_compile_definitions(sqisign_701_core PRIVATE SQISIGN_VARIANT=lvl5)

    # NIST API wrapper for lvl5
    set(SQISIGN_701_NISTAPI_SOURCES
        nistapi/lvl5/api.c
    )
    add_library(sqisign_701_nistapi OBJECT ${SQISIGN_701_NISTAPI_SOURCES})
    target_include_directories(sqisign_701_nistapi PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl5)
    target_compile_definitions(sqisign_701_nistapi PRIVATE SQISIGN_VARIANT=lvl5 DISABLE_NAMESPACING)

    # OQS glue code for sqisign-701
    add_library(sqisign_701_glue OBJECT sig_sqisign_701.c)
    target_include_directories(sqisign_701_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/nistapi/lvl5
        ${CMAKE_CURRENT_LIST_DIR}/include)

    # Collect all objects for sqisign-701
    set(_SQISIGN_OBJS ${_SQISIGN_OBJS}
        $<TARGET_OBJECTS:sqisign_mini_gmp>
        $<TARGET_OBJECTS:sqisign_common>
        $<TARGET_OBJECTS:sqisign_mp>
        $<TARGET_OBJECTS:sqisign_quaternion>
        $<TARGET_OBJECTS:sqisign_gf_lvl5>
        $<TARGET_OBJECTS:sqisign_precomp_lvl5>
        $<TARGET_OBJECTS:sqisign_ec_lvl5>
        $<TARGET_OBJECTS:sqisign_id2iso_lvl5>
        $<TARGET_OBJECTS:sqisign_verification_lvl5>
        $<TARGET_OBJECTS:sqisign_signature_lvl5>
        $<TARGET_OBJECTS:sqisign_701_core>
        $<TARGET_OBJECTS:sqisign_701_nistapi>
        $<TARGET_OBJECTS:sqisign_701_glue>)
endif()

# Export all SQIsign objects to parent scope
set(SQISIGN_OBJS ${_SQISIGN_OBJS} PARENT_SCOPE)
