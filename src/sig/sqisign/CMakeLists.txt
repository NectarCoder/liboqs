# SPDX-License-Identifier: MIT

set(_SQISIGN_OBJS "")
set(_SQISIGN_LIBS "")

set(SQISIGN_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})

set(SQISIGN_CORE_SOURCES
        ${SQISIGN_BASE_DIR}/sqisign.c
        ${SQISIGN_BASE_DIR}/mini-gmp/mini-gmp.c
        ${SQISIGN_BASE_DIR}/mini-gmp/mini-gmp-extra.c
)

file(GLOB SQISIGN_COMMON_GENERIC_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/common/generic/*.c)
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_COMMON_GENERIC_SOURCES})

file(GLOB SQISIGN_COMMON_REF_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/common/ref/*.c)
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_COMMON_REF_SOURCES})

file(GLOB_RECURSE SQISIGN_MP_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/mp/ref/generic/*.c)
list(FILTER SQISIGN_MP_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_MP_SOURCES})

file(GLOB_RECURSE SQISIGN_QUATERNION_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/quaternion/ref/generic/*.c)
list(FILTER SQISIGN_QUATERNION_SOURCES EXCLUDE REGEX "/test/")
list(FILTER SQISIGN_QUATERNION_SOURCES EXCLUDE REGEX "bench")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_QUATERNION_SOURCES})

file(GLOB_RECURSE SQISIGN_ID2ISO_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/id2iso/ref/lvlx/*.c)
list(FILTER SQISIGN_ID2ISO_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_ID2ISO_SOURCES})

file(GLOB_RECURSE SQISIGN_HD_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/hd/ref/lvlx/*.c)
list(FILTER SQISIGN_HD_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_HD_SOURCES})

file(GLOB_RECURSE SQISIGN_EC_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/ec/ref/lvlx/*.c)
list(FILTER SQISIGN_EC_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_EC_SOURCES})

file(GLOB SQISIGN_GF_LVLX_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/gf/ref/lvlx/*.c)
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_GF_LVLX_SOURCES})

file(GLOB_RECURSE SQISIGN_SIGNATURE_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/signature/ref/lvlx/*.c)
list(FILTER SQISIGN_SIGNATURE_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_SIGNATURE_SOURCES})

file(GLOB_RECURSE SQISIGN_VERIFICATION_SOURCES CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/verification/ref/lvlx/*.c)
list(FILTER SQISIGN_VERIFICATION_SOURCES EXCLUDE REGEX "/test/")
list(APPEND SQISIGN_CORE_SOURCES ${SQISIGN_VERIFICATION_SOURCES})

list(REMOVE_DUPLICATES SQISIGN_CORE_SOURCES)

function(sqisign_add_variant suffix variant_dir namespace_header glue_source gf_specific)
        set(local_sources ${SQISIGN_CORE_SOURCES})

        file(GLOB VARIANT_PRECOMP CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/precomp/ref/${variant_dir}/*.c)
        list(FILTER VARIANT_PRECOMP EXCLUDE REGEX "/test/")
        list(APPEND local_sources ${VARIANT_PRECOMP})

        file(GLOB VARIANT_NISTAPI CONFIGURE_DEPENDS ${SQISIGN_BASE_DIR}/nistapi/${variant_dir}/*.c)
        list(APPEND local_sources ${VARIANT_NISTAPI})

        list(APPEND local_sources ${gf_specific})
        list(REMOVE_DUPLICATES local_sources)

        add_library(sqisign_${suffix}_ref OBJECT ${local_sources})
        target_include_directories(sqisign_${suffix}_ref PRIVATE
                ${SQISIGN_BASE_DIR}
                ${SQISIGN_BASE_DIR}/include
                ${SQISIGN_BASE_DIR}/common/generic/include
                ${SQISIGN_BASE_DIR}/common/ref/include
                ${SQISIGN_BASE_DIR}/mini-gmp
                ${SQISIGN_BASE_DIR}/mp/ref/generic/include
                ${SQISIGN_BASE_DIR}/quaternion/ref/generic/include
                ${SQISIGN_BASE_DIR}/quaternion/ref/generic/internal_quaternion_headers
                ${SQISIGN_BASE_DIR}/id2iso/ref/include
                ${SQISIGN_BASE_DIR}/hd/ref/include
                ${SQISIGN_BASE_DIR}/ec/ref/include
                ${SQISIGN_BASE_DIR}/gf/ref/include
                ${SQISIGN_BASE_DIR}/signature/ref/include
                ${SQISIGN_BASE_DIR}/verification/ref/include
                ${SQISIGN_BASE_DIR}/precomp/ref/${variant_dir}/include
                ${SQISIGN_BASE_DIR}/nistapi/${variant_dir})
        target_compile_options(sqisign_${suffix}_ref PRIVATE "-include" ${namespace_header})
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                target_compile_definitions(sqisign_${suffix}_ref PRIVATE ONLY_REF_IMPLEMENTATION GMP_LIMB_BITS=64 RANDOMBYTES_SYSTEM)
        else()
                target_compile_definitions(sqisign_${suffix}_ref PRIVATE ONLY_REF_IMPLEMENTATION GMP_LIMB_BITS=32 RANDOMBYTES_SYSTEM)
        endif()

        add_library(sqisign_${suffix}_glue OBJECT ${glue_source})
        target_include_directories(sqisign_${suffix}_glue PRIVATE
                ${SQISIGN_BASE_DIR}
                ${SQISIGN_BASE_DIR}/include)
        target_compile_options(sqisign_${suffix}_glue PRIVATE "-include" ${namespace_header})

        set(_SQISIGN_OBJS ${_SQISIGN_OBJS}
                $<TARGET_OBJECTS:sqisign_${suffix}_ref>
                $<TARGET_OBJECTS:sqisign_${suffix}_glue>
                PARENT_SCOPE)
endfunction()

if(OQS_ENABLE_SIG_sqisign_353)
        sqisign_add_variant("353" "lvl1" ${SQISIGN_BASE_DIR}/namespace_sqisign_353.h ${SQISIGN_BASE_DIR}/sig_sqisign_353.c ${SQISIGN_BASE_DIR}/gf/ref/lvl1/fp_p5248_64.c)
endif()

if(OQS_ENABLE_SIG_sqisign_529)
        sqisign_add_variant("529" "lvl3" ${SQISIGN_BASE_DIR}/namespace_sqisign_529.h ${SQISIGN_BASE_DIR}/sig_sqisign_529.c ${SQISIGN_BASE_DIR}/gf/ref/lvl3/fp_p65376_64.c)
endif()

if(OQS_ENABLE_SIG_sqisign_701)
        sqisign_add_variant("701" "lvl5" ${SQISIGN_BASE_DIR}/namespace_sqisign_701.h ${SQISIGN_BASE_DIR}/sig_sqisign_701.c ${SQISIGN_BASE_DIR}/gf/ref/lvl5/fp_p27500_64.c)
endif()

list(REMOVE_DUPLICATES _SQISIGN_LIBS)

set(SQISIGN_OBJS ${_SQISIGN_OBJS} PARENT_SCOPE)
set(SQISIGN_LIBS ${_SQISIGN_LIBS} PARENT_SCOPE)
