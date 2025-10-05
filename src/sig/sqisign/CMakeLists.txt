# SPDX-License-Identifier: Apache-2.0

/*
 * CMakeLists.txt for the SQISign reference implementation
*/

#example format below(CMakeLists.txt) needs extensive modifications to fit into liboqs build system

set(_SQISIGN_OBJS "")

if(OQS_ENABLE_SIG_uov_ov_V_pkc_skc_avx2)
    add_library(uov_ov_V_pkc_skc_avx2 OBJECT pqov_ov_V_pkc_skc_avx2/blas_matrix.c pqov_ov_V_pkc_skc_avx2/blas_matrix_avx2.c pqov_ov_V_pkc_skc_avx2/gf16_tabs.c pqov_ov_V_pkc_skc_avx2/gf256_tabs.c pqov_ov_V_pkc_skc_avx2/ov.c pqov_ov_V_pkc_skc_avx2/ov_keypair.c pqov_ov_V_pkc_skc_avx2/ov_keypair_computation.c pqov_ov_V_pkc_skc_avx2/ov_publicmap.c pqov_ov_V_pkc_skc_avx2/parallel_matrix_op.c pqov_ov_V_pkc_skc_avx2/sign.c pqov_ov_V_pkc_skc_avx2/utils_hash.c pqov_ov_V_pkc_skc_avx2/utils_prng.c pqov_ov_V_pkc_skc_avx2/utils_randombytes.c)
    target_include_directories(uov_ov_V_pkc_skc_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/pqov_ov_V_pkc_skc_avx2)
    target_include_directories(uov_ov_V_pkc_skc_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(uov_ov_V_pkc_skc_avx2 PRIVATE -mavx2)
    target_compile_options(uov_ov_V_pkc_skc_avx2 PUBLIC -D_OV256_244_96 -D_OV_PKC_SKC -D_UTILS_OQS_ -D_BLAS_AVX2_ -D_MUL_WITH_MULTAB_)
    set(_UOV_OBJS ${_UOV_OBJS} $<TARGET_OBJECTS:uov_ov_V_pkc_skc_avx2>)
endif()

set(SQISIGN_OBJS ${_SQISIGN_OBJS} PARENT_SCOPE)