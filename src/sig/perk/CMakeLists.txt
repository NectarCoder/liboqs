# SPDX-License-Identifier: MIT

set(_PERK_OBJS "")
set(_PERK_LIBS "")

if(OQS_ENABLE_SIG_perk_ak_1_short)
	set(PERK_AK_1_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short/namespace_perk_ak_1_short.h)

	set(PERK_AK_1_SHORT_LIB_SOURCES
		perk_ak_1_short/lib/djbsort/djbsort.c
		perk_ak_1_short/lib/djbsort/sort.c
		perk_ak_1_short/lib/randombytes/rng.c
		perk_ak_1_short/lib/XKCP/KeccakHash.c
		perk_ak_1_short/lib/XKCP/KeccakHashtimes4.c
		perk_ak_1_short/lib/XKCP/KeccakP-1600-opt64.c
		perk_ak_1_short/lib/XKCP/KeccakP-1600-times4-on1.c
		perk_ak_1_short/lib/XKCP/KeccakSponge.c
		perk_ak_1_short/lib/XKCP/KeccakSpongetimes4.c
		perk_ak_1_short/lib/XKCP/SimpleFIPS202.c
	)

	set(PERK_AK_1_SHORT_SOURCES
		${PERK_AK_1_SHORT_LIB_SOURCES}
		perk_ak_1_short/crypto_memset.c
		perk_ak_1_short/ev_expand.c
		perk_ak_1_short/gf2_11_arithmetic.c
		perk_ak_1_short/gf2_12_arithmetic.c
		perk_ak_1_short/gf2_13_arithmetic.c
		perk_ak_1_short/gf2_8_arithmetic.c
		perk_ak_1_short/gf2_9_arithmetic.c
		perk_ak_1_short/gf_arithmetic.c
		perk_ak_1_short/gf_common_arithmetic.c
		perk_ak_1_short/ggm_tree.c
		perk_ak_1_short/keygen.c
		perk_ak_1_short/parsing.c
		perk_ak_1_short/permutation.c
		perk_ak_1_short/prove_pkp.c
		perk_ak_1_short/sign.c
		perk_ak_1_short/signature.c
		perk_ak_1_short/symmetric.c
		perk_ak_1_short/symmetric_times4.c
		perk_ak_1_short/universal_hash.c
		perk_ak_1_short/verbose.c
		perk_ak_1_short/verify.c
		perk_ak_1_short/verify_ev_expand.c
		perk_ak_1_short/verify_pkp.c
		perk_ak_1_short/voles.c
	)

	add_library(perk_ak_1_short_ref OBJECT ${PERK_AK_1_SHORT_SOURCES})
	target_include_directories(perk_ak_1_short_ref PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short/lib
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short/lib/djbsort
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short/lib/randombytes
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short/lib/XKCP)
	target_compile_options(perk_ak_1_short_ref PRIVATE "-include" ${PERK_AK_1_SHORT_NAMESPACE_HEADER})

	add_library(perk_ak_1_short_glue OBJECT sig_perk_ak_1_short.c)
	target_include_directories(perk_ak_1_short_glue PRIVATE
		${CMAKE_CURRENT_LIST_DIR}
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_1_short)
	target_compile_options(perk_ak_1_short_glue PRIVATE "-include" ${PERK_AK_1_SHORT_NAMESPACE_HEADER})

	set(_PERK_OBJS ${_PERK_OBJS}
		$<TARGET_OBJECTS:perk_ak_1_short_ref>
		$<TARGET_OBJECTS:perk_ak_1_short_glue>)
endif()

if(OQS_ENABLE_SIG_perk_ak_3_short)
	set(PERK_AK_3_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short/namespace_perk_ak_3_short.h)

	set(PERK_AK_3_SHORT_LIB_SOURCES
		perk_ak_3_short/lib/djbsort/djbsort.c
		perk_ak_3_short/lib/djbsort/sort.c
		perk_ak_3_short/lib/randombytes/rng.c
		perk_ak_3_short/lib/XKCP/KeccakHash.c
		perk_ak_3_short/lib/XKCP/KeccakHashtimes4.c
		perk_ak_3_short/lib/XKCP/KeccakP-1600-opt64.c
		perk_ak_3_short/lib/XKCP/KeccakP-1600-times4-on1.c
		perk_ak_3_short/lib/XKCP/KeccakSponge.c
		perk_ak_3_short/lib/XKCP/KeccakSpongetimes4.c
		perk_ak_3_short/lib/XKCP/SimpleFIPS202.c
	)

	set(PERK_AK_3_SHORT_SOURCES
		${PERK_AK_3_SHORT_LIB_SOURCES}
		perk_ak_3_short/crypto_memset.c
		perk_ak_3_short/ev_expand.c
		perk_ak_3_short/gf2_11_arithmetic.c
		perk_ak_3_short/gf2_12_arithmetic.c
		perk_ak_3_short/gf2_13_arithmetic.c
		perk_ak_3_short/gf2_8_arithmetic.c
		perk_ak_3_short/gf2_9_arithmetic.c
		perk_ak_3_short/gf_arithmetic.c
		perk_ak_3_short/gf_common_arithmetic.c
		perk_ak_3_short/ggm_tree.c
		perk_ak_3_short/keygen.c
		perk_ak_3_short/parsing.c
		perk_ak_3_short/permutation.c
		perk_ak_3_short/prove_pkp.c
		perk_ak_3_short/sign.c
		perk_ak_3_short/signature.c
		perk_ak_3_short/symmetric.c
		perk_ak_3_short/symmetric_times4.c
		perk_ak_3_short/universal_hash.c
		perk_ak_3_short/verbose.c
		perk_ak_3_short/verify.c
		perk_ak_3_short/verify_ev_expand.c
		perk_ak_3_short/verify_pkp.c
		perk_ak_3_short/voles.c
	)

	add_library(perk_ak_3_short_ref OBJECT ${PERK_AK_3_SHORT_SOURCES})
	target_include_directories(perk_ak_3_short_ref PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short/lib
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short/lib/djbsort
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short/lib/randombytes
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short/lib/XKCP)
	target_compile_options(perk_ak_3_short_ref PRIVATE "-include" ${PERK_AK_3_SHORT_NAMESPACE_HEADER})

	add_library(perk_ak_3_short_glue OBJECT sig_perk_ak_3_short.c)
	target_include_directories(perk_ak_3_short_glue PRIVATE
		${CMAKE_CURRENT_LIST_DIR}
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_3_short)
	target_compile_options(perk_ak_3_short_glue PRIVATE "-include" ${PERK_AK_3_SHORT_NAMESPACE_HEADER})

	set(_PERK_OBJS ${_PERK_OBJS}
		$<TARGET_OBJECTS:perk_ak_3_short_ref>
		$<TARGET_OBJECTS:perk_ak_3_short_glue>)
endif()

if(OQS_ENABLE_SIG_perk_ak_5_short)
	set(PERK_AK_5_SHORT_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short/namespace_perk_ak_5_short.h)

	set(PERK_AK_5_SHORT_LIB_SOURCES
		perk_ak_5_short/lib/djbsort/djbsort.c
		perk_ak_5_short/lib/djbsort/sort.c
		perk_ak_5_short/lib/randombytes/rng.c
		perk_ak_5_short/lib/XKCP/KeccakHash.c
		perk_ak_5_short/lib/XKCP/KeccakHashtimes4.c
		perk_ak_5_short/lib/XKCP/KeccakP-1600-opt64.c
		perk_ak_5_short/lib/XKCP/KeccakP-1600-times4-on1.c
		perk_ak_5_short/lib/XKCP/KeccakSponge.c
		perk_ak_5_short/lib/XKCP/KeccakSpongetimes4.c
		perk_ak_5_short/lib/XKCP/SimpleFIPS202.c
	)

	set(PERK_AK_5_SHORT_SOURCES
		${PERK_AK_5_SHORT_LIB_SOURCES}
		perk_ak_5_short/crypto_memset.c
		perk_ak_5_short/ev_expand.c
		perk_ak_5_short/gf2_11_arithmetic.c
		perk_ak_5_short/gf2_12_arithmetic.c
		perk_ak_5_short/gf2_13_arithmetic.c
		perk_ak_5_short/gf2_8_arithmetic.c
		perk_ak_5_short/gf2_9_arithmetic.c
		perk_ak_5_short/gf_arithmetic.c
		perk_ak_5_short/gf_common_arithmetic.c
		perk_ak_5_short/ggm_tree.c
		perk_ak_5_short/keygen.c
		perk_ak_5_short/parsing.c
		perk_ak_5_short/permutation.c
		perk_ak_5_short/prove_pkp.c
		perk_ak_5_short/sign.c
		perk_ak_5_short/signature.c
		perk_ak_5_short/symmetric.c
		perk_ak_5_short/symmetric_times4.c
		perk_ak_5_short/universal_hash.c
		perk_ak_5_short/verbose.c
		perk_ak_5_short/verify.c
		perk_ak_5_short/verify_ev_expand.c
		perk_ak_5_short/verify_pkp.c
		perk_ak_5_short/voles.c
	)

	add_library(perk_ak_5_short_ref OBJECT ${PERK_AK_5_SHORT_SOURCES})
	target_include_directories(perk_ak_5_short_ref PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short/lib
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short/lib/djbsort
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short/lib/randombytes
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short/lib/XKCP)
	target_compile_options(perk_ak_5_short_ref PRIVATE "-include" ${PERK_AK_5_SHORT_NAMESPACE_HEADER})

	add_library(perk_ak_5_short_glue OBJECT sig_perk_ak_5_short.c)
	target_include_directories(perk_ak_5_short_glue PRIVATE
		${CMAKE_CURRENT_LIST_DIR}
		${CMAKE_CURRENT_LIST_DIR}/perk_ak_5_short)
	target_compile_options(perk_ak_5_short_glue PRIVATE "-include" ${PERK_AK_5_SHORT_NAMESPACE_HEADER})

	set(_PERK_OBJS ${_PERK_OBJS}
		$<TARGET_OBJECTS:perk_ak_5_short_ref>
		$<TARGET_OBJECTS:perk_ak_5_short_glue>)
endif()

list(REMOVE_DUPLICATES _PERK_LIBS)

set(PERK_OBJS ${_PERK_OBJS} PARENT_SCOPE)
set(PERK_LIBS ${_PERK_LIBS} PARENT_SCOPE)