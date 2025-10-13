# SPDX-License-Identifier: MIT

set(_MQOM_OBJS "")
set(_MQOM_LIBS "")

if(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r3)
    set(MQOM2_CAT1_GF2_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/namespace_mqom2_cat1_gf2_short_r3.h)

    set(MQOM2_CAT1_GF2_SHORT_R3_SOURCES
        mqom2_cat1_gf2_short_r3/expand_mq.c
        mqom2_cat1_gf2_short_r3/ggm_tree.c
        mqom2_cat1_gf2_short_r3/keygen.c
        mqom2_cat1_gf2_short_r3/prg.c
        mqom2_cat1_gf2_short_r3/sign.c
        mqom2_cat1_gf2_short_r3/xof.c
        mqom2_cat1_gf2_short_r3/lib/blc/blc_default.c
        mqom2_cat1_gf2_short_r3/lib/blc/blc_memopt.c
        mqom2_cat1_gf2_short_r3/lib/piop/piop_default.c
        mqom2_cat1_gf2_short_r3/lib/piop/piop_memopt.c
        mqom2_cat1_gf2_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat1_gf2_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf2_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf2_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf2_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf2_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf2_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf2_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf2_short_r3_ref OBJECT ${MQOM2_CAT1_GF2_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat1_gf2_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf2_short_r3_ref PRIVATE "-include" ${MQOM2_CAT1_GF2_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf2_short_r3_glue OBJECT sig_mqom2_cat1_gf2_short_r3.c)
    target_include_directories(mqom2_cat1_gf2_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf2_short_r3_glue PRIVATE "-include" ${MQOM2_CAT1_GF2_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf2_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf2_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r5)
    set(MQOM2_CAT1_GF2_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/namespace_mqom2_cat1_gf2_short_r5.h)

    set(MQOM2_CAT1_GF2_SHORT_R5_SOURCES
        mqom2_cat1_gf2_short_r5/expand_mq.c
        mqom2_cat1_gf2_short_r5/ggm_tree.c
        mqom2_cat1_gf2_short_r5/keygen.c
        mqom2_cat1_gf2_short_r5/prg.c
        mqom2_cat1_gf2_short_r5/sign.c
        mqom2_cat1_gf2_short_r5/xof.c
        mqom2_cat1_gf2_short_r5/lib/blc/blc_default.c
        mqom2_cat1_gf2_short_r5/lib/blc/blc_memopt.c
        mqom2_cat1_gf2_short_r5/lib/piop/piop_default.c
        mqom2_cat1_gf2_short_r5/lib/piop/piop_memopt.c
        mqom2_cat1_gf2_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat1_gf2_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf2_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf2_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf2_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf2_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf2_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf2_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf2_short_r5_ref OBJECT ${MQOM2_CAT1_GF2_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat1_gf2_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf2_short_r5_ref PRIVATE "-include" ${MQOM2_CAT1_GF2_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf2_short_r5_glue OBJECT sig_mqom2_cat1_gf2_short_r5.c)
    target_include_directories(mqom2_cat1_gf2_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf2_short_r5_glue PRIVATE "-include" ${MQOM2_CAT1_GF2_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf2_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf2_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat1_gf16_short_r3)
    set(MQOM2_CAT1_GF16_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/namespace_mqom2_cat1_gf16_short_r3.h)

    set(MQOM2_CAT1_GF16_SHORT_R3_SOURCES
        mqom2_cat1_gf16_short_r3/expand_mq.c
        mqom2_cat1_gf16_short_r3/ggm_tree.c
        mqom2_cat1_gf16_short_r3/keygen.c
        mqom2_cat1_gf16_short_r3/prg.c
        mqom2_cat1_gf16_short_r3/sign.c
        mqom2_cat1_gf16_short_r3/xof.c
        mqom2_cat1_gf16_short_r3/lib/blc/blc_default.c
        mqom2_cat1_gf16_short_r3/lib/blc/blc_memopt.c
        mqom2_cat1_gf16_short_r3/lib/piop/piop_default.c
        mqom2_cat1_gf16_short_r3/lib/piop/piop_memopt.c
        mqom2_cat1_gf16_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat1_gf16_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf16_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf16_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf16_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf16_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf16_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf16_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf16_short_r3_ref OBJECT ${MQOM2_CAT1_GF16_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat1_gf16_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf16_short_r3_ref PRIVATE "-include" ${MQOM2_CAT1_GF16_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf16_short_r3_glue OBJECT sig_mqom2_cat1_gf16_short_r3.c)
    target_include_directories(mqom2_cat1_gf16_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf16_short_r3_glue PRIVATE "-include" ${MQOM2_CAT1_GF16_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf16_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf16_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat1_gf16_short_r5)
    set(MQOM2_CAT1_GF16_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/namespace_mqom2_cat1_gf16_short_r5.h)

    set(MQOM2_CAT1_GF16_SHORT_R5_SOURCES
        mqom2_cat1_gf16_short_r5/expand_mq.c
        mqom2_cat1_gf16_short_r5/ggm_tree.c
        mqom2_cat1_gf16_short_r5/keygen.c
        mqom2_cat1_gf16_short_r5/prg.c
        mqom2_cat1_gf16_short_r5/sign.c
        mqom2_cat1_gf16_short_r5/xof.c
        mqom2_cat1_gf16_short_r5/lib/blc/blc_default.c
        mqom2_cat1_gf16_short_r5/lib/blc/blc_memopt.c
        mqom2_cat1_gf16_short_r5/lib/piop/piop_default.c
        mqom2_cat1_gf16_short_r5/lib/piop/piop_memopt.c
        mqom2_cat1_gf16_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat1_gf16_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf16_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf16_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf16_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf16_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf16_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf16_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf16_short_r5_ref OBJECT ${MQOM2_CAT1_GF16_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat1_gf16_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf16_short_r5_ref PRIVATE "-include" ${MQOM2_CAT1_GF16_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf16_short_r5_glue OBJECT sig_mqom2_cat1_gf16_short_r5.c)
    target_include_directories(mqom2_cat1_gf16_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf16_short_r5_glue PRIVATE "-include" ${MQOM2_CAT1_GF16_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf16_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf16_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat1_gf256_short_r3)
    set(MQOM2_CAT1_GF256_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/namespace_mqom2_cat1_gf256_short_r3.h)

    set(MQOM2_CAT1_GF256_SHORT_R3_SOURCES
        mqom2_cat1_gf256_short_r3/expand_mq.c
        mqom2_cat1_gf256_short_r3/ggm_tree.c
        mqom2_cat1_gf256_short_r3/keygen.c
        mqom2_cat1_gf256_short_r3/prg.c
        mqom2_cat1_gf256_short_r3/sign.c
        mqom2_cat1_gf256_short_r3/xof.c
        mqom2_cat1_gf256_short_r3/lib/blc/blc_default.c
        mqom2_cat1_gf256_short_r3/lib/blc/blc_memopt.c
        mqom2_cat1_gf256_short_r3/lib/piop/piop_default.c
        mqom2_cat1_gf256_short_r3/lib/piop/piop_memopt.c
        mqom2_cat1_gf256_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat1_gf256_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf256_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf256_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf256_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf256_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf256_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf256_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf256_short_r3_ref OBJECT ${MQOM2_CAT1_GF256_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat1_gf256_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf256_short_r3_ref PRIVATE "-include" ${MQOM2_CAT1_GF256_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf256_short_r3_glue OBJECT sig_mqom2_cat1_gf256_short_r3.c)
    target_include_directories(mqom2_cat1_gf256_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf256_short_r3_glue PRIVATE "-include" ${MQOM2_CAT1_GF256_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf256_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf256_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat1_gf256_short_r5)
    set(MQOM2_CAT1_GF256_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/namespace_mqom2_cat1_gf256_short_r5.h)

    set(MQOM2_CAT1_GF256_SHORT_R5_SOURCES
        mqom2_cat1_gf256_short_r5/expand_mq.c
        mqom2_cat1_gf256_short_r5/ggm_tree.c
        mqom2_cat1_gf256_short_r5/keygen.c
        mqom2_cat1_gf256_short_r5/prg.c
        mqom2_cat1_gf256_short_r5/sign.c
        mqom2_cat1_gf256_short_r5/xof.c
        mqom2_cat1_gf256_short_r5/lib/blc/blc_default.c
        mqom2_cat1_gf256_short_r5/lib/blc/blc_memopt.c
        mqom2_cat1_gf256_short_r5/lib/piop/piop_default.c
        mqom2_cat1_gf256_short_r5/lib/piop/piop_memopt.c
        mqom2_cat1_gf256_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat1_gf256_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat1_gf256_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat1_gf256_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat1_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat1_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat1_gf256_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat1_gf256_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat1_gf256_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat1_gf256_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat1_gf256_short_r5_ref OBJECT ${MQOM2_CAT1_GF256_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat1_gf256_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf256_short_r5_ref PRIVATE "-include" ${MQOM2_CAT1_GF256_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat1_gf256_short_r5_glue OBJECT sig_mqom2_cat1_gf256_short_r5.c)
    target_include_directories(mqom2_cat1_gf256_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat1_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat1_gf256_short_r5_glue PRIVATE "-include" ${MQOM2_CAT1_GF256_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat1_gf256_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat1_gf256_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf2_short_r3)
    set(MQOM2_CAT3_GF2_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/namespace_mqom2_cat3_gf2_short_r3.h)

    set(MQOM2_CAT3_GF2_SHORT_R3_SOURCES
        mqom2_cat3_gf2_short_r3/expand_mq.c
        mqom2_cat3_gf2_short_r3/ggm_tree.c
        mqom2_cat3_gf2_short_r3/keygen.c
        mqom2_cat3_gf2_short_r3/prg.c
        mqom2_cat3_gf2_short_r3/sign.c
        mqom2_cat3_gf2_short_r3/xof.c
        mqom2_cat3_gf2_short_r3/lib/blc/blc_default.c
        mqom2_cat3_gf2_short_r3/lib/blc/blc_memopt.c
        mqom2_cat3_gf2_short_r3/lib/piop/piop_default.c
        mqom2_cat3_gf2_short_r3/lib/piop/piop_memopt.c
        mqom2_cat3_gf2_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat3_gf2_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf2_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf2_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf2_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf2_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf2_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf2_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf2_short_r3_ref OBJECT ${MQOM2_CAT3_GF2_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat3_gf2_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf2_short_r3_ref PRIVATE "-include" ${MQOM2_CAT3_GF2_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf2_short_r3_glue OBJECT sig_mqom2_cat3_gf2_short_r3.c)
    target_include_directories(mqom2_cat3_gf2_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf2_short_r3_glue PRIVATE "-include" ${MQOM2_CAT3_GF2_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf2_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf2_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf2_short_r5)
    set(MQOM2_CAT3_GF2_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/namespace_mqom2_cat3_gf2_short_r5.h)

    set(MQOM2_CAT3_GF2_SHORT_R5_SOURCES
        mqom2_cat3_gf2_short_r5/expand_mq.c
        mqom2_cat3_gf2_short_r5/ggm_tree.c
        mqom2_cat3_gf2_short_r5/keygen.c
        mqom2_cat3_gf2_short_r5/prg.c
        mqom2_cat3_gf2_short_r5/sign.c
        mqom2_cat3_gf2_short_r5/xof.c
        mqom2_cat3_gf2_short_r5/lib/blc/blc_default.c
        mqom2_cat3_gf2_short_r5/lib/blc/blc_memopt.c
        mqom2_cat3_gf2_short_r5/lib/piop/piop_default.c
        mqom2_cat3_gf2_short_r5/lib/piop/piop_memopt.c
        mqom2_cat3_gf2_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat3_gf2_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf2_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf2_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf2_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf2_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf2_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf2_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf2_short_r5_ref OBJECT ${MQOM2_CAT3_GF2_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat3_gf2_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf2_short_r5_ref PRIVATE "-include" ${MQOM2_CAT3_GF2_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf2_short_r5_glue OBJECT sig_mqom2_cat3_gf2_short_r5.c)
    target_include_directories(mqom2_cat3_gf2_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf2_short_r5_glue PRIVATE "-include" ${MQOM2_CAT3_GF2_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf2_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf2_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf16_short_r3)
    set(MQOM2_CAT3_GF16_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/namespace_mqom2_cat3_gf16_short_r3.h)

    set(MQOM2_CAT3_GF16_SHORT_R3_SOURCES
        mqom2_cat3_gf16_short_r3/expand_mq.c
        mqom2_cat3_gf16_short_r3/ggm_tree.c
        mqom2_cat3_gf16_short_r3/keygen.c
        mqom2_cat3_gf16_short_r3/prg.c
        mqom2_cat3_gf16_short_r3/sign.c
        mqom2_cat3_gf16_short_r3/xof.c
        mqom2_cat3_gf16_short_r3/lib/blc/blc_default.c
        mqom2_cat3_gf16_short_r3/lib/blc/blc_memopt.c
        mqom2_cat3_gf16_short_r3/lib/piop/piop_default.c
        mqom2_cat3_gf16_short_r3/lib/piop/piop_memopt.c
        mqom2_cat3_gf16_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat3_gf16_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf16_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf16_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf16_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf16_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf16_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf16_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf16_short_r3_ref OBJECT ${MQOM2_CAT3_GF16_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat3_gf16_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf16_short_r3_ref PRIVATE "-include" ${MQOM2_CAT3_GF16_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf16_short_r3_glue OBJECT sig_mqom2_cat3_gf16_short_r3.c)
    target_include_directories(mqom2_cat3_gf16_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf16_short_r3_glue PRIVATE "-include" ${MQOM2_CAT3_GF16_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf16_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf16_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf16_short_r5)
    set(MQOM2_CAT3_GF16_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/namespace_mqom2_cat3_gf16_short_r5.h)

    set(MQOM2_CAT3_GF16_SHORT_R5_SOURCES
        mqom2_cat3_gf16_short_r5/expand_mq.c
        mqom2_cat3_gf16_short_r5/ggm_tree.c
        mqom2_cat3_gf16_short_r5/keygen.c
        mqom2_cat3_gf16_short_r5/prg.c
        mqom2_cat3_gf16_short_r5/sign.c
        mqom2_cat3_gf16_short_r5/xof.c
        mqom2_cat3_gf16_short_r5/lib/blc/blc_default.c
        mqom2_cat3_gf16_short_r5/lib/blc/blc_memopt.c
        mqom2_cat3_gf16_short_r5/lib/piop/piop_default.c
        mqom2_cat3_gf16_short_r5/lib/piop/piop_memopt.c
        mqom2_cat3_gf16_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat3_gf16_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf16_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf16_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf16_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf16_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf16_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf16_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf16_short_r5_ref OBJECT ${MQOM2_CAT3_GF16_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat3_gf16_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf16_short_r5_ref PRIVATE "-include" ${MQOM2_CAT3_GF16_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf16_short_r5_glue OBJECT sig_mqom2_cat3_gf16_short_r5.c)
    target_include_directories(mqom2_cat3_gf16_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf16_short_r5_glue PRIVATE "-include" ${MQOM2_CAT3_GF16_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf16_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf16_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf256_short_r3)
    set(MQOM2_CAT3_GF256_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/namespace_mqom2_cat3_gf256_short_r3.h)

    set(MQOM2_CAT3_GF256_SHORT_R3_SOURCES
        mqom2_cat3_gf256_short_r3/expand_mq.c
        mqom2_cat3_gf256_short_r3/ggm_tree.c
        mqom2_cat3_gf256_short_r3/keygen.c
        mqom2_cat3_gf256_short_r3/prg.c
        mqom2_cat3_gf256_short_r3/sign.c
        mqom2_cat3_gf256_short_r3/xof.c
        mqom2_cat3_gf256_short_r3/lib/blc/blc_default.c
        mqom2_cat3_gf256_short_r3/lib/blc/blc_memopt.c
        mqom2_cat3_gf256_short_r3/lib/piop/piop_default.c
        mqom2_cat3_gf256_short_r3/lib/piop/piop_memopt.c
        mqom2_cat3_gf256_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat3_gf256_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf256_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf256_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf256_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf256_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf256_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf256_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf256_short_r3_ref OBJECT ${MQOM2_CAT3_GF256_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat3_gf256_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf256_short_r3_ref PRIVATE "-include" ${MQOM2_CAT3_GF256_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf256_short_r3_glue OBJECT sig_mqom2_cat3_gf256_short_r3.c)
    target_include_directories(mqom2_cat3_gf256_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf256_short_r3_glue PRIVATE "-include" ${MQOM2_CAT3_GF256_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf256_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf256_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat3_gf256_short_r5)
    set(MQOM2_CAT3_GF256_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/namespace_mqom2_cat3_gf256_short_r5.h)

    set(MQOM2_CAT3_GF256_SHORT_R5_SOURCES
        mqom2_cat3_gf256_short_r5/expand_mq.c
        mqom2_cat3_gf256_short_r5/ggm_tree.c
        mqom2_cat3_gf256_short_r5/keygen.c
        mqom2_cat3_gf256_short_r5/prg.c
        mqom2_cat3_gf256_short_r5/sign.c
        mqom2_cat3_gf256_short_r5/xof.c
        mqom2_cat3_gf256_short_r5/lib/blc/blc_default.c
        mqom2_cat3_gf256_short_r5/lib/blc/blc_memopt.c
        mqom2_cat3_gf256_short_r5/lib/piop/piop_default.c
        mqom2_cat3_gf256_short_r5/lib/piop/piop_memopt.c
        mqom2_cat3_gf256_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat3_gf256_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat3_gf256_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat3_gf256_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat3_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat3_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat3_gf256_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat3_gf256_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat3_gf256_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat3_gf256_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat3_gf256_short_r5_ref OBJECT ${MQOM2_CAT3_GF256_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat3_gf256_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf256_short_r5_ref PRIVATE "-include" ${MQOM2_CAT3_GF256_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat3_gf256_short_r5_glue OBJECT sig_mqom2_cat3_gf256_short_r5.c)
    target_include_directories(mqom2_cat3_gf256_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat3_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat3_gf256_short_r5_glue PRIVATE "-include" ${MQOM2_CAT3_GF256_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat3_gf256_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat3_gf256_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf2_short_r3)
    set(MQOM2_CAT5_GF2_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/namespace_mqom2_cat5_gf2_short_r3.h)

    set(MQOM2_CAT5_GF2_SHORT_R3_SOURCES
        mqom2_cat5_gf2_short_r3/expand_mq.c
        mqom2_cat5_gf2_short_r3/ggm_tree.c
        mqom2_cat5_gf2_short_r3/keygen.c
        mqom2_cat5_gf2_short_r3/prg.c
        mqom2_cat5_gf2_short_r3/sign.c
        mqom2_cat5_gf2_short_r3/xof.c
        mqom2_cat5_gf2_short_r3/lib/blc/blc_default.c
        mqom2_cat5_gf2_short_r3/lib/blc/blc_memopt.c
        mqom2_cat5_gf2_short_r3/lib/piop/piop_default.c
        mqom2_cat5_gf2_short_r3/lib/piop/piop_memopt.c
        mqom2_cat5_gf2_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat5_gf2_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf2_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf2_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf2_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf2_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf2_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf2_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf2_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf2_short_r3_ref OBJECT ${MQOM2_CAT5_GF2_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat5_gf2_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf2_short_r3_ref PRIVATE "-include" ${MQOM2_CAT5_GF2_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf2_short_r3_glue OBJECT sig_mqom2_cat5_gf2_short_r3.c)
    target_include_directories(mqom2_cat5_gf2_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf2_short_r3_glue PRIVATE "-include" ${MQOM2_CAT5_GF2_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf2_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf2_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf2_short_r5)
    set(MQOM2_CAT5_GF2_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/namespace_mqom2_cat5_gf2_short_r5.h)

    set(MQOM2_CAT5_GF2_SHORT_R5_SOURCES
        mqom2_cat5_gf2_short_r5/expand_mq.c
        mqom2_cat5_gf2_short_r5/ggm_tree.c
        mqom2_cat5_gf2_short_r5/keygen.c
        mqom2_cat5_gf2_short_r5/prg.c
        mqom2_cat5_gf2_short_r5/sign.c
        mqom2_cat5_gf2_short_r5/xof.c
        mqom2_cat5_gf2_short_r5/lib/blc/blc_default.c
        mqom2_cat5_gf2_short_r5/lib/blc/blc_memopt.c
        mqom2_cat5_gf2_short_r5/lib/piop/piop_default.c
        mqom2_cat5_gf2_short_r5/lib/piop/piop_memopt.c
        mqom2_cat5_gf2_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat5_gf2_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf2_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf2_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf2_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf2_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf2_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf2_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf2_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf2_short_r5_ref OBJECT ${MQOM2_CAT5_GF2_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat5_gf2_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf2_short_r5_ref PRIVATE "-include" ${MQOM2_CAT5_GF2_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf2_short_r5_glue OBJECT sig_mqom2_cat5_gf2_short_r5.c)
    target_include_directories(mqom2_cat5_gf2_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf2_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf2_short_r5_glue PRIVATE "-include" ${MQOM2_CAT5_GF2_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf2_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf2_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf16_short_r3)
    set(MQOM2_CAT5_GF16_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/namespace_mqom2_cat5_gf16_short_r3.h)

    set(MQOM2_CAT5_GF16_SHORT_R3_SOURCES
        mqom2_cat5_gf16_short_r3/expand_mq.c
        mqom2_cat5_gf16_short_r3/ggm_tree.c
        mqom2_cat5_gf16_short_r3/keygen.c
        mqom2_cat5_gf16_short_r3/prg.c
        mqom2_cat5_gf16_short_r3/sign.c
        mqom2_cat5_gf16_short_r3/xof.c
        mqom2_cat5_gf16_short_r3/lib/blc/blc_default.c
        mqom2_cat5_gf16_short_r3/lib/blc/blc_memopt.c
        mqom2_cat5_gf16_short_r3/lib/piop/piop_default.c
        mqom2_cat5_gf16_short_r3/lib/piop/piop_memopt.c
        mqom2_cat5_gf16_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat5_gf16_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf16_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf16_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf16_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf16_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf16_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf16_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf16_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf16_short_r3_ref OBJECT ${MQOM2_CAT5_GF16_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat5_gf16_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf16_short_r3_ref PRIVATE "-include" ${MQOM2_CAT5_GF16_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf16_short_r3_glue OBJECT sig_mqom2_cat5_gf16_short_r3.c)
    target_include_directories(mqom2_cat5_gf16_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf16_short_r3_glue PRIVATE "-include" ${MQOM2_CAT5_GF16_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf16_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf16_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf16_short_r5)
    set(MQOM2_CAT5_GF16_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/namespace_mqom2_cat5_gf16_short_r5.h)

    set(MQOM2_CAT5_GF16_SHORT_R5_SOURCES
        mqom2_cat5_gf16_short_r5/expand_mq.c
        mqom2_cat5_gf16_short_r5/ggm_tree.c
        mqom2_cat5_gf16_short_r5/keygen.c
        mqom2_cat5_gf16_short_r5/prg.c
        mqom2_cat5_gf16_short_r5/sign.c
        mqom2_cat5_gf16_short_r5/xof.c
        mqom2_cat5_gf16_short_r5/lib/blc/blc_default.c
        mqom2_cat5_gf16_short_r5/lib/blc/blc_memopt.c
        mqom2_cat5_gf16_short_r5/lib/piop/piop_default.c
        mqom2_cat5_gf16_short_r5/lib/piop/piop_memopt.c
        mqom2_cat5_gf16_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat5_gf16_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf16_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf16_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf16_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf16_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf16_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf16_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf16_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf16_short_r5_ref OBJECT ${MQOM2_CAT5_GF16_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat5_gf16_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf16_short_r5_ref PRIVATE "-include" ${MQOM2_CAT5_GF16_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf16_short_r5_glue OBJECT sig_mqom2_cat5_gf16_short_r5.c)
    target_include_directories(mqom2_cat5_gf16_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf16_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf16_short_r5_glue PRIVATE "-include" ${MQOM2_CAT5_GF16_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf16_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf16_short_r5_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf256_short_r3)
    set(MQOM2_CAT5_GF256_SHORT_R3_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/namespace_mqom2_cat5_gf256_short_r3.h)

    set(MQOM2_CAT5_GF256_SHORT_R3_SOURCES
        mqom2_cat5_gf256_short_r3/expand_mq.c
        mqom2_cat5_gf256_short_r3/ggm_tree.c
        mqom2_cat5_gf256_short_r3/keygen.c
        mqom2_cat5_gf256_short_r3/prg.c
        mqom2_cat5_gf256_short_r3/sign.c
        mqom2_cat5_gf256_short_r3/xof.c
        mqom2_cat5_gf256_short_r3/lib/blc/blc_default.c
        mqom2_cat5_gf256_short_r3/lib/blc/blc_memopt.c
        mqom2_cat5_gf256_short_r3/lib/piop/piop_default.c
        mqom2_cat5_gf256_short_r3/lib/piop/piop_memopt.c
        mqom2_cat5_gf256_short_r3/lib/sha3/KeccakHash.c
        mqom2_cat5_gf256_short_r3/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf256_short_r3/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf256_short_r3/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf256_short_r3/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf256_short_r3/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf256_short_r3/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf256_short_r3/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf256_short_r3/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf256_short_r3_ref OBJECT ${MQOM2_CAT5_GF256_SHORT_R3_SOURCES})
    target_include_directories(mqom2_cat5_gf256_short_r3_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf256_short_r3_ref PRIVATE "-include" ${MQOM2_CAT5_GF256_SHORT_R3_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf256_short_r3_glue OBJECT sig_mqom2_cat5_gf256_short_r3.c)
    target_include_directories(mqom2_cat5_gf256_short_r3_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r3/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf256_short_r3_glue PRIVATE "-include" ${MQOM2_CAT5_GF256_SHORT_R3_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf256_short_r3_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf256_short_r3_glue>)
endif()

if(OQS_ENABLE_SIG_mqom2_cat5_gf256_short_r5)
    set(MQOM2_CAT5_GF256_SHORT_R5_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/namespace_mqom2_cat5_gf256_short_r5.h)

    set(MQOM2_CAT5_GF256_SHORT_R5_SOURCES
        mqom2_cat5_gf256_short_r5/expand_mq.c
        mqom2_cat5_gf256_short_r5/ggm_tree.c
        mqom2_cat5_gf256_short_r5/keygen.c
        mqom2_cat5_gf256_short_r5/prg.c
        mqom2_cat5_gf256_short_r5/sign.c
        mqom2_cat5_gf256_short_r5/xof.c
        mqom2_cat5_gf256_short_r5/lib/blc/blc_default.c
        mqom2_cat5_gf256_short_r5/lib/blc/blc_memopt.c
        mqom2_cat5_gf256_short_r5/lib/piop/piop_default.c
        mqom2_cat5_gf256_short_r5/lib/piop/piop_memopt.c
        mqom2_cat5_gf256_short_r5/lib/sha3/KeccakHash.c
        mqom2_cat5_gf256_short_r5/lib/sha3/KeccakHashtimes4.c
        mqom2_cat5_gf256_short_r5/lib/sha3/KeccakSponge.c
        mqom2_cat5_gf256_short_r5/lib/sha3/KeccakSpongetimes4.c
        mqom2_cat5_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-opt64.c
        mqom2_cat5_gf256_short_r5/lib/sha3/opt64/KeccakP-1600-times4-on1.c
        mqom2_cat5_gf256_short_r5/lib/rijndael/rijndael_aes_ni.c
        mqom2_cat5_gf256_short_r5/lib/rijndael/rijndael_ct64.c
        mqom2_cat5_gf256_short_r5/lib/rijndael/rijndael_ref.c
        mqom2_cat5_gf256_short_r5/lib/rijndael/rijndael_table.c
    )

    add_library(mqom2_cat5_gf256_short_r5_ref OBJECT ${MQOM2_CAT5_GF256_SHORT_R5_SOURCES})
    target_include_directories(mqom2_cat5_gf256_short_r5_ref PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf256_short_r5_ref PRIVATE "-include" ${MQOM2_CAT5_GF256_SHORT_R5_NAMESPACE_HEADER})

    add_library(mqom2_cat5_gf256_short_r5_glue OBJECT sig_mqom2_cat5_gf256_short_r5.c)
    target_include_directories(mqom2_cat5_gf256_short_r5_glue PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/blc
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/fields
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/generator
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/piop
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/rijndael
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/sha3
        ${CMAKE_CURRENT_LIST_DIR}/mqom2_cat5_gf256_short_r5/lib/sha3/opt64)
    target_compile_options(mqom2_cat5_gf256_short_r5_glue PRIVATE "-include" ${MQOM2_CAT5_GF256_SHORT_R5_NAMESPACE_HEADER})

    set(_MQOM_OBJS ${_MQOM_OBJS}
        $<TARGET_OBJECTS:mqom2_cat5_gf256_short_r5_ref>
        $<TARGET_OBJECTS:mqom2_cat5_gf256_short_r5_glue>)
endif()

list(REMOVE_DUPLICATES _MQOM_LIBS)

set(MQOM_OBJS ${_MQOM_OBJS} PARENT_SCOPE)
set(MQOM_LIBS ${_MQOM_LIBS} PARENT_SCOPE)
