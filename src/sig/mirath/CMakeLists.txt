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
        mirath_tcith_1a_fast/mirath_verify.c
        mirath_tcith_1a_fast/sign.c
    )

    add_library(mirath_tcith_1a_fast_ref OBJECT ${MIRATH_TCITH_1A_FAST_SOURCES})
    
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast)
    target_include_directories(mirath_tcith_1a_fast_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    
    # Add the glue code as a separate object for the MIRATH_1a_fast variant
    add_library(mirath_tcith_1a_fast_glue OBJECT sig_mirath_1a_fast.c)
    target_include_directories(mirath_tcith_1a_fast_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(mirath_tcith_1a_fast_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mirath_tcith_1a_fast)
    
    set(_MIRATH_OBJS ${_MIRATH_OBJS} $<TARGET_OBJECTS:mirath_tcith_1a_fast_ref> $<TARGET_OBJECTS:mirath_tcith_1a_fast_glue>)
endif()

set(MIRATH_OBJS ${_MIRATH_OBJS} PARENT_SCOPE)