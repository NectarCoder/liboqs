

#needs edtiting to fit into liboqs build system
# SPDX-License-Identifier: Apache-2.0

set(_LESS_OBJS "")
if(OQS_ENABLE_SIG_less_252_45)
    set(LESS_252_45_NAMESPACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/less_252_45/less_252_45_namespace.h)
    # Main MIRATH algorithm sources (without lib dependencies)
    set(LESS_252_45_SOURCES
        less_252_45/codes.c
        less_252_45/fips202.c
        less_252_45/keccakf1600.c
        less_252_45/LESS1.c
        less_252_45/monomial.c
        less_252_45/rng.c
        less_252_45/seedtree.c
        less_252_45/sign.c
        less_252_45/utils.c
        less_252_45/sort.c
        less_252_45/canonical.c
        less_252_45/transpose.c
    )

    add_library(less_252_45_ref OBJECT ${LESS_252_45_SOURCES})
    
    target_include_directories(less_252_45_ref PRIVATE
        less_252_45/include)
    target_compile_options(less_252_45_ref PRIVATE "-include" ${LESS_252_45_NAMESPACE_HEADER})
    
    
    # Add the glue code as a separate object for the MIRATH_1a_short variant
    add_library(less_252_45_glue OBJECT sig_less_252_45.c)
    target_include_directories(less_252_45_glue PRIVATE
        less_252_45/include)
    target_compile_options(less_252_45_glue PRIVATE "-include" ${LESS_252_45_NAMESPACE_HEADER})
    set(_LESS_OBJS ${_LESS_OBJS} $<TARGET_OBJECTS:less_252_45_ref> $<TARGET_OBJECTS:less_252_45_glue>)
endif()

set(LESS_OBJS ${_LESS_OBJS} PARENT_SCOPE)