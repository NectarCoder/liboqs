# SPDX-License-Identifier: MIT

set(_HAWK_OBJS "")

if(OQS_ENABLE_SIG_hawk_512)
    # Main HAWK algorithm sources (without lib dependencies)
    set(HAWK_512_SOURCES
        hawk_512/hawk_kgen.c
        hawk_512/hawk_sign.c
        hawk_512/hawk_vrfy.c
        hawk_512/ng_fxp.c
        hawk_512/ng_hawk.c
        hawk_512/ng_mp31.c
        hawk_512/ng_ntru.c
        hawk_512/ng_poly.c
        hawk_512/ng_zint31.c
    )

    add_library(hawk_512 OBJECT ${HAWK_512_SOURCES})
    
    target_include_directories(hawk_512 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk_512)
    target_include_directories(hawk_512 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    
    # Add the glue code as a separate object for the Hawk-512 variant
    add_library(hawk_512_glue OBJECT sig_hawk512.c)
    target_include_directories(hawk_512_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(hawk_512_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk_512)
    
    set(_HAWK_OBJS ${_HAWK_OBJS} $<TARGET_OBJECTS:hawk_512> $<TARGET_OBJECTS:hawk_512_glue>)
endif()

if(OQS_ENABLE_SIG_hawk_1024)
    # Main HAWK algorithm sources (without lib dependencies)
    set(HAWK_1024_SOURCES
        hawk_1024/hawk_kgen.c
        hawk_1024/hawk_sign.c
        hawk_1024/hawk_vrfy.c
        hawk_1024/ng_fxp.c
        hawk_1024/ng_hawk.c
        hawk_1024/ng_mp31.c
        hawk_1024/ng_ntru.c
        hawk_1024/ng_poly.c
        hawk_1024/ng_zint31.c
    )

    add_library(hawk_1024 OBJECT ${HAWK_1024_SOURCES})
    
    target_include_directories(hawk_1024 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk_1024)
    target_include_directories(hawk_1024 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    
    # Add the glue code as a separate object for the Hawk-1024 variant
    add_library(hawk_1024_glue OBJECT sig_hawk1024.c)
    target_include_directories(hawk_1024_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(hawk_1024_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk_1024)
    
    set(_HAWK_OBJS ${_HAWK_OBJS} $<TARGET_OBJECTS:hawk_1024> $<TARGET_OBJECTS:hawk_1024_glue>)
endif()


set(HAWK_OBJS ${_HAWK_OBJS} PARENT_SCOPE)