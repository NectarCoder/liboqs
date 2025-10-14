# SPDX-License-Identifier: MIT

set(_LESS_OBJS "")

set(LESS_COMMON_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/common/LESS.c
    ${CMAKE_CURRENT_LIST_DIR}/common/canonical.c
    ${CMAKE_CURRENT_LIST_DIR}/common/codes.c
    ${CMAKE_CURRENT_LIST_DIR}/common/fips202.c
    ${CMAKE_CURRENT_LIST_DIR}/common/keccakf1600.c
    ${CMAKE_CURRENT_LIST_DIR}/common/monomial.c
    ${CMAKE_CURRENT_LIST_DIR}/common/rng.c
    ${CMAKE_CURRENT_LIST_DIR}/common/seedtree.c
    ${CMAKE_CURRENT_LIST_DIR}/common/sign.c
    ${CMAKE_CURRENT_LIST_DIR}/common/sort.c
    ${CMAKE_CURRENT_LIST_DIR}/common/transpose.c
    ${CMAKE_CURRENT_LIST_DIR}/common/utils.c
)

macro(add_less_variant variant category target)
    if(OQS_ENABLE_SIG_less_${variant})
        add_library(less_${variant}_ref OBJECT ${LESS_COMMON_SOURCES})
    target_include_directories(less_${variant}_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/common)
        target_compile_definitions(less_${variant}_ref PRIVATE
            LESS_NAMESPACE_PREFIX=less_${variant}_
            CATEGORY=${category}
            TARGET=${target}
        )

        add_library(less_${variant}_glue OBJECT ${CMAKE_CURRENT_LIST_DIR}/sig_less_${variant}.c)
        target_include_directories(less_${variant}_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_CURRENT_LIST_DIR}/common)
        target_compile_definitions(less_${variant}_glue PRIVATE
            LESS_NAMESPACE_PREFIX=less_${variant}_
            CATEGORY=${category}
            TARGET=${target}
        )

        set(_LESS_OBJS ${_LESS_OBJS}
            $<TARGET_OBJECTS:less_${variant}_ref>
            $<TARGET_OBJECTS:less_${variant}_glue>
        )
    endif()
endmacro()

add_less_variant(252_192 252 192)
add_less_variant(252_68 252 68)
add_less_variant(252_45 252 45)
add_less_variant(400_220 400 220)
add_less_variant(400_102 400 102)
add_less_variant(548_345 548 345)
add_less_variant(548_137 548 137)

set(LESS_OBJS ${_LESS_OBJS} PARENT_SCOPE)
