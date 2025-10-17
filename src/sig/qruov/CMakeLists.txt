# SPDX-License-Identifier: MIT

if(NOT OQS_USE_OPENSSL)
    message(FATAL_ERROR "QR-UOV requires OpenSSL support. Please configure with OQS_USE_OPENSSL=ON.")
endif()

set(QRUOV_COMMON_SOURCES
    common/Fql.c
    common/matrix.c
    common/mgf.c
    common/qruov.c
    common/rng.c
    common/sign.c)

set(QRUOV_VARIANT_DATA
    "qruov1q127L3v156m54|1|24256|32|200"
    "qruov1q7L10v740m100|1|20641|32|331"
    "qruov1q31L3v165m60|1|23641|32|157"
    "qruov1q31L10v600m70|1|12266|32|435"
    "qruov3q127L3v228m78|3|71892|48|292"
    "qruov3q7L10v1100m140|3|55149|48|489"
    "qruov3q31L3v246m87|3|70984|48|233"
    "qruov3q31L10v890m100|3|34399|48|643"
    "qruov5q127L3v306m105|5|173676|64|392"
    "qruov5q7L10v1490m190|5|135407|64|662"
    "qruov5q31L3v324m114|5|158421|64|306"
    "qruov5q31L10v1120m120|5|58532|64|807"
)

set(_QRUOV_OBJS "")

foreach(entry ${QRUOV_VARIANT_DATA})
    string(REPLACE "|" ";" entry_list ${entry})
    list(GET entry_list 0 variant)
    list(GET entry_list 1 level)
    list(GET entry_list 2 pk_bytes)
    list(GET entry_list 3 sk_bytes)
    list(GET entry_list 4 sig_bytes)

    set(variant_target "qruov_${variant}")
    add_library(${variant_target} OBJECT ${QRUOV_COMMON_SOURCES})
    set(namespace_header ${CMAKE_CURRENT_LIST_DIR}/${variant}/namespace_${variant}.h)
    target_compile_options(${variant_target} PRIVATE "-include" ${namespace_header})
    target_include_directories(${variant_target} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/common
        ${CMAKE_CURRENT_LIST_DIR}/${variant}
        ${PROJECT_SOURCE_DIR}/src/common
        ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    set(glue_target "${variant_target}_glue")
    add_library(${glue_target} OBJECT sig_${variant}.c)
    target_compile_options(${glue_target} PRIVATE "-include" ${namespace_header})
    target_include_directories(${glue_target} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/common
        ${CMAKE_CURRENT_LIST_DIR}/${variant}
        ${PROJECT_SOURCE_DIR}/src/common)

    set(_QRUOV_OBJS ${_QRUOV_OBJS} $<TARGET_OBJECTS:${variant_target}> $<TARGET_OBJECTS:${glue_target}>)
endforeach()

set(QRUOV_OBJS ${_QRUOV_OBJS} PARENT_SCOPE)
