# SPDX-License-Identifier: MIT

set(_QR_UOV_OBJS "")

if(OQS_ENABLE_SIG_qr_uov_s)
    # Main QR-UOV algorithm sources (without lib dependencies)
    set(QR_UOV_SOURCES
        qr_uov_s/api_h_gen.c
        qr_uov_s/Fql.c
        qr_uov_s/matrix.c
        qr_uov_s/mgf.c
        qr_uov_s/PQCgenKAT_sign.c
        qr_uov_s/qruov_config_h_gen.c
        qr_uov_s/qruov.c
        qr_uov_s/rng.c
        qr_uov_s/sign.c
        qr_uov_s/rng.c
    )

    add_library(qr_uov_s OBJECT ${QR_UOV_SOURCES})

    set(QR_UOV_S_API_DEFINES
        crypto_sign=qr_uov_s_crypto_sign
        crypto_sign_keypair=qr_uov_s_crypto_sign_keypair
        crypto_sign_open=qr_uov_s_crypto_sign_open
    )
    set_source_files_properties(qr_uov_s/api.c PROPERTIES COMPILE_DEFINITIONS "${QR_UOV_S_API_DEFINES}")

    target_include_directories(qr_uov_s PRIVATE ${CMAKE_CURRENT_LIST_DIR}/qr_uov_s)
    target_include_directories(qr_uov_s PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    # Add the glue code as a separate object for the QR-UOV variant
    add_library(qr_uov_s_glue OBJECT sig_qr_uov_s.c)
    target_include_directories(qr_uov_s_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_include_directories(qr_uov_s_glue PRIVATE ${CMAKE_CURRENT_LIST_DIR}/qr_uov_s)
    target_compile_definitions(qr_uov_s_glue PRIVATE ${QR_UOV_S_API_DEFINES})

    set(_QR_UOV_S_OBJS ${_QR_UOV_S_OBJS} $<TARGET_OBJECTS:qr_uov_s> $<TARGET_OBJECTS:qr_uov_s_glue>)
endif()

set(QR_UOV_S_OBJS ${_QR_UOV_S_OBJS} PARENT_SCOPE)