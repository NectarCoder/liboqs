// SPDX-License-Identifier: MIT
#pragma once

#ifndef QRUOV_NAMESPACE_PREFIX
#define QRUOV_NAMESPACE_PREFIX QRUOV
#endif

#define QRUOV_NS_CONCAT_INNER(a, b) a##_##b
#define QRUOV_NS_CONCAT(a, b) QRUOV_NS_CONCAT_INNER(a, b)
#define QRUOV_NS(name) QRUOV_NS_CONCAT(QRUOV_NAMESPACE_PREFIX, name)

#define Fql_zero QRUOV_NS(Fql_zero)
#define Fq_inv_table QRUOV_NS(Fq_inv_table)

#define VECTOR_M_ADD QRUOV_NS(VECTOR_M_ADD)
#define VECTOR_M_SUB QRUOV_NS(VECTOR_M_SUB)
#define VECTOR_V_SUB QRUOV_NS(VECTOR_V_SUB)
#define VECTOR_V_dot_VECTOR_V QRUOV_NS(VECTOR_V_dot_VECTOR_V)
#define VECTOR_M_dot_VECTOR_M QRUOV_NS(VECTOR_M_dot_VECTOR_M)
#define VECTOR_V_MUL_SYMMETRIC_MATRIX_VxV QRUOV_NS(VECTOR_V_MUL_SYMMETRIC_MATRIX_VxV)
#define MATRIX_TRANSPOSE_VxM QRUOV_NS(MATRIX_TRANSPOSE_VxM)
#define VECTOR_V_MUL_MATRIX_VxM QRUOV_NS(VECTOR_V_MUL_MATRIX_VxM)
#define MATRIX_MxV_MUL_SYMMETRIC_MATRIX_VxV QRUOV_NS(MATRIX_MxV_MUL_SYMMETRIC_MATRIX_VxV)
#define MATRIX_MUL_MxV_VxM QRUOV_NS(MATRIX_MUL_MxV_VxM)
#define MATRIX_ADD_MxM QRUOV_NS(MATRIX_ADD_MxM)
#define MATRIX_MUL_ADD_MxV_VxM QRUOV_NS(MATRIX_MUL_ADD_MxV_VxM)
#define MATRIX_SUB_MxV QRUOV_NS(MATRIX_SUB_MxV)

#define MGF_init QRUOV_NS(MGF_init)
#define MGF_update QRUOV_NS(MGF_update)
#define MGF_yield QRUOV_NS(MGF_yield)
#define MGF_final QRUOV_NS(MGF_final)
#define MGF_CTX_copy QRUOV_NS(MGF_CTX_copy)
#define EVP_DigestFinalXOF_BEGIN QRUOV_NS(EVP_DigestFinalXOF_BEGIN)
#define EVP_DigestFinalXOF_SQUEEZE QRUOV_NS(EVP_DigestFinalXOF_SQUEEZE)
#define EVP_DigestFinalXOF_END QRUOV_NS(EVP_DigestFinalXOF_END)

#define QRUOV_KeyGen QRUOV_NS(QRUOV_KeyGen)
#define QRUOV_Sign QRUOV_NS(QRUOV_Sign)
#define QRUOV_Verify QRUOV_NS(QRUOV_Verify)
#define store_QRUOV_P3 QRUOV_NS(store_QRUOV_P3)
#define restore_QRUOV_P3 QRUOV_NS(restore_QRUOV_P3)

#define crypto_sign_keypair QRUOV_NS(crypto_sign_keypair)
#define crypto_sign QRUOV_NS(crypto_sign)
#define crypto_sign_open QRUOV_NS(crypto_sign_open)

#define randombytes_init QRUOV_NS(randombytes_init)
#define randombytes QRUOV_NS(randombytes)
