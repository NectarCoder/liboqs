/**
 * \file sig_sqisign.h
 * \brief SQIsign signature algorithm family
 *
 * SQIsign is an isogeny-based post-quantum digital signature scheme derived from
 * the SQIsign reference implementation.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_SIG_SQISIGN_H
#define OQS_SIG_SQISIGN_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Algorithm identifier for SQIsign-353 */
#define OQS_SIG_alg_sqisign_353 "SQIsign-353"
/** SQIsign-353 public key length, in bytes */
#define OQS_SIG_sqisign_353_length_public_key 65
/** SQIsign-353 secret key length, in bytes */
#define OQS_SIG_sqisign_353_length_secret_key 353
/** SQIsign-353 signature length, in bytes */
#define OQS_SIG_sqisign_353_length_signature 148

/** Algorithm identifier for SQIsign-529 */
#define OQS_SIG_alg_sqisign_529 "SQIsign-529"
/** SQIsign-529 public key length, in bytes */
#define OQS_SIG_sqisign_529_length_public_key 97
/** SQIsign-529 secret key length, in bytes */
#define OQS_SIG_sqisign_529_length_secret_key 529
/** SQIsign-529 signature length, in bytes */
#define OQS_SIG_sqisign_529_length_signature 224

/** Algorithm identifier for SQIsign-701 */
#define OQS_SIG_alg_sqisign_701 "SQIsign-701"
/** SQIsign-701 public key length, in bytes */
#define OQS_SIG_sqisign_701_length_public_key 129
/** SQIsign-701 secret key length, in bytes */
#define OQS_SIG_sqisign_701_length_secret_key 701
/** SQIsign-701 signature length, in bytes */
#define OQS_SIG_sqisign_701_length_signature 292

OQS_API OQS_STATUS OQS_SIG_sqisign_353_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_353_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_353_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_353_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_353_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_sqisign_353)
OQS_SIG *OQS_SIG_sqisign_353_new(void);
#endif

OQS_API OQS_STATUS OQS_SIG_sqisign_529_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_529_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_529_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_529_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_529_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_sqisign_529)
OQS_SIG *OQS_SIG_sqisign_529_new(void);
#endif

OQS_API OQS_STATUS OQS_SIG_sqisign_701_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_sqisign_701)
OQS_SIG *OQS_SIG_sqisign_701_new(void);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OQS_SIG_SQISIGN_H
