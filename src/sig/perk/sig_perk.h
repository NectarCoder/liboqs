/**
 * \file sig_perk.h
 * \brief PERK signature algorithm family declarations
 *
 * PERK-AK-1-short, PERK-AK-3-short, and PERK-AK-5-short are NIST Round 2
 * post-quantum digital signature schemes integrated into this fork by
 * NectarCoder.
 *
 * \author NectarCoder
 */

#ifndef OQS_SIG_PERK_H
#define OQS_SIG_PERK_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Algorithm identifier for PERK-AK-1-short */
#define OQS_SIG_alg_perk_ak_1_short "PERK-AK-1-short"
/** Algorithm identifier for PERK-AK-3-short */
#define OQS_SIG_alg_perk_ak_3_short "PERK-AK-3-short"
/** Algorithm identifier for PERK-AK-5-short */
#define OQS_SIG_alg_perk_ak_5_short "PERK-AK-5-short"

/** PERK-AK-1-short public key length, in bytes */
#define OQS_SIG_perk_ak_1_short_length_public_key 104
/** PERK-AK-3-short public key length, in bytes */
#define OQS_SIG_perk_ak_3_short_length_public_key 151
/** PERK-AK-5-short public key length, in bytes */
#define OQS_SIG_perk_ak_5_short_length_public_key 195

/** PERK-AK-1-short secret key length, in bytes */
#define OQS_SIG_perk_ak_1_short_length_secret_key 120
/** PERK-AK-3-short secret key length, in bytes */
#define OQS_SIG_perk_ak_3_short_length_secret_key 175
/** PERK-AK-5-short secret key length, in bytes */
#define OQS_SIG_perk_ak_5_short_length_secret_key 227

/** PERK-AK-1-short signature length, in bytes */
#define OQS_SIG_perk_ak_1_short_length_signature 3473
/** PERK-AK-3-short signature length, in bytes */
#define OQS_SIG_perk_ak_3_short_length_signature 8311
/** PERK-AK-5-short signature length, in bytes */
#define OQS_SIG_perk_ak_5_short_length_signature 14830

#if defined(OQS_ENABLE_SIG_perk_ak_1_short)
OQS_API OQS_SIG *OQS_SIG_perk_ak_1_short_new(void);

OQS_API OQS_STATUS OQS_SIG_perk_ak_1_short_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_1_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_1_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_1_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_1_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_perk_ak_3_short)
OQS_API OQS_SIG *OQS_SIG_perk_ak_3_short_new(void);

OQS_API OQS_STATUS OQS_SIG_perk_ak_3_short_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_3_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_3_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_3_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_3_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_perk_ak_5_short)
OQS_API OQS_SIG *OQS_SIG_perk_ak_5_short_new(void);

OQS_API OQS_STATUS OQS_SIG_perk_ak_5_short_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_5_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_5_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_5_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_perk_ak_5_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OQS_SIG_PERK_H