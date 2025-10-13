/**
 * \file sig_mqom.h
 * \brief MQOM signature algorithm family declarations
 *
 * MQOM2-CAT1-GF2-SHORT-R3 is a NIST Round 2
 * post-quantum digital signature scheme integrated into this fork.
 */

#ifndef OQS_SIG_MQOM_H
#define OQS_SIG_MQOM_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Algorithm identifier for MQOM2-CAT1-GF2-SHORT-R3 */
#define OQS_SIG_alg_mqom2_cat1_gf2_short_r3 "MQOM2-CAT1-GF2-SHORT-R3"
/** Algorithm identifier for MQOM2-CAT1-GF2-SHORT-R5 */
#define OQS_SIG_alg_mqom2_cat1_gf2_short_r5 "MQOM2-CAT1-GF2-SHORT-R5"

/** MQOM2-CAT1-GF2-SHORT-R3 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_public_key 52
/** MQOM2-CAT1-GF2-SHORT-R3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_secret_key 72
/** MQOM2-CAT1-GF2-SHORT-R3 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_signature 2868

/** MQOM2-CAT1-GF2-SHORT-R5 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key 52
/** MQOM2-CAT1-GF2-SHORT-R5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key 72
/** MQOM2-CAT1-GF2-SHORT-R5 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature 2820

OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r3)
OQS_API OQS_SIG *OQS_SIG_mqom2_cat1_gf2_short_r3_new(void);
#endif

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r5)
OQS_API OQS_SIG *OQS_SIG_mqom2_cat1_gf2_short_r5_new(void);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OQS_SIG_MQOM_H
