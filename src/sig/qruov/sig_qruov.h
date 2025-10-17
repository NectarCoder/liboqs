// SPDX-License-Identifier: MIT
/**
 * \file sig_qruov.h
 * \brief QR-UOV signature algorithm family
 */

#ifndef OQS_SIG_QRUOV_H
#define OQS_SIG_QRUOV_H

#include <oqs/oqs.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define OQS_SIG_alg_qruov1q127L3v156m54 "qruov1q127L3v156m54"
#define OQS_SIG_alg_qruov1q7L10v740m100 "qruov1q7L10v740m100"
#define OQS_SIG_alg_qruov1q31L3v165m60 "qruov1q31L3v165m60"
#define OQS_SIG_alg_qruov1q31L10v600m70 "qruov1q31L10v600m70"
#define OQS_SIG_alg_qruov3q127L3v228m78 "qruov3q127L3v228m78"
#define OQS_SIG_alg_qruov3q7L10v1100m140 "qruov3q7L10v1100m140"
#define OQS_SIG_alg_qruov3q31L3v246m87 "qruov3q31L3v246m87"
#define OQS_SIG_alg_qruov3q31L10v890m100 "qruov3q31L10v890m100"
#define OQS_SIG_alg_qruov5q127L3v306m105 "qruov5q127L3v306m105"
#define OQS_SIG_alg_qruov5q7L10v1490m190 "qruov5q7L10v1490m190"
#define OQS_SIG_alg_qruov5q31L3v324m114 "qruov5q31L3v324m114"
#define OQS_SIG_alg_qruov5q31L10v1120m120 "qruov5q31L10v1120m120"

#define OQS_SIG_qruov1q127L3v156m54_length_public_key 24256
#define OQS_SIG_qruov1q127L3v156m54_length_secret_key 32
#define OQS_SIG_qruov1q127L3v156m54_length_signature 200

#define OQS_SIG_qruov1q7L10v740m100_length_public_key 20641
#define OQS_SIG_qruov1q7L10v740m100_length_secret_key 32
#define OQS_SIG_qruov1q7L10v740m100_length_signature 331

#define OQS_SIG_qruov1q31L3v165m60_length_public_key 23641
#define OQS_SIG_qruov1q31L3v165m60_length_secret_key 32
#define OQS_SIG_qruov1q31L3v165m60_length_signature 157

#define OQS_SIG_qruov1q31L10v600m70_length_public_key 12266
#define OQS_SIG_qruov1q31L10v600m70_length_secret_key 32
#define OQS_SIG_qruov1q31L10v600m70_length_signature 435

#define OQS_SIG_qruov3q127L3v228m78_length_public_key 71892
#define OQS_SIG_qruov3q127L3v228m78_length_secret_key 48
#define OQS_SIG_qruov3q127L3v228m78_length_signature 292

#define OQS_SIG_qruov3q7L10v1100m140_length_public_key 55149
#define OQS_SIG_qruov3q7L10v1100m140_length_secret_key 48
#define OQS_SIG_qruov3q7L10v1100m140_length_signature 489

#define OQS_SIG_qruov3q31L3v246m87_length_public_key 70984
#define OQS_SIG_qruov3q31L3v246m87_length_secret_key 48
#define OQS_SIG_qruov3q31L3v246m87_length_signature 233

#define OQS_SIG_qruov3q31L10v890m100_length_public_key 34399
#define OQS_SIG_qruov3q31L10v890m100_length_secret_key 48
#define OQS_SIG_qruov3q31L10v890m100_length_signature 643

#define OQS_SIG_qruov5q127L3v306m105_length_public_key 173676
#define OQS_SIG_qruov5q127L3v306m105_length_secret_key 64
#define OQS_SIG_qruov5q127L3v306m105_length_signature 392

#define OQS_SIG_qruov5q7L10v1490m190_length_public_key 135407
#define OQS_SIG_qruov5q7L10v1490m190_length_secret_key 64
#define OQS_SIG_qruov5q7L10v1490m190_length_signature 662

#define OQS_SIG_qruov5q31L3v324m114_length_public_key 158421
#define OQS_SIG_qruov5q31L3v324m114_length_secret_key 64
#define OQS_SIG_qruov5q31L3v324m114_length_signature 306

#define OQS_SIG_qruov5q31L10v1120m120_length_public_key 58532
#define OQS_SIG_qruov5q31L10v1120m120_length_secret_key 64
#define OQS_SIG_qruov5q31L10v1120m120_length_signature 807

#if defined(OQS_ENABLE_SIG_qruov1q127L3v156m54)
OQS_SIG *OQS_SIG_qruov1q127L3v156m54_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov1q127L3v156m54_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q127L3v156m54_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q127L3v156m54_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q127L3v156m54_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q127L3v156m54_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov1q7L10v740m100)
OQS_SIG *OQS_SIG_qruov1q7L10v740m100_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov1q7L10v740m100_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q7L10v740m100_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q7L10v740m100_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q7L10v740m100_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q7L10v740m100_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov1q31L3v165m60)
OQS_SIG *OQS_SIG_qruov1q31L3v165m60_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L3v165m60_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L3v165m60_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L3v165m60_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L3v165m60_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L3v165m60_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov1q31L10v600m70)
OQS_SIG *OQS_SIG_qruov1q31L10v600m70_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L10v600m70_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L10v600m70_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L10v600m70_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L10v600m70_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov1q31L10v600m70_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov3q127L3v228m78)
OQS_SIG *OQS_SIG_qruov3q127L3v228m78_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov3q127L3v228m78_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q127L3v228m78_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q127L3v228m78_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q127L3v228m78_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q127L3v228m78_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov3q7L10v1100m140)
OQS_SIG *OQS_SIG_qruov3q7L10v1100m140_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov3q7L10v1100m140_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q7L10v1100m140_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q7L10v1100m140_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q7L10v1100m140_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q7L10v1100m140_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov3q31L3v246m87)
OQS_SIG *OQS_SIG_qruov3q31L3v246m87_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L3v246m87_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L3v246m87_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L3v246m87_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L3v246m87_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L3v246m87_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov3q31L10v890m100)
OQS_SIG *OQS_SIG_qruov3q31L10v890m100_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L10v890m100_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L10v890m100_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L10v890m100_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L10v890m100_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov3q31L10v890m100_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov5q127L3v306m105)
OQS_SIG *OQS_SIG_qruov5q127L3v306m105_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov5q127L3v306m105_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q127L3v306m105_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q127L3v306m105_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q127L3v306m105_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q127L3v306m105_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov5q7L10v1490m190)
OQS_SIG *OQS_SIG_qruov5q7L10v1490m190_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov5q7L10v1490m190_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q7L10v1490m190_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q7L10v1490m190_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q7L10v1490m190_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q7L10v1490m190_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov5q31L3v324m114)
OQS_SIG *OQS_SIG_qruov5q31L3v324m114_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L3v324m114_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L3v324m114_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L3v324m114_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L3v324m114_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L3v324m114_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_qruov5q31L10v1120m120)
OQS_SIG *OQS_SIG_qruov5q31L10v1120m120_new(void);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L10v1120m120_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L10v1120m120_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L10v1120m120_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L10v1120m120_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_qruov5q31L10v1120m120_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);
#endif

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_SIG_QRUOV_H
