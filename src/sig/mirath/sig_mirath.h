// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_MIRATH_H
#define OQS_SIG_MIRATH_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(OQS_ENABLE_SIG_mirath_tcith_1a_short)

/** Algorithm identifier for mirath_tcith_1a_short */
#define OQS_SIG_alg_mirath_tcith_1a_short "MIRATH-TCITH-1A-SHORT"

/** mirath_tcith_1a_short public key length in bytes */
#define OQS_SIG_mirath_tcith_1a_short_length_public_key 73

/** mirath_tcith_1a_short secret key length in bytes */
#define OQS_SIG_mirath_tcith_1a_short_length_secret_key 32

/** mirath_tcith_1a_short signature length in bytes */
#define OQS_SIG_mirath_tcith_1a_short_length_signature 3182

OQS_SIG *OQS_SIG_mirath_tcith_1a_short_new(void);
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#endif /* OQS_ENABLE_SIG_mirath_tcith_1a_short */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OQS_SIG_MIRATH_H