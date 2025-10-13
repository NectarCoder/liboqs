// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_LESS_H
#define OQS_SIG_LESS_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_less_LESS_252_192)
#define OQS_SIG_less_LESS_252_192_length_public_key 48384
#define OQS_SIG_less_LESS_252_192_length_secret_key 48
#define OQS_SIG_less_LESS_252_192_length_signature 12352

OQS_SIG *OQS_SIG_less_LESS_252_192_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_192_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_192_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_192_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_192_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_252_68)
#define OQS_SIG_less_LESS_252_68_length_public_key 16128
#define OQS_SIG_less_LESS_252_68_length_secret_key 48
#define OQS_SIG_less_LESS_252_68_length_signature 4112

OQS_SIG *OQS_SIG_less_LESS_252_68_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_68_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_68_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_68_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_68_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_68_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_252_45)
#define OQS_SIG_less_LESS_252_45_length_public_key 10816
#define OQS_SIG_less_LESS_252_45_length_secret_key 48
#define OQS_SIG_less_LESS_252_45_length_signature 2752

OQS_SIG *OQS_SIG_less_LESS_252_45_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_45_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_45_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_45_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_45_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_252_45_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_400_220)
#define OQS_SIG_less_LESS_400_220_length_public_key 88000
#define OQS_SIG_less_LESS_400_220_length_secret_key 48
#define OQS_SIG_less_LESS_400_220_length_signature 22400

OQS_SIG *OQS_SIG_less_LESS_400_220_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_220_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_220_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_220_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_220_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_220_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_400_102)
#define OQS_SIG_less_LESS_400_102_length_public_key 40800
#define OQS_SIG_less_LESS_400_102_length_secret_key 48
#define OQS_SIG_less_LESS_400_102_length_signature 10400

OQS_SIG *OQS_SIG_less_LESS_400_102_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_102_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_102_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_102_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_102_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_400_102_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_548_345)
#define OQS_SIG_less_LESS_548_345_length_public_key 189420
#define OQS_SIG_less_LESS_548_345_length_secret_key 48
#define OQS_SIG_less_LESS_548_345_length_signature 48320

OQS_SIG *OQS_SIG_less_LESS_548_345_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_345_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_345_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_345_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_345_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_345_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_LESS_548_137)
#define OQS_SIG_less_LESS_548_137_length_public_key 75176
#define OQS_SIG_less_LESS_548_137_length_secret_key 48
#define OQS_SIG_less_LESS_548_137_length_signature 19184

OQS_SIG *OQS_SIG_less_LESS_548_137_new(void);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_137_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_137_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_137_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_137_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_LESS_548_137_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#endif