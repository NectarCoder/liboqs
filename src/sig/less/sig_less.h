// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_LESS_H
#define OQS_SIG_LESS_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_less_252_192)
#define OQS_SIG_less_252_192_length_public_key 13940
#define OQS_SIG_less_252_192_length_secret_key 32
#define OQS_SIG_less_252_192_length_signature 2625

OQS_SIG *OQS_SIG_less_252_192_new(void);
OQS_API OQS_STATUS OQS_SIG_less_252_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_192_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_192_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_252_192_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_192_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_252_68)
#define OQS_SIG_less_252_68_length_public_key 41788
#define OQS_SIG_less_252_68_length_secret_key 32
#define OQS_SIG_less_252_68_length_signature 1825

OQS_SIG *OQS_SIG_less_252_68_new(void);
OQS_API OQS_STATUS OQS_SIG_less_252_68_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_68_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_68_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_252_68_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_68_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_252_45)
#define OQS_SIG_less_252_45_length_public_key 97484
#define OQS_SIG_less_252_45_length_secret_key 32
#define OQS_SIG_less_252_45_length_signature 1329

OQS_SIG *OQS_SIG_less_252_45_new(void);
OQS_API OQS_STATUS OQS_SIG_less_252_45_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_45_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_45_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_252_45_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_252_45_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_400_220)
#define OQS_SIG_less_400_220_length_public_key 35074
#define OQS_SIG_less_400_220_length_secret_key 48
#define OQS_SIG_less_400_220_length_signature 6329

OQS_SIG *OQS_SIG_less_400_220_new(void);
OQS_API OQS_STATUS OQS_SIG_less_400_220_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_220_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_220_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_400_220_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_220_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_400_102)
#define OQS_SIG_less_400_102_length_public_key 105174
#define OQS_SIG_less_400_102_length_secret_key 48
#define OQS_SIG_less_400_102_length_signature 4131

OQS_SIG *OQS_SIG_less_400_102_new(void);
OQS_API OQS_STATUS OQS_SIG_less_400_102_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_102_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_102_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_400_102_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_400_102_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_548_345)
#define OQS_SIG_less_548_345_length_public_key 65793
#define OQS_SIG_less_548_345_length_secret_key 64
#define OQS_SIG_less_548_345_length_signature 10680

OQS_SIG *OQS_SIG_less_548_345_new(void);
OQS_API OQS_STATUS OQS_SIG_less_548_345_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_345_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_345_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_548_345_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_345_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_less_548_137)
#define OQS_SIG_less_548_137_length_public_key 197315
#define OQS_SIG_less_548_137_length_secret_key 64
#define OQS_SIG_less_548_137_length_signature 7436

OQS_SIG *OQS_SIG_less_548_137_new(void);
OQS_API OQS_STATUS OQS_SIG_less_548_137_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_137_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_137_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_less_548_137_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_less_548_137_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx, size_t ctxlen, const uint8_t *public_key);
#endif

#endif /* OQS_SIG_LESS_H */
