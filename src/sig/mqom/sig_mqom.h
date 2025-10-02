/**
 * \file sig_mqom.h
 * \brief MQOM signature algorithm family
 *
 * MQOM (Multivariate Quadratic Polynomial) is a post-quantum signature scheme
 * based on the hardness of solving systems of multivariate quadratic equations.
 *
 * \author liboqs team
 */

#ifndef OQS_SIG_MQOM_H
#define OQS_SIG_MQOM_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* mqom2-cat1-gf2-short-r3 */

/** Algorithm identifier for MQOM2_cat1_gf2_short_r3 */
#define OQS_SIG_alg_mqom2_cat1_gf2_short_r3 "MQOM2_cat1_gf2_short_r3"

/** mqom2-cat1-gf2-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_public_key 52

/** mqom2-cat1-gf2-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_secret_key 72

/** mqom2-cat1-gf2-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r3_length_signature 2868

/**
 * \brief Process a mqom2-cat1-gf2-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf2_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf2-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf2_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf2_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf2-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf2_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf2_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf2-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf2-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf2-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf2_short_r3_new(void);
#endif

/* mqom2-cat1-gf2-short-r5 */

/** Algorithm identifier for mqom2-cat1-gf2-short-r5 */
#define OQS_SIG_alg_mqom2_cat1_gf2_short_r5 "MQOM2-cat1-gf2-short-r5"

/** mqom2-cat1-gf2-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key 52

/** mqom2-cat1-gf2-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key 72

/** mqom2-cat1-gf2-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature 2820

/**
 * \brief Process a mqom2-cat1-gf2-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf2-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf2-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf2-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf2-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf2-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf2_short_r5_new(void);
#endif

/* mqom2-cat1-gf16-short-r3 */

/** Algorithm identifier for mqom2-cat1-gf16-short-r3 */
#define OQS_SIG_alg_mqom2_cat1_gf16_short_r3 "MQOM2-cat1-gf16-short-r3"

/** mqom2-cat1-gf16-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r3_length_public_key 60

/** mqom2-cat1-gf16-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r3_length_secret_key 88

/** mqom2-cat1-gf16-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r3_length_signature 3036

/**
 * \brief Process a mqom2-cat1-gf16-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf16_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf16-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf16_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf16_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf16-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf16_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf16_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf16-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf16-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf16_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf16-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf16_short_r3_new(void);
#endif




/* mqom2-cat1-gf16-short-r5 */

/** Algorithm identifier for mqom2-cat1-gf16-short-r5 */
#define OQS_SIG_alg_mqom2_cat1_gf16_short_r5 "mqom2-cat1-gf16-short-r5"

/** mqom2-cat1-gf16-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r5_length_public_key 60

/** mqom2-cat1-gf16-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r5_length_secret_key 80

/** mqom2-cat1-gf16-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf16_short_r5_length_signature 2916

/**
 * \brief Process a mqom2-cat1-gf16-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf16_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf16-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf16_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf16_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf16-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf16_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf16_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf16-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf16-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf16_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf16_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf16-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf16_short_r5_new(void);
#endif




/* mqom2-cat1-gf256-short-r3 */

/** Algorithm identifier for mqom2-cat1-gf256-short-r3 */
#define OQS_SIG_alg_mqom2_cat1_gf256_short_r3 "MQOM-cat1-gf256-short-r3"

/** mqom2-cat1-gf256-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r3_length_public_key 80

/** mqom2-cat1-gf256-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r3_length_secret_key 128

/** mqom2-cat1-gf256-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r3_length_signature 3540

/**
 * \brief Process a mqom2-cat1-gf256-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf256_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf256-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf256_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf256_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf256-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf256_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf256_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf256-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf256-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf256_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf256-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf256_short_r3_new(void);
#endif



/* mqom2-cat1-gf256-short-r5 */

/** Algorithm identifier for mqom2-cat1-gf256-short-r5 */
#define OQS_SIG_alg_mqom2_cat1_gf256_short_r5 "MQOM2-cat1-gf256-short-r5"

/** mqom2-cat1-gf256-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r5_length_public_key 80

/** mqom2-cat1-gf256-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r5_length_secret_key 128

/** mqom2-cat1-gf256-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat1_gf256_short_r5_length_signature 3156

/**
 * \brief Process a mqom2-cat1-gf256-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat1_gf256_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat1_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat1-gf256-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat1_gf256_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat1_gf256_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat1_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat1-gf256-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat1_gf256_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat1_gf256_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat1-gf256-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat1-gf256-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat1_gf256_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf256_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat1-gf256-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat1_gf256_short_r5_new(void);
#endif


/* mqom2-cat3-gf2-short-r3 */

/** Algorithm identifier for mqom2-cat3-gf2-short-r3 */
#define OQS_SIG_alg_mqom2_cat3_gf2_short_r3 "MQOM2-cat3-gf2-short-r3"

/** mqom2-cat3-gf2-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r3_length_public_key 78

/** mqom2-cat3-gf2-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r3_length_secret_key 108

/** mqom2-cat3-gf2-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r3_length_signature 6388

/**
 * \brief Process a mqom2-cat3-gf2-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf2_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf2-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf2_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf2_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf2-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf2_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf2_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf2-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf2-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf2_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf2-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf2_short_r3_new(void);
#endif


/* mqom2-cat3-gf2-short-r5 */

/** Algorithm identifier for mqom2-cat3-gf2-short-r5 */
#define OQS_SIG_alg_mqom2_cat3_gf2_short_r5 "MQOM2-cat3-gf2-short-r5"

/** mqom2-cat3-gf2-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r5_length_public_key 78

/** mqom2-cat3-gf2-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r5_length_secret_key 108

/** mqom2-cat3-gf2-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf2_short_r5_length_signature 6280

/**
 * \brief Process a mqom2-cat3-gf2-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf2_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf2-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf2_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf2_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf2-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf2_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf2_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf2-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf2-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf2_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf2_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf2-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf2_short_r5_new(void);
#endif


/* mqom2_cat3_gf16_short_r3 */

/** Algorithm identifier for mqom2-cat3-gf2-short-r5 */
#define OQS_SIG_alg_mqom2_cat3_gf16_short_r3 "MQOM2-cat3-gf16-short-r3"

/** mqom2-cat3-gf16-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r3_length_public_key 90

/** mqom2-cat3-gf16-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r3_length_secret_key 132

/** mqom2-cat3-gf16-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r3_length_signature 6820

/**
 * \brief Process a mqom2-cat3-gf16-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf16_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf16-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf16_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf16_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf16-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf16_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf16_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf16-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf16-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf16_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf16-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf16_short_r3_new(void);
#endif



/* mqom2_cat3_gf16_short_r5 */

/** Algorithm identifier for mqom2-cat3-gf16-short-r5 */
#define OQS_SIG_alg_mqom2_cat3_gf16_short_r5 "MQOM2-cat3-gf16-short-r5"

/** mqom2-cat3-gf16-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r5_length_public_key 90

/** mqom2-cat3-gf16-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r5_length_secret_key 132

/** mqom2-cat3-gf16-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf16_short_r5_length_signature 6496

/**
 * \brief Process a mqom2-cat3-gf16-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf16_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf16-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf16_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf16_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf16-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf16_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf16_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf16-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf16-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf16_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf16_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf16-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf16_short_r5_new(void);
#endif


/* mqom2_cat3_gf256_short_r3 */

/** Algorithm identifier for mqom2-cat3-gf256-short-r3 */
#define OQS_SIG_alg_mqom2_cat3_gf256_short_r3 "mqom2-cat3-gf256-short-r3"

/** mqom2-cat3-gf256-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r3_length_public_key 120

/** mqom2-cat3-gf256-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r3_length_secret_key 192

/** mqom2-cat3-gf256-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r3_length_signature 7900

/**
 * \brief Process a mqom2-cat3-gf256-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf256_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf256-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf256_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf256_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf256-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf256_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf256_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf256-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf256-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf256_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf256-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf256_short_r3_new(void);
#endif




/* mqom2_cat3_gf256_short_r5 */

/** Algorithm identifier for mqom2-cat3-gf256-short-r5 */
#define OQS_SIG_alg_mqom2_cat3_gf256_short_r5 "mqom2-cat3-gf256-short-r5"

/** mqom2-cat3-gf256-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r5_length_public_key 120

/** mqom2-cat3-gf256-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r5_length_secret_key 192

/** mqom2-cat3-gf256-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat3_gf256_short_r5_length_signature 7036

/**
 * \brief Process a mqom2-cat3-gf256-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat3_gf256_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat3_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat3-gf256-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat3_gf256_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat3_gf256_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat3_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat3-gf256-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat3_gf256_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat3_gf256_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat3-gf256-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat3-gf256-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat3_gf256_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat3_gf256_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat3-gf256-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat3_gf256_short_r5_new(void);
#endif


/* mqom2_cat5_gf2_short_r3 */

/** Algorithm identifier for mqom2-cat5-gf2-short-r3 */
#define OQS_SIG_alg_mqom2_cat5_gf2_short_r3 "mqom2-cat5-gf2-short-r3"

/** mqom2-cat5-gf2-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_public_key 104

/** mqom2-cat5-gf2-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key 144

/** mqom2-cat5-gf2-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_signature 11764

/**
 * \brief Process a mqom2-cat5-gf2-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf2_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf2-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf2_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf2_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf2-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf2_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf2_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf2-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf2-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf2_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf2-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf2_short_r3_new(void);
#endif




/* mqom2-cat5-gf2-short-r5 */

/** Algorithm identifier for mqom2-cat5-gf2-short-r5 */
#define OQS_SIG_alg_mqom2_cat5_gf2_short_r5 "mqom2-cat5-gf2-short-r5"

/** mqom2-cat5-gf2-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r5_length_public_key 104

/** mqom2-cat5-gf2-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key 144

/** mqom2-cat5-gf2-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r5_length_signature 11564

/**
 * \brief Process a mqom2-cat5-gf2-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf2_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf2-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf2_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf2_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf2_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf2-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf2_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf2_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf2-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf2-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf2_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf2_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf2-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf2_short_r5_new(void);
#endif





/* mqom2-cat5-gf16-short-r3 */

/** Algorithm identifier for mqom2-cat5-gf16-short-r3 */
#define OQS_SIG_alg_mqom2_cat5_gf16_short_r3 "mqom2-cat5-gf16-short-r3"

/** mqom2-cat5-gf16-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf16_short_r3_length_public_key 122

/** mqom2-cat5-gf16-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key 180

/** mqom2-cat5-gf16-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf16_short_r3_length_signature 12664

/**
 * \brief Process a mqom2-cat5-gf16-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf16_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf16-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf16_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf16_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf16_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf16-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf16_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf16_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf16-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf16-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf16_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf16-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf16_short_r3_new(void);
#endif



/* mqom2-cat5-gf16-short-r5 */

/** Algorithm identifier for mqom2-cat5-gf16-short-r5 */
#define OQS_SIG_alg_mqom2_cat5_gf16_short_r5 "mqom2-cat5-gf16-short-r5"

/** mqom2-cat5-gf16-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf16_short_r5_length_public_key 122

/** mqom2-cat5-gf16-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf16_short_r5_length_secret_key 180

/** mqom2-cat5-gf16-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf16_short_r5_length_signature 12014

/**
 * \brief Process a mqom2-cat5-gf16-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf16_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf16-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf16_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf16_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf16_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf16-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf16_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf16_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf16-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf16-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf16_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf16_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf16-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf16_short_r5_new(void);
#endif



/* mqom2-cat5-gf256-short-r3 */

/** Algorithm identifier for mqom2-cat5-gf256-short-r3 */
#define OQS_SIG_alg_mqom2_cat5_gf256_short_r3 "mqom2-cat5-gf256-short-r3"

/** mqom2-cat5-gf256-short-r3 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf256_short_r3_length_public_key 160

/** mqom2-cat5-gf256-short-r3 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key 256

/** mqom2-cat5-gf256-short-r3 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf256_short_r3_length_signature 14564

/**
 * \brief Process a mqom2-cat5-gf256-short-r3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf256_short_r3_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf256-short-r3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf256_short_r3_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf256_short_r3_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf256_short_r3_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf256-short-r3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf256_short_r3_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf256_short_r3_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf256-short-r3 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf256-short-r3 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf256_short_r3)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf256-short-r3.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf256_short_r3_new(void);
#endif



/* mqom2-cat5-gf256-short-r5 */

/** Algorithm identifier for mqom2-cat5-gf256-short-r5 */
#define OQS_SIG_alg_mqom2_cat5_gf256_short_r5 "mqom2-cat5-gf256-short-r5"

/** mqom2-cat5-gf256-short-r5 public key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf256_short_r5_length_public_key 160

/** mqom2-cat5-gf256-short-r5 secret key length, in bytes */
#define OQS_SIG_mqom2_cat5_gf2_short_r3_length_secret_key 256

/** mqom2-cat5-gf256-short-r5 signature length, in bytes */
#define OQS_SIG_mqom2_cat5_gf256_short_r5_length_signature 12964

/**
 * \brief Process a mqom2-cat5-gf256-short-r5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (OQS_SIG_mqom2_cat5_gf256_short_r5_length_public_key bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (OQS_SIG_mqom2_cat5_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for mqom2-cat5-gf256-short-r5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (OQS_SIG_mqom2_cat5_gf256_short_r5_length_signature bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always OQS_SIG_mqom2_cat5_gf256_short_r5_length_signature).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (OQS_SIG_mqom2_cat5_gf256_short_r5_length_secret_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for mqom2-cat5-gf256-short-r5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (OQS_SIG_mqom2_cat5_gf256_short_r5_length_signature bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (OQS_SIG_mqom2_cat5_gf256_short_r5_length_public_key bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief mqom2-cat5-gf256-short-r5 signature generation with context string.
 *
 * \param[out] signature         Pointer to the output signature buffer.
 * \param[out] signature_len     Pointer to the length of the signature.
 * \param[in]  message           Pointer to the message to be signed.
 * \param[in]  message_len       Length of the message.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  secret_key        Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief mqom2-cat5-gf256-short-r5 signature verification with context string.
 *
 * \param[in]  message           Pointer to the message.
 * \param[in]  message_len       Length of the message.
 * \param[in]  signature         Pointer to the signature.
 * \param[in]  signature_len     Length of the signature.
 * \param[in]  ctx_str           Pointer to the context string.
 * \param[in]  ctx_str_len       Length of the context string.
 * \param[in]  public_key        Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mqom2_cat5_gf256_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mqom2_cat5_gf256_short_r5)
/**
 * \brief OQS_SIG object for mqom2-cat5-gf256-short-r5.
 */
OQS_SIG *OQS_SIG_mqom2_cat5_gf256_short_r5_new(void);
#endif


#ifdef __cplusplus
}
#endif

#endif