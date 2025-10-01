/**
 * \file sig_perk.h
 * \brief PERK signature algorithm family
 *
 * PERK (Permuted Equations and Random Keys) is a post-quantum signature scheme
 * based on the hardness of solving systems of permuted equations.
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_PERK_H
#define OQS_SIG_PERK_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* perk-128-fast-3 */

/** Algorithm identifier for PERK-128-fast-3 */
#define OQS_SIG_alg_perk_128_fast_3 "PERK-128-fast-3"

/** PERK-128-fast-3 public key length, in bytes */
#define OQS_SIG_perk_128_fast_3_length_public_key 148

/** PERK-128-fast-3 secret key length, in bytes */
#define OQS_SIG_perk_128_fast_3_length_secret_key 164

/** PERK-128-fast-3 signature length, in bytes */
#define OQS_SIG_perk_128_fast_3_length_signature 8345

/**
 * \brief Process a PERK-128-fast-3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-128-fast-3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (8345 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 8345).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-128-fast-3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (8345 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-128-fast-3 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-128-fast-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_128_fast_3)
/**
 * \brief OQS_SIG object for PERK-128-fast-3.
 */
OQS_SIG *OQS_SIG_perk_128_fast_3_new(void);
#endif

/* perk-128-short-3 */

/** Algorithm identifier for PERK-128-short-3 */
#define OQS_SIG_alg_perk_128_short_3 "PERK-128-short-3"

/** PERK-128-short-3 public key length, in bytes */
#define OQS_SIG_perk_128_short_3_length_public_key 148

/** PERK-128-short-3 secret key length, in bytes */
#define OQS_SIG_perk_128_short_3_length_secret_key 164

/** PERK-128-short-3 signature length, in bytes */
#define OQS_SIG_perk_128_short_3_length_signature 6251

/**
 * \brief Process a PERK-128-short-3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-128-short-3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-128-short-3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-128-short-3 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_short_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-128-short-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_short_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_128_short_3)
/**
 * \brief OQS_SIG object for PERK-128-short-3.
 */
OQS_SIG *OQS_SIG_perk_128_short_3_new(void);
#endif

/* perk-128-short-5 */

/** Algorithm identifier for PERK-128-short-5 */
#define OQS_SIG_alg_perk_128_short_5 "PERK-128-short-5"

/** PERK-128-short-5 public key length, in bytes */
#define OQS_SIG_perk_128_short_5_length_public_key 241

/** PERK-128-short-5 secret key length, in bytes */
#define OQS_SIG_perk_128_short_5_length_secret_key 257

/** PERK-128-short-5 signature length, in bytes */
#define OQS_SIG_perk_128_short_5_length_signature 5780

/**
 * \brief Process a PERK-128-short-5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-128-short-5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-128-short-5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_short_5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-128-short-5 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_short_5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-128-short-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_128_short_5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_128_short_5)
/**
 * \brief OQS_SIG object for PERK-128-short-5.
 */
OQS_SIG *OQS_SIG_perk_128_short_5_new(void);
#endif




/* perk-192-short-3 */

/** Algorithm identifier for PERK-192-short-3 */
#define OQS_SIG_alg_perk_192_short_3 "PERK-192-short-3"

/** PERK-192-short-3 public key length, in bytes */
#define OQS_SIG_perk_192_short_3_length_public_key 227

/** PERK-192-short-3 secret key length, in bytes */
#define OQS_SIG_perk_192_short_3_length_secret_key 251

/** PERK-192-short-3 signature length, in bytes */
#define OQS_SIG_perk_192_short_3_length_signature 14280

/**
 * \brief Process a PERK-192-short-3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-192-short-3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-192-short-3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-192-short-3 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_192_short_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-128-short-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_192_short_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_192_short_3)
/**
 * \brief OQS_SIG object for PERK-192-short-3.
 */
OQS_SIG *OQS_SIG_perk_192_short_3_new(void);
#endif




/* perk-192-short-5 */

/** Algorithm identifier for PERK-192-short-5 */
#define OQS_SIG_alg_perk_192_short_5 "PERK-192-short-5"

/** PERK-192-short-5 public key length, in bytes */
#define OQS_SIG_perk_192_short_5_length_public_key 386

/** PERK-192-short-5 secret key length, in bytes */
#define OQS_SIG_perk_192_short_5_length_secret_key 392

/** PERK-192-short-5 signature length, in bytes */
#define OQS_SIG_perk_192_short_5_length_signature 13164

/**
 * \brief Process a PERK-192-short-5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-192-short-5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-192-short-5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_192_short_5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-192-short-5 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_192_short_5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-128-short-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_192_short_5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_192_short_5)
/**
 * \brief OQS_SIG object for PERK-192-short-5.
 */
OQS_SIG *OQS_SIG_perk_192_short_5_new(void);
#endif



/* perk-256-short-3 */

/** Algorithm identifier for PERK-256-short-3 */
#define OQS_SIG_alg_perk_256_short_3 "PERK-256-short-3"

/** PERK-256-short-3 public key length, in bytes */
#define OQS_SIG_perk_256_short_3_length_public_key 594

/** PERK-256-short-3 secret key length, in bytes */
#define OQS_SIG_perk_256_short_3_length_secret_key 626

/** PERK-256-short-3 signature length, in bytes */
#define OQS_SIG_perk_256_short_3_length_signature 30317

/**
 * \brief Process a PERK-256-short-3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-256-short-3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-256-short-3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-256-short-3 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_256_short_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-256-short-3 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_256_short_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_256_short_3)
/**
 * \brief OQS_SIG object for PERK-256-short-3.
 */
OQS_SIG *OQS_SIG_perk_256_short_3_new(void);
#endif


/* perk-256-short-5 */

/** Algorithm identifier for PERK-256-short-5 */
#define OQS_SIG_alg_perk_256_short_5 "PERK-256-short-5"

/** PERK-256-short-5 public key length, in bytes */
#define OQS_SIG_perk_256_short_5_length_public_key 507

/** PERK-256-short-3 secret key length, in bytes */
#define OQS_SIG_perk_256_short_5_length_secret_key 539

/** PERK-256-short-3 signature length, in bytes */
#define OQS_SIG_perk_256_short_5_length_signature 23040

/**
 * \brief Process a PERK-256-short-5 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_5_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-256-short-5.
 *
 * \param[out] signature       Pointer to the buffer for the signature (6251 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 6251).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-256-short-5.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (6251 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_256_short_5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief PERK-256-short-3 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_256_short_5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief PERK-256-short-5 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_perk_256_short_5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_256_short_5)
/**
 * \brief OQS_SIG object for PERK-256-short-5.
 */
OQS_SIG *OQS_SIG_perk_256_short_5_new(void);
#endif



#ifdef __cplusplus
}
#endif

#endif