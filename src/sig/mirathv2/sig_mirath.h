/**
 * \file sig_mirath.h
 * \brief MIRATH signature algorithm family
 *
 * MIRATH is a post-quantum signature scheme
 * based on lattice isomorphism problem.
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_MIRATH_H
#define OQS_SIG_MIRATH_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* mirath_tcith_1a_short */

/** Algorithm identifier for Mirath_tcith_1a_short */
#define OQS_SIG_alg_mirath_tcith_1a_short "Mirath-1a-short"

/** Mirath_1a_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_1a_short_length_public_key 73

/** Mirath_1a_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_1a_short_length_secret_key 32

/** Mirath_1a_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_1a_short_length_signature 3182

/**
 * \brief Process a Mirath_1a_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_1a_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_1a_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_1a_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_1a_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1a_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_1a_short)
/**
 * \brief OQS_SIG object for Mirath_1a_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_1a_short_new(void);
#endif


/* mirath_tcith_1b_short */

/** Algorithm identifier for Mirath_tcith_1b_short */
#define OQS_SIG_alg_mirath_tcith_1b_short "Mirath-1b-short"

/** Mirath_1b_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_1b_short_length_public_key 57

/** Mirath_tcith_1b_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_1b_short_length_secret_key 32

/** Mirath_tcith_1b_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_1b_short_length_signature 2990

/**
 * \brief Process a Mirath_tcith_1b_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_tcith_1b_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_tcith_1b_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_tcith_1b_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_tcith_1b_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_1b_short)
/**
 * \brief OQS_SIG object for Mirath_tcith_1b_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_1b_short_new(void);
#endif


/* mirath_tcith_3a_short */

/** Algorithm identifier for Mirath_tcith_3a_short */
#define OQS_SIG_alg_mirath_tcith_3a_short "Mirath-3a-short"

/** Mirath_3a_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_3a_short_length_public_key 107

/** Mirath_3a_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_3a_short_length_secret_key 48

/** Mirath_3a_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_3a_short_length_signature 7456

/**
 * \brief Process a Mirath_3a_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3a_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_3a_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3a_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_3a_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3a_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_3a_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3a_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_3a_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3a_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_3a_short)
/**
 * \brief OQS_SIG object for Mirath_3a_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_3a_short_new(void);
#endif

//////////////////////////////
/* mirath_tcith_3b_short */

/** Algorithm identifier for Mirath_tcith_3b_short */
#define OQS_SIG_alg_mirath_tcith_3b_short "Mirath-3b-short"

/** Mirath_3a_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_3b_short_length_public_key 84

/** Mirath_3a_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_3b_short_length_secret_key 48

/** Mirath_3a_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_3b_short_length_signature 6925

/**
 * \brief Process a Mirath_3a_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3b_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_3a_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3b_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_3a_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3b_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_3a_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3b_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_3a_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_3b_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_3b_short)
/**
 * \brief OQS_SIG object for Mirath_3a_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_3b_short_new(void);
#endif
////////////////////////////

/* mirath_tcith_5a_short */

/** Algorithm identifier for Mirath_tcith_5a_short */
#define OQS_SIG_alg_mirath_tcith_5a_short "Mirath-5a-short"

/** Mirath_3a_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_5a_short_length_public_key 147

/** Mirath_3a_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_5a_short_length_secret_key 64

/** Mirath_3a_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_5a_short_length_signature 13091

/**
 * \brief Process a Mirath_3a_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5a_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_3a_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5a_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_3a_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5a_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_3a_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5a_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_3a_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5a_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_5a_short)
/**
 * \brief OQS_SIG object for Mirath_3a_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_5a_short_new(void);
#endif
///////////////////////////////


/* mirath_tcith_5b_short */

/** Algorithm identifier for Mirath_tcith_5b_short */
#define OQS_SIG_alg_mirath_tcith_5b_short "Mirath-5b-short"

/** Mirath_3a_short public key length, in bytes */
#define OQS_SIG_mirath_tcith_5b_short_length_public_key 112

/** Mirath_3a_short secret key length, in bytes */
#define OQS_SIG_mirath_tcith_5b_short_length_secret_key 64

/** Mirath_3a_short signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_mirath_tcith_5b_short_length_signature 12229

/**
 * \brief Process a Mirath_3a_short key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5b_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Mirath_3a_short.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5b_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Mirath_3a_short.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5b_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Mirath_3a_short signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5b_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Mirath_3a_short signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_mirath_tcith_5b_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_mirath_tcith_5b_short)
/**
 * \brief OQS_SIG object for Mirath_3a_short.
 */
OQS_SIG *OQS_SIG_mirath_tcith_5b_short_new(void);
#endif



#ifdef __cplusplus
}
#endif

#endif