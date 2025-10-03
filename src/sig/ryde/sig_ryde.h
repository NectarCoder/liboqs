/**
 * \file sig_ryde.h
 * \brief RYDE signature algorithm family
 *
 * RYDE is a digital signature scheme based on the hardness of the
 * Rank Syndrome Decoding problem. 
 * 
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_RYDE_H
#define OQS_SIG_RYDE_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ryde1f */

/** Algorithm identifier for ryde_1f */
#define OQS_SIG_alg_ryde_1f "RYDE-1F"

/** ryde_1f public key length, in bytes */
#define OQS_SIG_ryde_1f_length_public_key 69

/** ryde_1f secret key length, in bytes */
#define OQS_SIG_ryde_1f_length_secret_key 32

/** ryde_1f signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_ryde_1f_length_signature 3597

/**
 * \brief Process a ryde_1f key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (69 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (32 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1f_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for ryde_1f.
 *
 * \param[out] signature       Pointer to the buffer for the signature (3597 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 3597).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (32 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for ryde_1f.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (3597 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (69 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief ryde_1f signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_1f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief ryde_1f signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_1f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_ryde_1f)
/**
 * \brief OQS_SIG object for ryde_1f.
 */
OQS_SIG *OQS_SIG_ryde_1f_new(void);
#endif

/* ryde1s */

/** Algorithm identifier for ryde_1s */
#define OQS_SIG_alg_ryde_1s "RYDE-1S"

/** ryde_1s public key length, in bytes */
#define OQS_SIG_ryde_1s_length_public_key 69

/** ryde_1s secret key length, in bytes */
#define OQS_SIG_ryde_1s_length_secret_key 32

/** ryde_1s signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_ryde_1s_length_signature 3115

/**
 * \brief Process a ryde_1s key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (69 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (32 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1s_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for ryde_1s.
 *
 * \param[out] signature       Pointer to the buffer for the signature (3115 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 3115).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (32 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for ryde_1s.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (3115 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (69 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_1s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief ryde_1s signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_1s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief ryde_1s signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_1s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_ryde_1s)
/**
 * \brief OQS_SIG object for ryde_1s.
 */
OQS_SIG *OQS_SIG_ryde_1s_new(void);
#endif

/* ryde3s */

/** Algorithm identifier for ryde_3s */
#define OQS_SIG_alg_ryde_3s "RYDE-3S"

/** ryde_3s public key length, in bytes */
#define OQS_SIG_ryde_3s_length_public_key 101

/** ryde_3s secret key length, in bytes */
#define OQS_SIG_ryde_3s_length_secret_key 48

/** ryde_3s signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_ryde_3s_length_signature 7064

/**
 * \brief Process a ryde_3s key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (101 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (48 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_3s_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for ryde_3s.
 *
 * \param[out] signature       Pointer to the buffer for the signature (7064 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 7064).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (48 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_3s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for ryde_3s.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (7064 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (101 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde_3s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief ryde_3s signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_3s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief ryde_3s signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde_3s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_ryde_3s)
/**
 * \brief OQS_SIG object for ryde_3s.
 */
OQS_SIG *OQS_SIG_ryde_3s_new(void);
#endif

#ifdef __cplusplus
}
#endif

#endif