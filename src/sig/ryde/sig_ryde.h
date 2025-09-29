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

/** Algorithm identifier for ryde1f */
#define OQS_SIG_alg_ryde1f "RYDE-1F"

/** ryde1f public key length, in bytes */
#define OQS_SIG_ryde1f_length_public_key 69

/** ryde1f secret key length, in bytes */
#define OQS_SIG_ryde1f_length_secret_key 32

/** ryde1f signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_ryde1f_length_signature 3597

/**
 * \brief Process a ryde1f key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (69 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (32 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde1f_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for ryde1f.
 *
 * \param[out] signature       Pointer to the buffer for the signature (3597 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 3597).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde1f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for ryde1f.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (3597 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_ryde1f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief ryde1f signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde1f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief ryde1f signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_ryde1f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_ryde_1f)
/**
 * \brief OQS_SIG object for ryde1f.
 */
OQS_SIG *OQS_SIG_ryde1f_new(void);
#endif

#ifdef __cplusplus
}
#endif

#endif