/**
 * \file sig_faest.h
 * \brief FAEST signature algorithm family
 *
 * Fast and Efficient Signature Scheme based on Trapdoor Functions (FAEST) is a digital signature scheme
 * designed for high performance and security.
 *
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_FAEST_H
#define OQS_SIG_FAEST_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif


/** Algorithm identifier for faest_128s */
#define OQS_SIG_alg_faest_128s "faest_128s"

/** faest_128s public key length, in bytes */
#define OQS_SIG_faest_128s_length_public_key 148

/** faest_128s secret key length, in bytes */
#define OQS_SIG_faest_128s_length_secret_key 164

/** faest_128s signature length, in bytes */
#define OQS_SIG_faest_128s_length_signature 8345

/**
 * \brief Process a faest_128s key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_faest_128s_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for faest_128s.
 *
 * \param[out] signature       Pointer to the buffer for the signature (8345 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 8345).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_faest_128s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for faest_128s.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (8345 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_faest_128s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief faest_128s signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_faest_128s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief faest_128s signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_faest_128s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_faest_128s)
/**
 * \brief OQS_SIG object for faest_128s.
 */
OQS_SIG *OQS_SIG_faest_128s_new(void);
#endif

/* todo: Implement context string support for SDITH-short-3*/

/* todo: Implement context string support for SDITH-short-5*/



#ifdef __cplusplus
}
#endif

#endif