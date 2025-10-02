/**
 * \file sig_qr_uov.h
 * \brief QR-UOV signature algorithm family
 *
 * The QR-UOV signature scheme is a digital signature scheme based on the
 * Unbalanced Oil and Vinegar (UOV) problem, which is a hard problem in
 * multivariate polynomial equations.
 *
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_QR_UOV_H
#define OQS_SIG_QR_UOV_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Algorithm identifier for qr_uov_s */
#define OQS_SIG_alg_qr_uov_s "qr_uov_s"

/** qr_uov_s public key length, in bytes */
#define OQS_SIG_qr_uov_s_length_public_key 32

/** qr_uov_s secret key length, in bytes */
#define OQS_SIG_qr_uov_s_length_secret_key 32

/** qr_uov_s signature length, in bytes */
#define OQS_SIG_qr_uov_s_length_signature 4506

/**
 * \brief Process a qr_uov_s key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (148 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_qr_uov_s_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for qr_uov_s.
 *
 * \param[out] signature       Pointer to the buffer for the signature (8345 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 8345).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (164 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_qr_uov_s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for qr_uov_s.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (8345 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (148 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_qr_uov_s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief qr_uov_s signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_qr_uov_s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief qr_uov_s signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_qr_uov_s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_qr_uov_s)
/**
 * \brief OQS_SIG object for qr_uov_s.
 */
OQS_SIG *OQS_SIG_qr_uov_s_new(void);
#endif

////////////////////////////////////////////////////////////////////////////////



#ifdef __cplusplus
}
#endif

#endif