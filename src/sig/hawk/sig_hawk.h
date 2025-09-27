/**
 * \file sig_hawk.h
 * \brief HAWK signature algorithm family
 *
 * Hawk is a post-quantum signature scheme
 * based on lattice isomorphism problem.
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_HAWK_H
#define OQS_SIG_HAWK_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* hawk_512 */

/** Algorithm identifier for Hawk-512 */
#define OQS_SIG_alg_hawk_512 "Hawk-512"

/** Hawk-512 public key length, in bytes */
#define OQS_SIG_hawk_512_length_public_key 1024

/** Hawk-512 secret key length, in bytes */
#define OQS_SIG_hawk_512_length_secret_key 184

/** Hawk-512 signature length, in bytes (maximum size for signed message) */
#define OQS_SIG_hawk_512_length_signature 8365

/**
 * \brief Process a Hawk-512 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_hawk_512_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for Hawk-512.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_hawk_512_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for Hawk-512.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_hawk_512_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Hawk-512 signature generation with context string.
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
OQS_API OQS_STATUS OQS_SIG_hawk_512_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Hawk-512 signature verification with context string.
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
OQS_API OQS_STATUS OQS_SIG_hawk_512_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_hawk_512)
/**
 * \brief OQS_SIG object for Hawk-512.
 */
OQS_SIG *OQS_SIG_hawk_512_new(void);
#endif

#ifdef __cplusplus
}
#endif

#endif