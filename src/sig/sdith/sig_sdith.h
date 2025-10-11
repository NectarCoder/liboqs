/**
 * \file sig_sdith.h
 * \brief SDitH signature algorithm family

 * SDitH is a post-quantum digital signature scheme based on
 * syndrome decoding with iterative trapdoor hiding.
 *
 * \author liboqs team
 */

#ifndef OQS_SIG_SDITH_H
#define OQS_SIG_SDITH_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* sdith_cat1_short */

/** Algorithm identifier for SDitH-CAT1-SHORT */
#define OQS_SIG_alg_sdith_cat1_short "SDitH-CAT1-SHORT"

/** SDitH-CAT1-SHORT public key length, in bytes */
#define OQS_SIG_sdith_cat1_short_length_public_key 70

/** SDitH-CAT1-SHORT secret key length, in bytes */
#define OQS_SIG_sdith_cat1_short_length_secret_key 163

/** SDitH-CAT1-SHORT signature length, in bytes */
#define OQS_SIG_sdith_cat1_short_length_signature 3705

/**
 * \brief Process a SDitH-CAT1-SHORT key pair.
 *
 * \param[out] public_key Pointer to the buffer for the public key (70 bytes).
 * \param[out] secret_key Pointer to the buffer for the secret key (163 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sdith_cat1_short_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for SDitH-CAT1-SHORT.
 *
 * \param[out] signature Pointer to the buffer for the signature (3705 bytes).
 * \param[out] signature_len Pointer to the length of the signature (always 3705).
 * \param[in] message Pointer to the message to be signed.
 * \param[in] message_len Length of the message to be signed.
 * \param[in] secret_key Pointer to the secret key (163 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sdith_cat1_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for SDitH-CAT1-SHORT.
 *
 * \param[in] message Pointer to the message.
 * \param[in] message_len Length of the message.
 * \param[in] signature Pointer to the signature (3705 bytes).
 * \param[in] signature_len Length of the signature.
 * \param[in] public_key Pointer to the public key (70 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sdith_cat1_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief SDitH-CAT1-SHORT signature generation with context string.
 *
 * \param[out] signature Pointer to the output signature buffer.
 * \param[out] signature_len Pointer to the length of the signature.
 * \param[in] message Pointer to the message to be signed.
 * \param[in] message_len Length of the message.
 * \param[in] ctx_str Pointer to the context string.
 * \param[in] ctx_str_len Length of the context string.
 * \param[in] secret_key Pointer to the secret key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sdith_cat1_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief SDitH-CAT1-SHORT signature verification with context string.
 *
 * \param[in] message Pointer to the message.
 * \param[in] message_len Length of the message.
 * \param[in] signature Pointer to the signature.
 * \param[in] signature_len Length of the signature.
 * \param[in] ctx_str Pointer to the context string.
 * \param[in] ctx_str_len Length of the context string.
 * \param[in] public_key Pointer to the public key.
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sdith_cat1_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_sdith_cat1_short)
/**
 * \brief OQS_SIG object for SDitH-CAT1-SHORT.
 */
OQS_SIG *OQS_SIG_sdith_cat1_short_new(void);
#endif

/* sdith_cat3_short */

/** Algorithm identifier for SDitH-CAT3-SHORT */
#define OQS_SIG_alg_sdith_cat3_short "SDitH-CAT3-SHORT"

/** SDitH-CAT3-SHORT public key length, in bytes */
#define OQS_SIG_sdith_cat3_short_length_public_key 98

/** SDitH-CAT3-SHORT secret key length, in bytes */
#define OQS_SIG_sdith_cat3_short_length_secret_key 232

/** SDitH-CAT3-SHORT signature length, in bytes */
#define OQS_SIG_sdith_cat3_short_length_signature 7964

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_keypair(uint8_t *public_key, uint8_t *secret_key);

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_sdith_cat3_short)
OQS_SIG *OQS_SIG_sdith_cat3_short_new(void);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OQS_SIG_SDITH_H
