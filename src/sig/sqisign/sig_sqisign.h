/**
 * \file sig_sqisign.h
 * \brief SQIsign signature algorithm family
 *
 * SQIsign is a digital signature scheme based on isogenies between
 * supersingular elliptic curves.
 * 
 * \author liboqs team
 */

#ifndef OQS_SIG_SQISIGN_H
#define OQS_SIG_SQISIGN_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SQIsign-353 (NIST Level 1) */

/** Algorithm identifier for SQIsign-353 */
#define OQS_SIG_alg_sqisign_353 "SQIsign-353"

/** SQIsign-353 public key length, in bytes */
#define OQS_SIG_sqisign_353_length_public_key 65

/** SQIsign-353 secret key length, in bytes */
#define OQS_SIG_sqisign_353_length_secret_key 353

/** SQIsign-353 signature length, in bytes */
#define OQS_SIG_sqisign_353_length_signature 148

/**
 * \brief Process a SQIsign-353 key pair.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (65 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (353 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_353_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for SQIsign-353.
 *
 * \param[out] signature       Pointer to the buffer for the signature (148 bytes).
 * \param[out] signature_len   Pointer to the length of the signature.
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (353 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_353_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for SQIsign-353.
 *
 * \param[in]  message         Pointer to the message.
 * \param[in]  message_len     Length of the message.
 * \param[in]  signature       Pointer to the signature (148 bytes).
 * \param[in]  signature_len   Length of the signature.
 * \param[in]  public_key      Pointer to the public key (65 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_353_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/* SQIsign-529 (NIST Level 3) */

/** Algorithm identifier for SQIsign-529 */
#define OQS_SIG_alg_sqisign_529 "SQIsign-529"

/** SQIsign-529 public key length, in bytes */
#define OQS_SIG_sqisign_529_length_public_key 97

/** SQIsign-529 secret key length, in bytes */
#define OQS_SIG_sqisign_529_length_secret_key 529

/** SQIsign-529 signature length, in bytes */
#define OQS_SIG_sqisign_529_length_signature 224

/**
 * \brief Process a SQIsign-529 key pair.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (97 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (529 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_529_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for SQIsign-529.
 *
 * \param[out] signature       Pointer to the buffer for the signature (224 bytes).
 * \param[out] signature_len   Pointer to the length of the signature.
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (529 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_529_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for SQIsign-529.
 *
 * \param[in]  message         Pointer to the message.
 * \param[in]  message_len     Length of the message.
 * \param[in]  signature       Pointer to the signature (224 bytes).
 * \param[in]  signature_len   Length of the signature.
 * \param[in]  public_key      Pointer to the public key (97 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_529_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/* SQIsign-701 (NIST Level 5) */

/** Algorithm identifier for SQIsign-701 */
#define OQS_SIG_alg_sqisign_701 "SQIsign-701"

/** SQIsign-701 public key length, in bytes */
#define OQS_SIG_sqisign_701_length_public_key 129

/** SQIsign-701 secret key length, in bytes */
#define OQS_SIG_sqisign_701_length_secret_key 701

/** SQIsign-701 signature length, in bytes */
#define OQS_SIG_sqisign_701_length_signature 292

/**
 * \brief Process a SQIsign-701 key pair.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (129 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (701 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_701_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for SQIsign-701.
 *
 * \param[out] signature       Pointer to the buffer for the signature (292 bytes).
 * \param[out] signature_len   Pointer to the length of the signature.
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (701 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for SQIsign-701.
 *
 * \param[in]  message         Pointer to the message.
 * \param[in]  message_len     Length of the message.
 * \param[in]  signature       Pointer to the signature (292 bytes).
 * \param[in]  signature_len   Length of the signature.
 * \param[in]  public_key      Pointer to the public key (129 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/* OQS_SIG API wrappers */

#if defined(OQS_ENABLE_SIG_sqisign_353)
OQS_SIG *OQS_SIG_sqisign_353_new(void);
#endif

#if defined(OQS_ENABLE_SIG_sqisign_529)
OQS_SIG *OQS_SIG_sqisign_529_new(void);
#endif

#if defined(OQS_ENABLE_SIG_sqisign_701)
OQS_SIG *OQS_SIG_sqisign_701_new(void);
#endif

#ifdef __cplusplus
}
#endif

#endif // OQS_SIG_SQISIGN_H
