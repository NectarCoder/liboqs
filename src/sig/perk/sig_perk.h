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
#define OQS_SIG_perk_128_fast_3_length_public_key 64

/** PERK-128-fast-3 secret key length, in bytes */
#define OQS_SIG_perk_128_fast_3_length_secret_key 80

/** PERK-128-fast-3 signature length, in bytes */
#define OQS_SIG_perk_128_fast_3_length_signature 5444

/**
 * \brief Process a PERK-128-fast-3 key pair.
 * \warning The secret key contains the public key as a suffix.
 *
 * \param[out] public_key    Pointer to the buffer for the public key (64 bytes).
 * \param[out] secret_key    Pointer to the buffer for the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Signing function for PERK-128-fast-3.
 *
 * \param[out] signature       Pointer to the buffer for the signature (5444 bytes).
 * \param[out] signature_len   Pointer to the length of the signature (always 5444).
 * \param[in]  message         Pointer to the message to be signed.
 * \param[in]  message_len     Length of the message to be signed.
 * \param[in]  secret_key      Pointer to the secret key (80 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verification function for PERK-128-fast-3.
 *
 * \param[in]  message          Pointer to the message.
 * \param[in]  message_len      Length of the message.
 * \param[in]  signature        Pointer to the signature (5444 bytes).
 * \param[in]  signature_len    Length of the signature.
 * \param[in]  public_key       Pointer to the public key (64 bytes).
 * \return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_perk_128_fast_3)
/**
 * \brief OQS_SIG object for PERK-128-fast-3.
 */
OQS_SIG *OQS_SIG_perk_128_fast_3_new(void);
#endif

#ifdef __cplusplus
}
#endif

#endif