/**
 * \file sig_faest.h
 * \brief Public API for the FAEST signature family (less_252_45, faest_192s)
 *
 * Fast and Efficient Signature Scheme based on Trapdoor Functions (FAEST) is a
 * post-quantum digital signature scheme designed for high performance and
 * strong security guarantees.
 * 
 * 
 * 
 * 
 * 
 * still needs high editing to fit into liboqs build system ######
 */

#ifndef OQS_SIG_LESS_H
#define OQS_SIG_LESS_H

#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Algorithm identifier for FAEST-128s */
//#define OQS_SIG_alg_less_252_45 "LESS-252-45"

/** less_252_45 public key length, in bytes */
#define OQS_SIG_less_252_45_length_public_key 97484

/** less_252_45 secret key length, in bytes */
#define OQS_SIG_less_252_45_length_secret_key 32

/** less_252_45 signature length, in bytes */
#define OQS_SIG_less_252_45_length_signature 1301

/**
 * \brief Generates a FAEST-128s public/secret key pair.
 *
 * \param[out] public_key Pointer to the buffer for the 32-byte public key.
 * \param[out] secret_key Pointer to the buffer for the 32-byte secret key.
 * \return OQS_SUCCESS on success, otherwise OQS_ERROR.
 */
OQS_API OQS_STATUS OQS_SIG_less_252_45_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * \brief Produces a FAEST-128s signature for the supplied message.
 *
 * \param[out] signature       Pointer to the buffer for the signature (4506 bytes).
 * \param[out] signature_len   On success, set to 4506.
 * \param[in]  message         Pointer to the message to sign.
 * \param[in]  message_len     Length of the message in bytes.
 * \param[in]  secret_key      Pointer to the 32-byte secret key.
 * \return OQS_SUCCESS on success, otherwise OQS_ERROR.
 */
OQS_API OQS_STATUS OQS_SIG_less_252_45_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

/**
 * \brief Verifies a FAEST-128s signature for the supplied message.
 *
 * \param[in] message        Pointer to the message to verify.
 * \param[in] message_len    Length of the message in bytes.
 * \param[in] signature      Pointer to the 4506-byte signature to verify.
 * \param[in] signature_len  Length of the signature (must be 4506).
 * \param[in] public_key     Pointer to the 32-byte public key.
 * \return OQS_SUCCESS if the signature is valid, otherwise OQS_ERROR.
 */
OQS_API OQS_STATUS OQS_SIG_less_252_45_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * \brief Context-string signing helper for FAEST-128s.
 *
 * FAEST does not define a context-string variant. This helper succeeds only
 * when called with an empty context string and otherwise returns OQS_ERROR.
 */
OQS_API OQS_STATUS OQS_SIG_less_252_45_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);

/**
 * \brief Context-string verification helper for FAEST-128s.
 *
 * FAEST does not define a context-string variant. This helper succeeds only
 * when called with an empty context string and otherwise returns OQS_ERROR.
 */
OQS_API OQS_STATUS OQS_SIG_less_252_45_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#if defined(OQS_ENABLE_SIG_less_252_45)
/**
 * \brief Constructs an OQS_SIG object for FAEST-128s.
 */
OQS_SIG *OQS_SIG_less_252_45_new(void);
#endif


#ifdef __cplusplus
} // extern "C"
#endif

#endif