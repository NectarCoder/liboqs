/**
 * \file sig_sqisign_701.c
 * \brief Implementation of OQS_SIG wrapper for SQIsign-701 (NIST Level 5)
 */

#include <oqs/oqs.h>
#include <oqs/sig_sqisign.h>

#if defined(OQS_ENABLE_SIG_sqisign_701)

// Forward declarations for namespaced SQIsign functions
extern int sqisign_lvl5_ref_sqisign_keypair(unsigned char *pk, unsigned char *sk);
extern int sqisign_lvl5_ref_sqisign_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);
extern int sqisign_lvl5_ref_sqisign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);

OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key);

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

OQS_SIG *OQS_SIG_sqisign_701_new(void) {

	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_sqisign_701;
	sig->alg_version = "2.0";

	sig->claimed_nist_level = 5;
	sig->euf_cma = true;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_sqisign_701_length_public_key;
	sig->length_secret_key = OQS_SIG_sqisign_701_length_secret_key;
	sig->length_signature = OQS_SIG_sqisign_701_length_signature;

	sig->keypair = OQS_SIG_sqisign_701_keypair;
	sig->sign = OQS_SIG_sqisign_701_sign;
	sig->verify = OQS_SIG_sqisign_701_verify;
	sig->sign_with_ctx_str = OQS_SIG_sqisign_701_sign_with_ctx_str;
	sig->verify_with_ctx_str = OQS_SIG_sqisign_701_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_701_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (sqisign_lvl5_ref_sqisign_keypair(public_key, secret_key) == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	unsigned long long signed_msg_len = 0;
	uint8_t *signed_msg = OQS_MEM_malloc(message_len + OQS_SIG_sqisign_701_length_signature);
	if (signed_msg == NULL) {
		return OQS_ERROR;
	}

	int ret = sqisign_lvl5_ref_sqisign_sign(signed_msg, &signed_msg_len, message, (unsigned long long) message_len, secret_key);
	if (ret != 0) {
		OQS_MEM_insecure_free(signed_msg);
		return OQS_ERROR;
	}

	/* Extract signature (first length_signature bytes) from signed message */
	memcpy(signature, signed_msg, OQS_SIG_sqisign_701_length_signature);
	*signature_len = OQS_SIG_sqisign_701_length_signature;

	OQS_MEM_insecure_free(signed_msg);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_701_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	return OQS_SIG_sqisign_701_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (signature_len != OQS_SIG_sqisign_701_length_signature) {
		return OQS_ERROR;
	}

	unsigned long long recovered_msg_len = 0;
	uint8_t *signed_msg = OQS_MEM_malloc(message_len + OQS_SIG_sqisign_701_length_signature);
	uint8_t *recovered_msg = OQS_MEM_malloc(message_len + OQS_SIG_sqisign_701_length_signature);

	if (signed_msg == NULL || recovered_msg == NULL) {
		OQS_MEM_insecure_free(signed_msg);
		OQS_MEM_insecure_free(recovered_msg);
		return OQS_ERROR;
	}

	/* Reconstruct signed message (signature || message) */
	memcpy(signed_msg, signature, OQS_SIG_sqisign_701_length_signature);
	memcpy(signed_msg + OQS_SIG_sqisign_701_length_signature, message, message_len);

	int ret = sqisign_lvl5_ref_sqisign_open(recovered_msg, &recovered_msg_len, signed_msg, message_len + OQS_SIG_sqisign_701_length_signature, public_key);

	OQS_MEM_insecure_free(signed_msg);
	OQS_MEM_insecure_free(recovered_msg);

	return (ret == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_701_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	return OQS_SIG_sqisign_701_verify(message, message_len, signature, signature_len, public_key);
}

#endif
