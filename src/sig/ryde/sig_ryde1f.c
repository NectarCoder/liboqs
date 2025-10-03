/**
 * \file sig_ryde1f.c
 * \brief Implementation of OQS_SIG wrapper for RYDE1F
 */

#include <oqs/sig_ryde.h>

#if defined(OQS_ENABLE_SIG_ryde_1f)

#include "ryde1f/api.h"
#include "ryde1f/ryde.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

OQS_SIG *OQS_SIG_ryde_1f_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_ryde_1f;
	sig->alg_version = "1.0";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_ryde_1f_length_public_key;
	sig->length_secret_key = OQS_SIG_ryde_1f_length_secret_key;
	sig->length_signature = OQS_SIG_ryde_1f_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_ryde_1f_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_ryde_1f_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_ryde_1f_verify;
	sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_ryde_1f_sign_with_ctx_str;
	sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_ryde_1f_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_ryde_1f_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (public_key == NULL || secret_key == NULL) {
		return OQS_ERROR;
	}

	if (crypto_sign_keypair(public_key, secret_key) != 0) {
		memset(public_key, 0, OQS_SIG_ryde_1f_length_public_key);
		memset(secret_key, 0, OQS_SIG_ryde_1f_length_secret_key);
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_ryde_1f_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (signature == NULL || signature_len == NULL || message == NULL || secret_key == NULL) {
		return OQS_ERROR;
	}

	if (ryde_sign(signature, message, message_len, secret_key) != EXIT_SUCCESS) {
		memset(signature, 0, OQS_SIG_ryde_1f_length_signature);
		return OQS_ERROR;
	}

	*signature_len = OQS_SIG_ryde_1f_length_signature;
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_ryde_1f_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (message == NULL || signature == NULL || public_key == NULL) {
		return OQS_ERROR;
	}

	if (signature_len != OQS_SIG_ryde_1f_length_signature) {
		return OQS_ERROR;
	}

	if (ryde_verify(signature, signature_len, message, message_len, public_key) != EXIT_SUCCESS) {
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_ryde_1f_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	// RYDE-1F doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular signing
	return OQS_SIG_ryde_1f_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_ryde_1f_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	// RYDE-1F doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular verification
	return OQS_SIG_ryde_1f_verify(message, message_len, signature, signature_len, public_key);
}

#endif