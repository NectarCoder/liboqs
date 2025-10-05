/**
 * \file sig_faest_em_256s.c
 * \brief Implementation of OQS_SIG wrapper for FAEST- em_192s
 */

#include <oqs/sig_faest.h>

#if defined(OQS_ENABLE_SIG_faest_em_256s)

#include "faest_em_256s/api.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

OQS_SIG *OQS_SIG_faest_em_256s_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_faest_em_256s;
	sig->alg_version = "1.0";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;

	sig->length_public_key = OQS_SIG_faest_em_256s_length_public_key;
	sig->length_secret_key = OQS_SIG_faest_em_256s_length_secret_key;
	sig->length_signature = OQS_SIG_faest_em_256s_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_faest_em_256s_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_faest_em_256s_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_faest_em_256s_verify;
	sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_faest_em_256s_sign_with_ctx_str;
	sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_faest_em_256s_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_faest_em_256s_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (crypto_sign_keypair(public_key, secret_key) == 0) {
		return OQS_SUCCESS;
	} else {
		return OQS_ERROR;
	}
}

OQS_API OQS_STATUS OQS_SIG_faest_em_256s_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (message_len > SIZE_MAX - CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	size_t signed_message_len = CRYPTO_BYTES + message_len;
	uint8_t *signed_message = malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	unsigned long long smlen = 0;
	int ret = crypto_sign(signed_message, &smlen, message, message_len, secret_key);
	if (ret != 0 || smlen != (unsigned long long)signed_message_len) {
		free(signed_message);
		return OQS_ERROR;
	}

	memcpy(signature, signed_message, CRYPTO_BYTES);
	*signature_len = CRYPTO_BYTES;

	free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_faest_em_256s_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (signature_len != CRYPTO_BYTES) {
		return OQS_ERROR;
	}
	if (message_len > SIZE_MAX - signature_len) {
		return OQS_ERROR;
	}

	size_t signed_message_len = signature_len + message_len;
	uint8_t *signed_message = malloc(signed_message_len);
	uint8_t *recovered_message = malloc(message_len > 0 ? message_len : 1);
	if (signed_message == NULL || recovered_message == NULL) {
		free(signed_message);
		free(recovered_message);
		return OQS_ERROR;
	}

	memcpy(signed_message, signature, signature_len);
	memcpy(signed_message + signature_len, message, message_len);

	unsigned long long recovered_len = 0;
	int ret = crypto_sign_open(recovered_message, &recovered_len, signed_message,
	                          (unsigned long long)signed_message_len, public_key);
	if (ret != 0 || recovered_len != (unsigned long long)message_len ||
	    (message_len > 0 && memcmp(recovered_message, message, message_len) != 0)) {
		free(signed_message);
		free(recovered_message);
		return OQS_ERROR;
	}

	free(signed_message);
	free(recovered_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_faest_em_256s_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	// FAEST doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular signing
	return OQS_SIG_faest_em_256s_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_faest_em_256s_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	// FAEST doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular verification
	return OQS_SIG_faest_em_256s_verify(message, message_len, signature, signature_len, public_key);
}

#endif