/**
 * \file sig_hawk1024.c
 * \brief Implementation of OQS_SIG wrapper for Hawk-1024
 */

#include <oqs/sig_hawk.h>

#if defined(OQS_ENABLE_SIG_hawk_1024)
#include <stdint.h>
#include <stdlib.h>
#include "hawk_1024/api.h"
#include <string.h>

OQS_SIG *OQS_SIG_hawk_1024_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_hawk_1024;
	sig->alg_version = "1.1";

	sig->claimed_nist_level = 5;
	sig->euf_cma = true;

	sig->length_public_key = OQS_SIG_hawk_1024_length_public_key;
	sig->length_secret_key = OQS_SIG_hawk_1024_length_secret_key;
	sig->length_signature = OQS_SIG_hawk_1024_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_hawk_1024_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_hawk_1024_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_hawk_1024_verify;
	sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_hawk_1024_sign_with_ctx_str;
	sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_hawk_1024_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_hawk_1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (crypto_sign_keypair(public_key, secret_key) == 0) {
		return OQS_SUCCESS;
	} else {
		return OQS_ERROR;
	}
}

OQS_API OQS_STATUS OQS_SIG_hawk_1024_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (message_len > SIZE_MAX - CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	size_t signed_message_len = message_len + CRYPTO_BYTES;
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

	memcpy(signature, signed_message + message_len, CRYPTO_BYTES);
	*signature_len = CRYPTO_BYTES;

	free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_hawk_1024_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (signature_len != CRYPTO_BYTES) {
		return OQS_ERROR;
	}
	if (message_len > SIZE_MAX - signature_len) {
		return OQS_ERROR;
	}

	size_t signed_message_len = signature_len + message_len;
	uint8_t *signed_message = malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	memcpy(signed_message, message, message_len);
	memcpy(signed_message + message_len, signature, signature_len);

	unsigned long long recovered_len = 0;
	int ret = crypto_sign_open(signed_message, &recovered_len, signed_message, (unsigned long long)signed_message_len, public_key);
	if (ret != 0 || recovered_len != (unsigned long long)message_len) {
		free(signed_message);
		return OQS_ERROR;
	}

	free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_hawk_1024_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	// HAWK doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular signing
	return OQS_SIG_hawk_1024_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_hawk_1024_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	// HAWK doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular verification
	return OQS_SIG_hawk_1024_verify(message, message_len, signature, signature_len, public_key);
}

#endif