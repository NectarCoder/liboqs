/**
 * \file sig_less_252_45.c
 * \brief Implementation of OQS_SIG wrapper for FAEST-128s
 */

#include <oqs/sig_less.h>

#if defined(OQS_ENABLE_SIG_less_252_45)

#include "less_252_45/include/api.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

OQS_SIG *OQS_SIG_less_252_45_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_less_252_45;
	sig->alg_version = "2.0";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;

	sig->length_public_key = OQS_SIG_less_252_45_length_public_key;
	sig->length_secret_key = OQS_SIG_less_252_45_length_secret_key;
	sig->length_signature = OQS_SIG_less_252_45_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_less_252_45_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_less_252_45_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_less_252_45_verify;
	sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_less_252_45_sign_with_ctx_str;
	sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_less_252_45_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_less_252_45_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (LESS_252_45_crypto_sign_keypair(public_key, secret_key) == 0) {
		return OQS_SUCCESS;
	} else {
		return OQS_ERROR;
	}
}

OQS_API OQS_STATUS OQS_SIG_less_252_45_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (message_len > SIZE_MAX - CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	size_t signed_message_len = *signature_len + message_len;
	uint8_t *signed_message = malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	unsigned long long smlen = 0;
	int ret = crypto_sign(signed_message, &smlen, message, message_len, secret_key);
	if (ret != 0) {
		free(signed_message);
		return OQS_ERROR;
	}
	*signature_len = smlen - message_len;
	printf("%llu\n", smlen);
	memcpy(signature, signed_message, *signature_len);
	//*signature_len = CRYPTO_BYTES;

	free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_less_252_45_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	printf("ML1: %zu\n",message_len);
	printf("SL1: %zu \n", signature_len);
	if (message_len > SIZE_MAX - signature_len) {
		return OQS_ERROR;
	}

	size_t signed_message_len = signature_len + message_len;
	uint8_t *signed_message = malloc(signed_message_len);
	uint8_t *recovered_message = malloc(message_len > 0 ? message_len : 1);
	printf("ML2: %zu\n",message_len);
	printf("SL2: %zu \n", signature_len);
	printf("SML1: %zu \n", signed_message_len);
	if (signed_message == NULL || recovered_message == NULL) {
		free(signed_message);
		free(recovered_message);
		return OQS_ERROR;
	}
	memcpy(signed_message, message, message_len);
	memcpy(signed_message + message_len, signature, signature_len);

	unsigned long long recovered_len = 0;
	int ret = LESS_252_45_crypto_sign_open(recovered_message, &recovered_len, signed_message,
	                          (unsigned long long)signed_message_len, public_key);
	printf("RL1: %llu\n", recovered_len);
	printf("ML3: %llu \n", message_len);
	printf("RET: %d \n", ret);
	printf("CMP: %d \n", memcmp(recovered_message, message, message_len));

	if (ret != 0 || (message_len > 0 && memcmp(recovered_message, message, message_len) != 0)) {
		free(signed_message);
		free(recovered_message);
		return OQS_ERROR;
	}

	free(signed_message);
	free(recovered_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_less_252_45_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	// FAEST doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular signing
	return OQS_SIG_less_252_45_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_less_252_45_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	// FAEST doesn't support context strings, fail if a non-empty context is provided
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	// Otherwise use regular verification
	return OQS_SIG_less_252_45_verify(message, message_len, signature, signature_len, public_key);
}

#endif