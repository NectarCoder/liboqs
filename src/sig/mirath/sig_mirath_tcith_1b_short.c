/**
 * \file sig_mirath_tcith_1b_short.c
 * \brief OQS glue for MIRATH-TCITH-1B-SHORT
 */

#include <oqs/sig_mirath.h>

#if defined(OQS_ENABLE_SIG_mirath_tcith_1b_short)

#include "mirath_tcith_1b_short/api.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

OQS_SIG *OQS_SIG_mirath_tcith_1b_short_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_mirath_tcith_1b_short;
	sig->alg_version = "reference implementation (Round 2)";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_mirath_tcith_1b_short_length_public_key;
	sig->length_secret_key = OQS_SIG_mirath_tcith_1b_short_length_secret_key;
	sig->length_signature = OQS_SIG_mirath_tcith_1b_short_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_mirath_tcith_1b_short_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_mirath_tcith_1b_short_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_mirath_tcith_1b_short_verify;
	sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_mirath_tcith_1b_short_sign_with_ctx_str;
	sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_mirath_tcith_1b_short_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (public_key == NULL || secret_key == NULL) {
		return OQS_ERROR;
	}

	if (crypto_sign_keypair(public_key, secret_key) != 0) {
		memset(public_key, 0, OQS_SIG_mirath_tcith_1b_short_length_public_key);
		memset(secret_key, 0, OQS_SIG_mirath_tcith_1b_short_length_secret_key);
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (signature == NULL || signature_len == NULL || message == NULL || secret_key == NULL) {
		return OQS_ERROR;
	}

	if (message_len > SIZE_MAX - CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	const size_t signed_message_len = message_len + CRYPTO_BYTES;
	uint8_t *signed_message = OQS_MEM_malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	unsigned long long produced_len = 0;
	int ret = crypto_sign(signed_message, &produced_len, message, (unsigned long long) message_len, secret_key);
	if (ret != 0 || produced_len != signed_message_len) {
		OQS_MEM_insecure_free(signed_message);
		memset(signature, 0, OQS_SIG_mirath_tcith_1b_short_length_signature);
		return OQS_ERROR;
	}

	memcpy(signature, signed_message, CRYPTO_BYTES);
	*signature_len = CRYPTO_BYTES;

	OQS_MEM_insecure_free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (message == NULL || signature == NULL || public_key == NULL) {
		return OQS_ERROR;
	}

	if (signature_len != CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	if (message_len > SIZE_MAX - signature_len) {
		return OQS_ERROR;
	}

	const size_t signed_message_len = signature_len + message_len;
	uint8_t *signed_message = OQS_MEM_malloc(signed_message_len);
	uint8_t *recovered_message = OQS_MEM_malloc(message_len > 0 ? message_len : 1);
	if (signed_message == NULL || recovered_message == NULL) {
		OQS_MEM_insecure_free(signed_message);
		OQS_MEM_insecure_free(recovered_message);
		return OQS_ERROR;
	}

	memcpy(signed_message, signature, signature_len);
	memcpy(signed_message + signature_len, message, message_len);

	unsigned long long recovered_len = 0;
	int ret = crypto_sign_open(recovered_message, &recovered_len, signed_message, (unsigned long long) signed_message_len, public_key);
	if (ret != 0 || recovered_len != message_len || (message_len > 0 && memcmp(recovered_message, message, message_len) != 0)) {
		OQS_MEM_insecure_free(signed_message);
		OQS_MEM_insecure_free(recovered_message);
		return OQS_ERROR;
	}

	OQS_MEM_insecure_free(signed_message);
	OQS_MEM_insecure_free(recovered_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	return OQS_SIG_mirath_tcith_1b_short_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_mirath_tcith_1b_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	if (ctx_str != NULL && ctx_str_len > 0) {
		return OQS_ERROR;
	}
	return OQS_SIG_mirath_tcith_1b_short_verify(message, message_len, signature, signature_len, public_key);
}

#endif
