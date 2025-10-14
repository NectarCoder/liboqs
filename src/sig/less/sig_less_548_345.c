// SPDX-License-Identifier: MIT

#include <oqs/sig_less.h>

#if defined(OQS_ENABLE_SIG_less_548_345)

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "namespace.h"
#include "common/api.h"

#undef verify

OQS_SIG *OQS_SIG_less_548_345_new(void) {
	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_less_548_345;
	sig->alg_version = "1.2";

	sig->claimed_nist_level = 5;
	sig->euf_cma = true;
	sig->suf_cma = false;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_less_548_345_length_public_key;
	sig->length_secret_key = OQS_SIG_less_548_345_length_secret_key;
	sig->length_signature = OQS_SIG_less_548_345_length_signature;

	sig->keypair = OQS_SIG_less_548_345_keypair;
	sig->sign = OQS_SIG_less_548_345_sign;
	sig->verify = OQS_SIG_less_548_345_verify;
	sig->sign_with_ctx_str = OQS_SIG_less_548_345_sign_with_ctx_str;
	sig->verify_with_ctx_str = OQS_SIG_less_548_345_verify_with_ctx_str;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_less_548_345_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (crypto_sign_keypair(public_key, secret_key) == 0) {
		return OQS_SUCCESS;
	} else {
		return OQS_ERROR;
	}
}

OQS_API OQS_STATUS OQS_SIG_less_548_345_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	if (message_len > SIZE_MAX - CRYPTO_BYTES) {
		return OQS_ERROR;
	}

	size_t signed_message_len = message_len + CRYPTO_BYTES;
	uint8_t *signed_message = OQS_MEM_malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	unsigned long long smlen = 0;
	int rc = crypto_sign(signed_message, &smlen, message, (unsigned long long) message_len, secret_key);
	if (rc != 0 || smlen < (unsigned long long) message_len || smlen > (unsigned long long) signed_message_len) {
		OQS_MEM_insecure_free(signed_message);
		return OQS_ERROR;
	}

	size_t produced_signature_len = (size_t) (smlen - (unsigned long long) message_len);
	memcpy(signature, signed_message + message_len, produced_signature_len);
	*signature_len = produced_signature_len;

	OQS_MEM_insecure_free(signed_message);
	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_less_548_345_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	if (signature_len == 0 || signature_len > CRYPTO_BYTES) {
		return OQS_ERROR;
	}
	if (message_len > SIZE_MAX - signature_len) {
		return OQS_ERROR;
	}

	size_t signed_message_len = signature_len + message_len;
	uint8_t *signed_message = OQS_MEM_malloc(signed_message_len);
	if (signed_message == NULL) {
		return OQS_ERROR;
	}

	memcpy(signed_message, message, message_len);
	memcpy(signed_message + message_len, signature, signature_len);

	unsigned long long recovered_len = 0;
	int rc = crypto_sign_open(signed_message, &recovered_len, signed_message, (unsigned long long) signed_message_len, public_key);
	OQS_MEM_insecure_free(signed_message);
	if (rc != 0 || recovered_len != (unsigned long long) message_len) {
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_less_548_345_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	if ((ctx_str != NULL && ctx_str_len > 0)) {
		return OQS_ERROR;
	}
	return OQS_SIG_less_548_345_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_less_548_345_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	if ((ctx_str != NULL && ctx_str_len > 0)) {
		return OQS_ERROR;
	}
	return OQS_SIG_less_548_345_verify(message, message_len, signature, signature_len, public_key);
}

#endif
