/**
 * \file sig_perk_128_fast_3.c
 * \brief Implementation of OQS_SIG wrapper for PERK-128-fast-3
 */

#include <oqs/sig_perk.h>

#if defined(OQS_ENABLE_SIG_perk_128_fast_3)

#include "perk_128_fast_3/api.h"
#include <string.h>

OQS_SIG *OQS_SIG_perk_128_fast_3_new(void) {

	OQS_SIG *sig = malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));

	sig->method_name = OQS_SIG_alg_perk_128_fast_3;
	sig->alg_version = "1.0";

	sig->claimed_nist_level = 1;
	sig->euf_cma = true;

	sig->length_public_key = OQS_SIG_perk_128_fast_3_length_public_key;
	sig->length_secret_key = OQS_SIG_perk_128_fast_3_length_secret_key;
	sig->length_signature = OQS_SIG_perk_128_fast_3_length_signature;

	sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_perk_128_fast_3_keypair;
	sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_perk_128_fast_3_sign;
	sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_perk_128_fast_3_verify;

	return sig;
}

OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_keypair(uint8_t *public_key, uint8_t *secret_key) {
	if (crypto_sign_keypair(public_key, secret_key) == 0) {
		return OQS_SUCCESS;
	} else {
		return OQS_ERROR;
	}
}

OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	unsigned long long signed_msg_len;
	uint8_t *signed_msg = NULL;
	OQS_STATUS result = OQS_ERROR;
	
	// Allocate buffer for the full signed message (signature + message)
	signed_msg = malloc(message_len + OQS_SIG_perk_128_fast_3_length_signature);
	if (signed_msg == NULL) {
		goto cleanup;
	}
	
	int ret = crypto_sign(signed_msg, &signed_msg_len, message, message_len, secret_key);
	
	if (ret == 0) {
		// Extract only the signature part (first CRYPTO_BYTES)
		memcpy(signature, signed_msg, OQS_SIG_perk_128_fast_3_length_signature);
		*signature_len = OQS_SIG_perk_128_fast_3_length_signature;
		result = OQS_SUCCESS;
	}

cleanup:
	if (signed_msg != NULL) {
		free(signed_msg);
	}
	return result;
}

OQS_API OQS_STATUS OQS_SIG_perk_128_fast_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	unsigned long long recovered_msg_len;
	uint8_t *signed_msg = NULL;
	uint8_t *recovered_msg = NULL;
	OQS_STATUS result = OQS_ERROR;
	
	// Allocate buffers for the signed message reconstruction and recovery
	signed_msg = malloc(signature_len + message_len);
	recovered_msg = malloc(message_len);
	
	if (signed_msg == NULL || recovered_msg == NULL) {
		goto cleanup;
	}
	
	// Reconstruct the signed message format: [SIGNATURE][MESSAGE]
	memcpy(signed_msg, signature, signature_len);
	memcpy(signed_msg + signature_len, message, message_len);
	
	int ret = crypto_sign_open(recovered_msg, &recovered_msg_len, signed_msg, signature_len + message_len, public_key);
	
	if (ret == 0 && recovered_msg_len == message_len && memcmp(recovered_msg, message, message_len) == 0) {
		result = OQS_SUCCESS;
	}

cleanup:
	if (signed_msg != NULL) {
		free(signed_msg);
	}
	if (recovered_msg != NULL) {
		free(recovered_msg);
	}
	return result;
}

#endif