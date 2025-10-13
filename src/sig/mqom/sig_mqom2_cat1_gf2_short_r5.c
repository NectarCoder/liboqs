/**
 * \file sig_mqom2_cat1_gf2_short_r5.c
 * \brief Implementation of OQS_SIG wrapper for MQOM2-CAT1-GF2-SHORT-R5
 */

#include <oqs/sig_mqom.h>

#if defined(OQS_ENABLE_SIG_mqom2_cat1_gf2_short_r5)

#include "mqom2_cat1_gf2_short_r5/api.h"

#include <oqs/rand.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static OQS_STATUS oqs_mqom2_cat1_gf2_short_r5_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
static OQS_STATUS oqs_mqom2_cat1_gf2_short_r5_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

OQS_SIG *OQS_SIG_mqom2_cat1_gf2_short_r5_new(void) {
        OQS_SIG *sig = malloc(sizeof(OQS_SIG));
        if (sig == NULL) {
                return NULL;
        }
        memset(sig, 0, sizeof(OQS_SIG));

        sig->method_name = OQS_SIG_alg_mqom2_cat1_gf2_short_r5;
        sig->alg_version = "MQOM reference 1.00";

        sig->claimed_nist_level = 1;
        sig->euf_cma = true;
        sig->sig_with_ctx_support = false;

        sig->length_public_key = OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key;
        sig->length_secret_key = OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key;
        sig->length_signature = OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature;

        sig->keypair = OQS_SIG_mqom2_cat1_gf2_short_r5_keypair;
        sig->sign = OQS_SIG_mqom2_cat1_gf2_short_r5_sign;
        sig->verify = OQS_SIG_mqom2_cat1_gf2_short_r5_verify;
        sig->sign_with_ctx_str = OQS_SIG_mqom2_cat1_gf2_short_r5_sign_with_ctx_str;
        sig->verify_with_ctx_str = OQS_SIG_mqom2_cat1_gf2_short_r5_verify_with_ctx_str;

        return sig;
}

/* Provide deterministic sampling using liboqs RNG to avoid linking external RNG code. */
int randombytes(unsigned char *output, unsigned long long output_len) {
        if (output_len == 0) {
                return 0;
        }
        if (output == NULL) {
                return -1;
        }
        unsigned char *cursor = output;
        unsigned long long remaining = output_len;
        while (remaining > 0) {
                size_t chunk = remaining > (unsigned long long) SIZE_MAX ? SIZE_MAX : (size_t) remaining;
                OQS_randombytes(cursor, chunk);
                cursor += chunk;
                remaining -= chunk;
        }
        return 0;
}

void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) {
        (void) entropy_input;
        (void) personalization_string;
        (void) security_strength;
}

OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_keypair(uint8_t *public_key, uint8_t *secret_key) {
        if (public_key == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }

        if (crypto_sign_keypair(public_key, secret_key) != 0) {
                memset(public_key, 0, OQS_SIG_mqom2_cat1_gf2_short_r5_length_public_key);
                memset(secret_key, 0, OQS_SIG_mqom2_cat1_gf2_short_r5_length_secret_key);
                return OQS_ERROR;
        }

        return OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
        return oqs_mqom2_cat1_gf2_short_r5_sign_internal(signature, signature_len, message, message_len, secret_key);
}

OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
        return oqs_mqom2_cat1_gf2_short_r5_verify_internal(message, message_len, signature, signature_len, public_key);
}

OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return oqs_mqom2_cat1_gf2_short_r5_sign_internal(signature, signature_len, message, message_len, secret_key);
}

OQS_STATUS OQS_SIG_mqom2_cat1_gf2_short_r5_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return oqs_mqom2_cat1_gf2_short_r5_verify_internal(message, message_len, signature, signature_len, public_key);
}

static OQS_STATUS oqs_mqom2_cat1_gf2_short_r5_sign_internal(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
        if (signature == NULL || signature_len == NULL || message == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }
        if (message_len > (size_t) UINT64_MAX) {
                return OQS_ERROR;
        }

        unsigned long long produced_len = 0;
        int ret = crypto_sign_signature(signature, &produced_len, message, (unsigned long long) message_len, secret_key);
        if (ret != 0 || produced_len != (unsigned long long) OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature) {
                memset(signature, 0, OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature);
                return OQS_ERROR;
        }

        *signature_len = OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature;
        return OQS_SUCCESS;
}

static OQS_STATUS oqs_mqom2_cat1_gf2_short_r5_verify_internal(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
        if (message == NULL || signature == NULL || public_key == NULL) {
                return OQS_ERROR;
        }
        if (signature_len != OQS_SIG_mqom2_cat1_gf2_short_r5_length_signature) {
                        return OQS_ERROR;
        }
        if (message_len > (size_t) UINT64_MAX) {
                return OQS_ERROR;
        }

        int ret = crypto_sign_verify(signature, (unsigned long long) signature_len, message, (unsigned long long) message_len, public_key);
        return ret == 0 ? OQS_SUCCESS : OQS_ERROR;
}

#endif
