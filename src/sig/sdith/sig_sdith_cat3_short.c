/**
 * \file sig_sdith_cat3_short.c
 * \brief Implementation of OQS_SIG wrapper for SDitH-CAT3-SHORT
 */

#include <oqs/sig_sdith.h>

#if defined(OQS_ENABLE_SIG_sdith_cat3_short)

#include "sdith_cat3_short/api.h"
#include "sdith_cat3_short/rng.h"

#include <oqs/common.h>
#include <oqs/rand.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void oqs_sdith_cat3_short_ensure_rng(void) {
        static bool is_seeded = false;
        if (!is_seeded) {
                unsigned char entropy[48];
                OQS_randombytes(entropy, sizeof(entropy));
                randombytes_init(entropy, NULL, 256);
                memset(entropy, 0, sizeof(entropy));
                is_seeded = true;
        }
}

OQS_SIG *OQS_SIG_sdith_cat3_short_new(void) {
        OQS_SIG *sig = malloc(sizeof(OQS_SIG));
        if (sig == NULL) {
                return NULL;
        }
        memset(sig, 0, sizeof(OQS_SIG));

        sig->method_name = OQS_SIG_alg_sdith_cat3_short;
        sig->alg_version = "NIST SDitH reference";

        sig->claimed_nist_level = 3;
        sig->euf_cma = true;
        sig->sig_with_ctx_support = false;

        sig->length_public_key = OQS_SIG_sdith_cat3_short_length_public_key;
        sig->length_secret_key = OQS_SIG_sdith_cat3_short_length_secret_key;
        sig->length_signature = OQS_SIG_sdith_cat3_short_length_signature;

        sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_sdith_cat3_short_keypair;
        sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sdith_cat3_short_sign;
        sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sdith_cat3_short_verify;
        sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sdith_cat3_short_sign_with_ctx_str;
        sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sdith_cat3_short_verify_with_ctx_str;

        return sig;
}

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_keypair(uint8_t *public_key, uint8_t *secret_key) {
        if (public_key == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }

        oqs_sdith_cat3_short_ensure_rng();

        if (crypto_sign_keypair(public_key, secret_key) != 0) {
                memset(public_key, 0, OQS_SIG_sdith_cat3_short_length_public_key);
                memset(secret_key, 0, OQS_SIG_sdith_cat3_short_length_secret_key);
                return OQS_ERROR;
        }

        return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
        if (signature == NULL || signature_len == NULL || message == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }

        if (message_len > SIZE_MAX - OQS_SIG_sdith_cat3_short_length_signature) {
                return OQS_ERROR;
        }

        oqs_sdith_cat3_short_ensure_rng();

        const size_t sm_target_len = message_len + OQS_SIG_sdith_cat3_short_length_signature;
        uint8_t *sm = OQS_MEM_malloc(sm_target_len);
        if (sm == NULL) {
                return OQS_ERROR;
        }

        unsigned long long sm_len = 0;
        int ret = crypto_sign(sm, &sm_len, message, (unsigned long long) message_len, secret_key);
        if (ret != 0 || sm_len != sm_target_len) {
                memset(signature, 0, OQS_SIG_sdith_cat3_short_length_signature);
                OQS_MEM_insecure_free(sm);
                return OQS_ERROR;
        }

        memcpy(signature, sm + message_len, OQS_SIG_sdith_cat3_short_length_signature);
        *signature_len = OQS_SIG_sdith_cat3_short_length_signature;

        OQS_MEM_insecure_free(sm);
        return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
        if (message == NULL || signature == NULL || public_key == NULL) {
                return OQS_ERROR;
        }

        if (signature_len != OQS_SIG_sdith_cat3_short_length_signature) {
                return OQS_ERROR;
        }

        if (message_len > SIZE_MAX - signature_len) {
                return OQS_ERROR;
        }

        const size_t sm_len = message_len + signature_len;
        uint8_t *sm = OQS_MEM_malloc(sm_len);
        uint8_t *recovered = OQS_MEM_malloc(message_len > 0 ? message_len : 1);
        if (sm == NULL || recovered == NULL) {
                OQS_MEM_insecure_free(sm);
                OQS_MEM_insecure_free(recovered);
                return OQS_ERROR;
        }

        memcpy(sm, message, message_len);
        memcpy(sm + message_len, signature, signature_len);

        unsigned long long recovered_len = 0;
        int ret = crypto_sign_open(recovered, &recovered_len, sm, (unsigned long long) sm_len, public_key);
        OQS_MEM_insecure_free(sm);
        OQS_MEM_insecure_free(recovered);

        return ret == 0 ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return OQS_SIG_sdith_cat3_short_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_sdith_cat3_short_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return OQS_SIG_sdith_cat3_short_verify(message, message_len, signature, signature_len, public_key);
}

#endif
