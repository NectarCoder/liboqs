/**
 * \file sig_sqisign_529.c
 * \brief Implementation of OQS_SIG wrapper for SQIsign-529
 */

#include <oqs/sig_sqisign.h>

#if defined(OQS_ENABLE_SIG_sqisign_529)

#include "nistapi/lvl3/api.h"
#include "include/rng.h"

#include <oqs/common.h>
#include <oqs/rand.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void oqs_sqisign_529_ensure_rng(void) {
        static bool is_seeded = false;
        if (!is_seeded) {
                unsigned char entropy[48];
                OQS_randombytes(entropy, sizeof(entropy));
                randombytes_init(entropy, NULL, 256);
                memset(entropy, 0, sizeof(entropy));
                is_seeded = true;
        }
}

OQS_SIG *OQS_SIG_sqisign_529_new(void) {
        OQS_SIG *sig = malloc(sizeof(OQS_SIG));
        if (sig == NULL) {
                return NULL;
        }
        memset(sig, 0, sizeof(OQS_SIG));

        sig->method_name = OQS_SIG_alg_sqisign_529;
        sig->alg_version = "SQIsign reference (sqisign-ref-impl)";

        sig->claimed_nist_level = 3;
        sig->euf_cma = true;
        sig->sig_with_ctx_support = false;

        sig->length_public_key = OQS_SIG_sqisign_529_length_public_key;
        sig->length_secret_key = OQS_SIG_sqisign_529_length_secret_key;
        sig->length_signature = OQS_SIG_sqisign_529_length_signature;

        sig->keypair = (OQS_STATUS (*)(uint8_t *, uint8_t *)) OQS_SIG_sqisign_529_keypair;
        sig->sign = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sqisign_529_sign;
        sig->verify = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sqisign_529_verify;
        sig->sign_with_ctx_str = (OQS_STATUS (*)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sqisign_529_sign_with_ctx_str;
        sig->verify_with_ctx_str = (OQS_STATUS (*)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)) OQS_SIG_sqisign_529_verify_with_ctx_str;

        return sig;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_529_keypair(uint8_t *public_key, uint8_t *secret_key) {
        if (public_key == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }

        oqs_sqisign_529_ensure_rng();

        if (crypto_sign_keypair(public_key, secret_key) != 0) {
                memset(public_key, 0, OQS_SIG_sqisign_529_length_public_key);
                memset(secret_key, 0, OQS_SIG_sqisign_529_length_secret_key);
                return OQS_ERROR;
        }

        return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_529_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
        if (signature == NULL || signature_len == NULL || message == NULL || secret_key == NULL) {
                return OQS_ERROR;
        }

        if (message_len > SIZE_MAX - OQS_SIG_sqisign_529_length_signature) {
                return OQS_ERROR;
        }

        oqs_sqisign_529_ensure_rng();

        const size_t sm_len_expected = message_len + OQS_SIG_sqisign_529_length_signature;
        uint8_t *sm = OQS_MEM_malloc(sm_len_expected);
        if (sm == NULL) {
                return OQS_ERROR;
        }

        unsigned long long sm_len = 0;
        int ret = crypto_sign(sm, &sm_len, message, (unsigned long long) message_len, secret_key);
        if (ret != 0 || sm_len != sm_len_expected) {
                memset(signature, 0, OQS_SIG_sqisign_529_length_signature);
                OQS_MEM_insecure_free(sm);
                return OQS_ERROR;
        }

        memcpy(signature, sm, OQS_SIG_sqisign_529_length_signature);
        *signature_len = OQS_SIG_sqisign_529_length_signature;

        OQS_MEM_insecure_free(sm);
        return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_529_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
        if (message == NULL || signature == NULL || public_key == NULL) {
                return OQS_ERROR;
        }

        if (signature_len != OQS_SIG_sqisign_529_length_signature) {
                return OQS_ERROR;
        }

        if (message_len > SIZE_MAX - signature_len) {
                return OQS_ERROR;
        }

        const size_t sm_len = signature_len + message_len;
        uint8_t *sm = OQS_MEM_malloc(sm_len);
        uint8_t *recovered = OQS_MEM_malloc(message_len > 0 ? message_len : 1);
        if (sm == NULL || recovered == NULL) {
                OQS_MEM_insecure_free(sm);
                OQS_MEM_insecure_free(recovered);
                return OQS_ERROR;
        }

        memcpy(sm, signature, signature_len);
        memcpy(sm + signature_len, message, message_len);

        unsigned long long recovered_len = 0;
        int ret = crypto_sign_open(recovered, &recovered_len, sm, (unsigned long long) sm_len, public_key);

        OQS_MEM_insecure_free(sm);
        OQS_MEM_insecure_free(recovered);

        return ret == 0 && recovered_len == message_len ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sqisign_529_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return OQS_SIG_sqisign_529_sign(signature, signature_len, message, message_len, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_sqisign_529_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
        if (ctx_str != NULL && ctx_str_len > 0) {
                return OQS_ERROR;
        }
        return OQS_SIG_sqisign_529_verify(message, message_len, signature, signature_len, public_key);
}

#endif
