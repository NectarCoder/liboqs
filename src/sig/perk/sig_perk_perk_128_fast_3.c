// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/sig_perk.h>
/* Include PERK parameters so PUBLIC_KEY_BYTES etc. are visible to this glue file. */
#include "perk_128_fast_3/parameters.h"

#if defined(OQS_ENABLE_SIG_perk_perk_128_fast_3)
OQS_SIG *OQS_SIG_perk_perk_128_fast_3_new(void) {

    OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = "PERK-perk_128_fast_3";
    sig->alg_version = "round2-ref";

    sig->claimed_nist_level = 1;
    sig->euf_cma = true;
    sig->suf_cma = false;
    sig->sig_with_ctx_support = false;

    sig->length_public_key = OQS_SIG_perk_perk_128_fast_3_length_public_key;
    sig->length_secret_key = OQS_SIG_perk_perk_128_fast_3_length_secret_key;
    sig->length_signature = OQS_SIG_perk_perk_128_fast_3_length_signature;

    sig->keypair = OQS_SIG_perk_perk_128_fast_3_keypair;
    sig->sign = OQS_SIG_perk_perk_128_fast_3_sign;
    sig->verify = OQS_SIG_perk_perk_128_fast_3_verify;
    sig->sign_with_ctx_str = OQS_SIG_perk_perk_128_fast_3_sign_with_ctx_str;
    sig->verify_with_ctx_str = OQS_SIG_perk_perk_128_fast_3_verify_with_ctx_str;

    return sig;
}

extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
extern int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

OQS_API OQS_STATUS OQS_SIG_perk_perk_128_fast_3_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return (OQS_STATUS) crypto_sign_keypair(public_key, secret_key);
}

OQS_API OQS_STATUS OQS_SIG_perk_perk_128_fast_3_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    unsigned long long smlen = 0;
    int rv = crypto_sign((unsigned char *)signature, &smlen, message, (unsigned long long)message_len, secret_key);
    if (rv != 0) {
        return OQS_ERROR;
    }
    *signature_len = (size_t)smlen;
    return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_perk_perk_128_fast_3_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    unsigned long long mlen = 0;
    int rv = crypto_sign_open((unsigned char *)NULL, &mlen, signature, (unsigned long long)signature_len, public_key);
    if (rv != 0) {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_perk_perk_128_fast_3_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    if (ctx_str == NULL && ctx_str_len == 0) {
        return OQS_SIG_perk_perk_128_fast_3_sign(signature, signature_len, message, message_len, secret_key);
    } else {
        return OQS_ERROR;
    }
}

OQS_API OQS_STATUS OQS_SIG_perk_perk_128_fast_3_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    if (ctx_str == NULL && ctx_str_len == 0) {
        return OQS_SIG_perk_perk_128_fast_3_verify(message, message_len, signature, signature_len, public_key);
    } else {
        return OQS_ERROR;
    }
}

#endif
