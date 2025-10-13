// SPDX-License-Identifier: MIT

/**
 * Glue code between LESS and liboqs
 */

#include <oqs/oqs.h>

#include "params.h"
#include "LESS.h"

OQS_STATUS LESS_NAMESPACE(keypair)(uint8_t *pk, uint8_t *sk) {
    LESS_keygen((prikey_t *)sk, (pubkey_t *)pk);
    return OQS_SUCCESS;
}

OQS_STATUS LESS_NAMESPACE(sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len,
                                 const uint8_t *secret_key) {
    LESS_sign((const prikey_t *)secret_key, (const char *)message, message_len, (sign_t *)signature);
    *signature_len = sizeof(sign_t);
    return OQS_SUCCESS;
}

OQS_STATUS LESS_NAMESPACE(verify)(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len,
                                   const uint8_t *pk) {
    if (signature_len != sizeof(sign_t)) {
        return OQS_ERROR;
    }
    int res = LESS_verify((const pubkey_t *)pk, (const char *)message, message_len, (const sign_t *)signature);
    if (res == 1) {
        return OQS_SUCCESS;
    } else {
        return OQS_ERROR;
    }
}