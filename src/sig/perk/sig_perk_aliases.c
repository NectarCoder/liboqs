// SPDX-License-Identifier: MIT
#include <stddef.h>

#if defined(OQS_PERK_ALIAS_IMPL_FAST)
int OQS_PERK_128_FAST_3_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int OQS_PERK_128_FAST_3_crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk);
int OQS_PERK_128_FAST_3_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk);

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    return OQS_PERK_128_FAST_3_crypto_sign_keypair(pk, sk);
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk) {
    return OQS_PERK_128_FAST_3_crypto_sign(sm, smlen, m, mlen, sk);
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk) {
    return OQS_PERK_128_FAST_3_crypto_sign_open(m, mlen, sm, smlen, pk);
}

#elif defined(OQS_PERK_ALIAS_IMPL_SHORT)
int OQS_PERK_128_SHORT_3_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int OQS_PERK_128_SHORT_3_crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk);
int OQS_PERK_128_SHORT_3_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk);

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    return OQS_PERK_128_SHORT_3_crypto_sign_keypair(pk, sk);
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk) {
    return OQS_PERK_128_SHORT_3_crypto_sign(sm, smlen, m, mlen, sk);
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk) {
    return OQS_PERK_128_SHORT_3_crypto_sign_open(m, mlen, sm, smlen, pk);
}

#else
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    (void)pk;
    (void)sk;
    return -1;
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk) {
    (void)sm;
    (void)smlen;
    (void)m;
    (void)mlen;
    (void)sk;
    return -1;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk) {
    (void)m;
    (void)mlen;
    (void)sm;
    (void)smlen;
    (void)pk;
    return -1;
}
#endif
