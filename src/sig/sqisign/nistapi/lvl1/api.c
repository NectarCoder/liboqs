// SPDX-License-Identifier: Apache-2.0

#include <api.h>

// Forward declarations for namespaced functions
extern int sqisign_lvl1_ref_sqisign_keypair(unsigned char *pk, unsigned char *sk);
extern int sqisign_lvl1_ref_sqisign_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);
extern int sqisign_lvl1_ref_sqisign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);

#if defined(ENABLE_SIGN)

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    return sqisign_lvl1_ref_sqisign_keypair(pk, sk);
}

int
crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk)
{
    return sqisign_lvl1_ref_sqisign_sign(sm, smlen, m, mlen, sk);
}
#endif

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk)
{
    return sqisign_lvl1_ref_sqisign_open(m, mlen, sm, smlen, pk);
}
