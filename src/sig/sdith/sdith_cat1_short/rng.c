/*
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
 
NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 
You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
*/

#include <stdint.h>
#include <string.h>

#include "rng.h"

int rijndaelKeySetupEnc(uint32_t rk[], const unsigned char cipherKey[], int keyBits);
void rijndaelEncrypt(const uint32_t rk[], int Nr, const unsigned char pt[16], unsigned char ct[16]);

static AES256_CTR_DRBG_struct DRBG_ctx;

static void AES256_ECB(const unsigned char *key, const unsigned char *ctr, unsigned char *buffer);

/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
int seedexpander_init(AES_XOF_struct *ctx,
        unsigned char *seed,
        unsigned char *diversifier,
        unsigned long maxlen) {
    if (ctx == NULL || seed == NULL || diversifier == NULL) {
        return RNG_BAD_OUTBUF;
    }
    if (maxlen >= 0x100000000UL) {
        return RNG_BAD_MAXLEN;
    }

    ctx->length_remaining = maxlen;
    memcpy(ctx->key, seed, 32);
    memcpy(ctx->ctr, diversifier, 8);
    ctx->ctr[11] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[10] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[9] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[8] = maxlen % 256;
    memset(ctx->ctr + 12, 0x00, 4);

    ctx->buffer_pos = 16;
    memset(ctx->buffer, 0, sizeof ctx->buffer);

    return RNG_SUCCESS;
}

/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
int seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen) {
    if (ctx == NULL || x == NULL) {
        return RNG_BAD_OUTBUF;
    }
    if (xlen >= ctx->length_remaining) {
        return RNG_BAD_REQ_LEN;
    }

    ctx->length_remaining -= xlen;

    unsigned long offset = 0;
    while (xlen > 0) {
        if (xlen <= (16U - (unsigned long) ctx->buffer_pos)) {
            memcpy(x + offset, ctx->buffer + ctx->buffer_pos, xlen);
            ctx->buffer_pos += (int) xlen;
            return RNG_SUCCESS;
        }

        memcpy(x + offset, ctx->buffer + ctx->buffer_pos, 16U - (unsigned long) ctx->buffer_pos);
        xlen -= 16U - (unsigned long) ctx->buffer_pos;
        offset += 16U - (unsigned long) ctx->buffer_pos;

        AES256_ECB(ctx->key, ctx->ctr, ctx->buffer);
        ctx->buffer_pos = 0;

        for (int i = 15; i >= 0; i--) {
            if (ctx->ctr[i] == 0xff) {
                ctx->ctr[i] = 0x00;
            } else {
                ctx->ctr[i]++;
                break;
            }
        }
    }

    return RNG_SUCCESS;
}


void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) {
    (void) security_strength;

    unsigned char seed_material[48];
    memcpy(seed_material, entropy_input, sizeof seed_material);
    if (personalization_string != NULL) {
        for (size_t i = 0; i < sizeof seed_material; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }

    memset(DRBG_ctx.Key, 0, sizeof DRBG_ctx.Key);
    memset(DRBG_ctx.V, 0, sizeof DRBG_ctx.V);

    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;

    memset(seed_material, 0, sizeof seed_material);
}

int randombytes(unsigned char *x, unsigned long long xlen) {
    if (x == NULL) {
        return RNG_BAD_OUTBUF;
    }

    unsigned long long offset = 0;
    unsigned char block[16];
    while (xlen > 0) {
        for (int i = 15; i >= 0; i--) {
            if (DRBG_ctx.V[i] == 0xff) {
                DRBG_ctx.V[i] = 0x00;
            } else {
                DRBG_ctx.V[i]++;
                break;
            }
        }

        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);

        size_t todo = xlen > 16 ? 16 : (size_t) xlen;
        memcpy(x + offset, block, todo);
        offset += todo;
        xlen -= todo;
    }

    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;

    memset(block, 0, sizeof block);
    return RNG_SUCCESS;
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data, unsigned char *Key, unsigned char *V) {
    unsigned char temp[48];

    for (int i = 0; i < 3; i++) {
        for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff) {
                V[j] = 0x00;
            } else {
                V[j]++;
                break;
            }
        }
        AES256_ECB(Key, V, temp + 16 * i);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);
    memset(temp, 0, sizeof temp);
}

static void AES256_ECB(const unsigned char *key, const unsigned char *ctr, unsigned char *buffer) {
    uint32_t round_keys[4 * (14 + 1)];
    rijndaelKeySetupEnc(round_keys, key, 256);
    rijndaelEncrypt(round_keys, 14, ctr, buffer);
    memset(round_keys, 0, sizeof round_keys);
}









