#pragma once
#include <stdint.h>

#define Q (127)
#define Qm1 (Q-1)
#define FQ_ELEM uint8_t
#define FQ_DOUBLEPREC uint16_t
#define POSITION_T uint16_t

#define N (252)
#define K (126)

#define SEED_LENGTH_BYTES (16)
#define SIGN_PIVOT_REUSE_LIMIT (25) // Ensures probability of non-CT operation is < 2^-64
#define NUM_KEYPAIRS (8)
#define T (45)
#define W (34)
#define TREE_OFFSETS {0, 0, 0, 0, 2, 2, 26}
#define TREE_NODES_PER_LEVEL {1, 2, 4, 8, 14, 28, 32}
#define TREE_LEAVES_PER_LEVEL {0, 0, 0, 1, 0, 12, 32}
#define TREE_SUBROOTS 3
#define TREE_LEAVES_START_INDICES {57, 45, 14}
#define TREE_CONSECUTIVE_LEAVES {32, 12, 1}
#define MAX_PUBLISHED_SEEDS 11


/* number of bytes needed to store K or N bits */
#define K8 ((K+7u)/8u)
#define N8 ((N+7u)/8u)

/// rounds x to the next multiple of n
#define NEXT_MULTIPLE(x,n) ((((x)+((n)-1u))/(n))*(n))

/***************** Derived parameters *****************************************/
/*length of the output of the cryptographic hash, in bytes */
#define HASH_DIGEST_LENGTH (2*SEED_LENGTH_BYTES)
#define SALT_LENGTH_BYTES HASH_DIGEST_LENGTH

#define N_K_pad (N-K)
#define N_pad   N
#define K_pad   K
#define Q_pad   NEXT_MULTIPLE(Q, 8)

/* length of the private key seed doubled to avoid multikey attacks */
#define PRIVATE_KEY_SEED_LENGTH_BYTES (2*SEED_LENGTH_BYTES)

#define MASK_Q ((1 << BITS_TO_REPRESENT(Q)) - 1)
#define MASK_N ((1 << BITS_TO_REPRESENT(N)) - 1)
#define VERIFY_PIVOT_REUSE_LIMIT K

#define IS_REPRESENTABLE_IN_D_BITS(D, N)                \
  (((unsigned long) N>=(1UL << (D-1)) && (unsigned long) N<(1UL << D)) ? D : -1)

#define BITS_TO_REPRESENT(N)                            \
  (N == 0 ? 1 : (15                                     \
                 + IS_REPRESENTABLE_IN_D_BITS( 1, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 2, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 3, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 4, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 5, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 6, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 7, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 8, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS( 9, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(10, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(11, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(12, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(13, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(14, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(15, N)    \
                 + IS_REPRESENTABLE_IN_D_BITS(16, N)    \
                 )                                      \
   )

#define LOG2(L) ( (BITS_TO_REPRESENT(L) > BITS_TO_REPRESENT(L-1)) ? (BITS_TO_REPRESENT(L-1)) : (BITS_TO_REPRESENT(L)) )

#define NUM_LEAVES_SEED_TREE (T)
#define NUM_NODES_SEED_TREE ((2*NUM_LEAVES_SEED_TREE) - 1)

#define RREF_MAT_PACKEDBYTES ((BITS_TO_REPRESENT(Q)*(N-K)*K + 7)/8 + (N + 7)/8)

#define LESS_CRYPTO_PUBLICKEYBYTES (NUM_KEYPAIRS*RREF_MAT_PACKEDBYTES)
#define LESS_CRYPTO_SECRETKEYBYTES ((NUM_KEYPAIRS-1)*SEED_LENGTH_BYTES + RREF_MAT_PACKEDBYTES)

#define SEED_TREE_MAX_PUBLISHED_BYTES (MAX_PUBLISHED_SEEDS*SEED_LENGTH_BYTES + 1)
#define LESS_SIGNATURE_SIZE(NR_LEAVES) (HASH_DIGEST_LENGTH*2 + N8*W + NR_LEAVES*SEED_LENGTH_BYTES + 1)

// if defined the gaussian elimination will try to reuse the pivot rows
// from its last computation, to speed up the computation. Note: this
// leads to non-constant time code, which is fine in vrfy.
#define LESS_REUSE_PIVOTS_VY
#define LESS_REUSE_PIVOTS_SG