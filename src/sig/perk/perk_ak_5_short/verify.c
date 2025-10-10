
/**
 * @file verify.c
 * @brief Implementation of verify function
 */

#include "verify.h"
#include "api.h"
#include "prove_pkp.h"
#include "signature.h"
#include "verify_pkp.h"
#include "voles.h"

#include <oqs/common.h>

#include <string.h>

static inline void sig_perk_ivect_to_tower_field(gf2_q_poly v_idx, i_vect_t i_vect) {
    unsigned fb = 0;
    for (unsigned e = 0; e < PERK_PARAM_TAU; e++) {
        unsigned mu = (e < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);
        uint8_t e1;
        uint16_t delta_e;
        ggm_tree_subtree_and_leaf(&e1, &delta_e, i_vect[e]);
        for (unsigned i = 0; i < mu; i++) {
            v_idx[fb / PERK_PARAM_Q] |= ((delta_e >> i) & 1U) << (fb % PERK_PARAM_Q);
            fb++;
        }
    }
}

int sig_perk_verify(const sig_perk_signature_t *signature, const digest_t mu, const sig_perk_public_key_t *pk) {
    uint8_t ch1_bar[5 * PERK_SECURITY_BYTES + 8] = {0};
    int ret = PERK_FAILURE;
    uint8_t h_V[2 * PERK_SECURITY_BYTES] = {0};
    perk_vole_data_t *q_prime = NULL;
    perk_vole_data_t *q = NULL;
    uint8_t (*D_tilde)[PERK_VOLE_HASH_BYTES] = NULL;
    uint8_t (*Q_tilde)[PERK_VOLE_HASH_BYTES] = NULL;
    uint8_t (*Q_tilde_xor_D_tilde)[PERK_VOLE_HASH_BYTES] = NULL;
    int result = PERK_FAILURE;

    // line 4
    i_vect_t i_vect = {0};
    challenge_decode(i_vect, signature->ch3);

    q_prime = OQS_MEM_calloc(PERK_PARAM_RHO, sizeof(*q_prime));
    if (q_prime == NULL) {
        goto cleanup;
    }

    q = OQS_MEM_calloc(PERK_PARAM_RHO, sizeof(*q));
    if (q == NULL) {
        goto cleanup;
    }

    D_tilde = OQS_MEM_calloc(PERK_PARAM_RHO, sizeof(*D_tilde));
    if (D_tilde == NULL) {
        goto cleanup;
    }

    Q_tilde = OQS_MEM_calloc(PERK_PARAM_RHO, sizeof(*Q_tilde));
    if (Q_tilde == NULL) {
        goto cleanup;
    }

    Q_tilde_xor_D_tilde = OQS_MEM_calloc(PERK_PARAM_RHO, sizeof(*Q_tilde_xor_D_tilde));
    if (Q_tilde_xor_D_tilde == NULL) {
        goto cleanup;
    }

    //  Reconstruct VOLEs and check commitments
    cmt_t h_com = {0};
    ret = vole_reconstuct(h_com, q_prime, i_vect, (const uint8_t(*)[sizeof(node_seed_t)])signature->pdecom,
                          signature->com_e_i, signature->salt);
    if (ret != PERK_SUCCESS) {
        goto cleanup;
    }

    // Compute challenge 1
    sig_perk_gen_first_challenge(ch1_bar, mu, h_com, signature->c, signature->salt);

    // Check VOLE’s consistency

    // Compute Q
    for (unsigned i = 0; i < PERK_PARAM_MU1; i++) {
        memcpy(q[i], q_prime[i], sizeof(perk_vole_data_t));
    }
    unsigned q_idx = PERK_PARAM_MU1;

    for (unsigned e = 1; e < PERK_PARAM_TAU; e++) {
        unsigned const mu_e = (e < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);

        uint8_t e1;
        uint16_t delta_e;
        ggm_tree_subtree_and_leaf(&e1, &delta_e, i_vect[e]);
        uint16_t k_e = ggm_tree_subtree_k(e);
        unsigned i = 0;
        for (i = 0; i < k_e; i++) {
            if ((delta_e >> i) & 1U) {
                xor_vole(q[q_idx], q_prime[q_idx], signature->c[e - 1]);
            } else {
                copy_vole(q[q_idx], q_prime[q_idx]);
            }
            q_idx++;
        }
        // padding
        for (; i < mu_e; i++) {
            memset(q[q_idx], 0, sizeof(perk_vole_data_t));
            q_idx++;
        }
    }

    uint16_t idx = 0;

    // Compute D tilde
    for (unsigned e = 0; e < PERK_PARAM_TAU; ++e) {
        unsigned const mu_e = (e < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);
        uint8_t e1;
        uint16_t delta_e;
        ggm_tree_subtree_and_leaf(&e1, &delta_e, i_vect[e]);
        uint16_t k_e = ggm_tree_subtree_k(e);

        unsigned i = 0;
        for (i = 0; i < k_e; ++i) {
            if ((delta_e >> i) & 1U) {
                memcpy(D_tilde[idx], signature->u_tilde, PERK_VOLE_HASH_BYTES);
            } else {
                memset(D_tilde[idx], 0, PERK_VOLE_HASH_BYTES);
            }
            idx++;
        }
        // padding
        for (; i < mu_e; i++) {
            memset(D_tilde[idx], 0, PERK_VOLE_HASH_BYTES);
            idx++;
        }
    }

    // Compute Q tilde
    for (uint16_t i = 0; i < PERK_PARAM_RHO; i++) {
        sig_perk_vole_hash(Q_tilde[i], ch1_bar, q[i]);
    }

    for (unsigned i = 0; i < PERK_PARAM_RHO; ++i) {
        for (unsigned j = 0; j < PERK_VOLE_HASH_BYTES; ++j) {
            Q_tilde_xor_D_tilde[i][j] = Q_tilde[i][j] ^ D_tilde[i][j];
        }
    }

    sig_perk_compute_h_V(h_V, Q_tilde_xor_D_tilde);

    ch2_t ch2_bar = {0};
    sig_perk_gen_second_challenge(ch2_bar, ch1_bar, signature->u_tilde, h_V, signature->t);

    // compute ch3_bar
    ch3_t ch3_bar = {0};
    sig_perk_gen_third_challenge(ch3_bar, ch2_bar, &signature->a, &signature->ctr);

    //  Check PKP’s consistency
    gf2_q_poly delta = {0};
    sig_perk_ivect_to_tower_field(delta, i_vect);
    uint8_t b_V = sig_perk_verify_check_pkp(&signature->a, (const perk_vole_data_t *)q, delta, signature->t,
                                            (const sig_perk_public_key_t *)pk, ch2_bar);

    for (unsigned i = 0; i < sizeof(ch3_t); i++) {
        if (ch3_bar[i] != signature->ch3[i]) {
            goto cleanup;
        }
    }

    if (PERK_SUCCESS != b_V) {
        goto cleanup;
    }

    result = PERK_SUCCESS;

cleanup:
    if (Q_tilde_xor_D_tilde != NULL) {
        OQS_MEM_insecure_free(Q_tilde_xor_D_tilde);
    }
    if (Q_tilde != NULL) {
        OQS_MEM_insecure_free(Q_tilde);
    }
    if (D_tilde != NULL) {
        OQS_MEM_insecure_free(D_tilde);
    }
    if (q != NULL) {
        OQS_MEM_insecure_free(q);
    }
    if (q_prime != NULL) {
        OQS_MEM_insecure_free(q_prime);
    }

    return result;
}
