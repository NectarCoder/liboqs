// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_LESS_NAMESPACE_H
#define OQS_SIG_LESS_NAMESPACE_H

#ifndef LESS_NAMESPACE_PREFIX
#error "LESS_NAMESPACE_PREFIX must be defined"
#endif

#define LESS_NAMESPACE_CONCAT_(prefix, name) prefix##name
#define LESS_NAMESPACE_CONCAT(prefix, name) LESS_NAMESPACE_CONCAT_(prefix, name)
#define LESS_NAMESPACE(name) LESS_NAMESPACE_CONCAT(LESS_NAMESPACE_PREFIX, name)

// canonical.c
#define blind LESS_NAMESPACE(blind)
#define CF LESS_NAMESPACE(CF)
#define compare_matrices LESS_NAMESPACE(compare_matrices)
#define compute_canonical_form_type3 LESS_NAMESPACE(compute_canonical_form_type3)
#define compute_canonical_form_type4 LESS_NAMESPACE(compute_canonical_form_type4)
#define compute_canonical_form_type4_sub LESS_NAMESPACE(compute_canonical_form_type4_sub)
#define compute_canonical_form_type5 LESS_NAMESPACE(compute_canonical_form_type5)
#define compute_canonical_form_type5_popcnt LESS_NAMESPACE(compute_canonical_form_type5_popcnt)

// codes.c
#define apply_cf_action_to_G LESS_NAMESPACE(apply_cf_action_to_G)
#define apply_cf_action_to_G_with_pivots LESS_NAMESPACE(apply_cf_action_to_G_with_pivots)
#define compress_rref LESS_NAMESPACE(compress_rref)
#define expand_to_rref LESS_NAMESPACE(expand_to_rref)
#define generator_get_pivot_flags LESS_NAMESPACE(generator_get_pivot_flags)
#define generator_monomial_mul LESS_NAMESPACE(generator_monomial_mul)
#define generator_RREF LESS_NAMESPACE(generator_RREF)
#define generator_rref_compact LESS_NAMESPACE(generator_rref_compact)
#define generator_rref_expand LESS_NAMESPACE(generator_rref_expand)
#define generator_RREF_pivot_reuse LESS_NAMESPACE(generator_RREF_pivot_reuse)
#define generator_sample LESS_NAMESPACE(generator_sample)
#define normalized_copy LESS_NAMESPACE(normalized_copy)
#define normalized_row_swap LESS_NAMESPACE(normalized_row_swap)
#define swap_rows LESS_NAMESPACE(swap_rows)

// fips202.c
#define sha3_256 LESS_NAMESPACE(sha3_256)
#define sha3_256_inc_absorb LESS_NAMESPACE(sha3_256_inc_absorb)
#define sha3_256_inc_finalize LESS_NAMESPACE(sha3_256_inc_finalize)
#define sha3_256_inc_init LESS_NAMESPACE(sha3_256_inc_init)
#define sha3_384 LESS_NAMESPACE(sha3_384)
#define sha3_384_inc_absorb LESS_NAMESPACE(sha3_384_inc_absorb)
#define sha3_384_inc_finalize LESS_NAMESPACE(sha3_384_inc_finalize)
#define sha3_384_inc_init LESS_NAMESPACE(sha3_384_inc_init)
#define sha3_512 LESS_NAMESPACE(sha3_512)
#define sha3_512_inc_absorb LESS_NAMESPACE(sha3_512_inc_absorb)
#define sha3_512_inc_finalize LESS_NAMESPACE(sha3_512_inc_finalize)
#define sha3_512_inc_init LESS_NAMESPACE(sha3_512_inc_init)
#define shake128 LESS_NAMESPACE(shake128)
#define shake128_absorb LESS_NAMESPACE(shake128_absorb)
#define shake128_ctx_clone LESS_NAMESPACE(shake128_ctx_clone)
#define shake128_inc_absorb LESS_NAMESPACE(shake128_inc_absorb)
#define shake128_inc_finalize LESS_NAMESPACE(shake128_inc_finalize)
#define shake128_inc_init LESS_NAMESPACE(shake128_inc_init)
#define shake128_inc_squeeze LESS_NAMESPACE(shake128_inc_squeeze)
#define shake128_squeezeblocks LESS_NAMESPACE(shake128_squeezeblocks)
#define shake256 LESS_NAMESPACE(shake256)
#define shake256_absorb LESS_NAMESPACE(shake256_absorb)
#define shake256_ctx_clone LESS_NAMESPACE(shake256_ctx_clone)
#define shake256_inc_absorb LESS_NAMESPACE(shake256_inc_absorb)
#define shake256_inc_finalize LESS_NAMESPACE(shake256_inc_finalize)
#define shake256_inc_init LESS_NAMESPACE(shake256_inc_init)
#define shake256_inc_squeeze LESS_NAMESPACE(shake256_inc_squeeze)
#define shake256_squeezeblocks LESS_NAMESPACE(shake256_squeezeblocks)

// keccakf1600.c
#define KeccakF1600_StateExtractBytes LESS_NAMESPACE(KeccakF1600_StateExtractBytes)
#define KeccakF1600_StatePermute LESS_NAMESPACE(KeccakF1600_StatePermute)
#define KeccakF1600_StateXORBytes LESS_NAMESPACE(KeccakF1600_StateXORBytes)

// LESS.c
#define LESS_keygen LESS_NAMESPACE(LESS_keygen)
#define LESS_sign LESS_NAMESPACE(LESS_sign)
#define LESS_verify LESS_NAMESPACE(LESS_verify)

// monomial.c
#define CheckCanonicalAction LESS_NAMESPACE(CheckCanonicalAction)
#define CosetRep LESS_NAMESPACE(CosetRep)
#define monomial_compose_action LESS_NAMESPACE(monomial_compose_action)
#define monomial_inv LESS_NAMESPACE(monomial_inv)
#define monomial_sample_prikey LESS_NAMESPACE(monomial_sample_prikey)
#define monomial_sample_salt LESS_NAMESPACE(monomial_sample_salt)
#define yt_shuffle LESS_NAMESPACE(yt_shuffle)
#define yt_shuffle_state LESS_NAMESPACE(yt_shuffle_state)
#define yt_shuffle_state_limit LESS_NAMESPACE(yt_shuffle_state_limit)

// rng.c
#define initialize_csprng LESS_NAMESPACE(initialize_csprng)
#define initialize_csprng_ds LESS_NAMESPACE(initialize_csprng_ds)

// seedtree.c
#define BuildGGM LESS_NAMESPACE(BuildGGM)
#define GGMPath LESS_NAMESPACE(GGMPath)
#define RebuildGGM LESS_NAMESPACE(RebuildGGM)
#define seed_leaves LESS_NAMESPACE(seed_leaves)

// sign.c
#define crypto_sign LESS_NAMESPACE(crypto_sign)
#define crypto_sign_keypair LESS_NAMESPACE(crypto_sign_keypair)
#define crypto_sign_open LESS_NAMESPACE(crypto_sign_open)

// sort.c
#define compare_rows LESS_NAMESPACE(compare_rows)
#define counting_sort_u8 LESS_NAMESPACE(counting_sort_u8)
#define sort LESS_NAMESPACE(sort)
#define SortCols LESS_NAMESPACE(SortCols)
#define SortCols_internal LESS_NAMESPACE(SortCols_internal)
#define SortCols_internal_compare LESS_NAMESPACE(SortCols_internal_compare)
#define SortCols_internal_hoare_partition LESS_NAMESPACE(SortCols_internal_hoare_partition)
#define SortRows LESS_NAMESPACE(SortRows)
#define SortRows_internal LESS_NAMESPACE(SortRows_internal)
#define SortRows_internal_compare LESS_NAMESPACE(SortRows_internal_compare)
#define SortRows_internal_hoare_partition LESS_NAMESPACE(SortRows_internal_hoare_partition)

// transpose.c
#define matrix_transpose8x8 LESS_NAMESPACE(matrix_transpose8x8)
#define matrix_transpose_opt LESS_NAMESPACE(matrix_transpose_opt)
#define next_block LESS_NAMESPACE(next_block)

// utils.c
#define cswap LESS_NAMESPACE(cswap)
#define SampleChallenge LESS_NAMESPACE(SampleChallenge)
#define verify LESS_NAMESPACE(verify)

#endif /* OQS_SIG_LESS_NAMESPACE_H */
