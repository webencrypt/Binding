/* Helper for the byte-faithful PKB-1 attack on SNOVA.
 *
 * Re-implements the SNOVA verifier's central-map evaluation up to (and not
 * including) the final hash comparison.  Given an expanded_PK struct (already
 * populated by upstream pk_expand) and a candidate signature, returns the
 * verifier's hash_in_GF[GF16_HASH] vector.
 *
 * The verifier accepts iff hash_in_GF == signed_gf, where signed_gf is
 * derived from hash_combined(digest, pk_seed, salt) and is independent of
 * P22.  The attack relies on the fact that hash_in_GF is a *linear* function
 * of P22 with the other components (pk_seed, salt, digest, signature) fixed.
 *
 * This file does not modify any upstream SNOVA source. */

#include "snova_pkb.h"

#include <stdint.h>
#include <string.h>

#include "snova.h"
#include "symmetric.h"

typedef uint8_t gf_t;

extern gf_t gf_multtab[SNOVA_q * SNOVA_q];

static inline gf_t gf_mult(const gf_t a, const gf_t b) {
    return gf_multtab[a * SNOVA_q + b];
}

#if SNOVA_q == 16
static inline void gf_set_add(gf_t *a, const gf_t b) {
    *a ^= b;
}
#else
static inline void gf_set_add(gf_t *a, const gf_t b) {
    *a = (*a + b) % SNOVA_q;
}
#endif

static void mat_mul_add16(gf_t *a, const uint16_t *b, const gf_t *c) {
    /* b is uint16_t to match the upstream expanded_PK::P layout. */
    for (int i1 = 0; i1 < SNOVA_l; i1++) {
        for (int j1 = 0; j1 < SNOVA_r; j1++) {
            gf_t sum = 0;
            for (int k1 = 0; k1 < SNOVA_l; k1++) {
                gf_set_add(&sum, gf_mult((gf_t)b[i1 * SNOVA_l + k1],
                                          c[k1 * SNOVA_r + j1]));
            }
            gf_set_add(&a[i1 * SNOVA_r + j1], sum);
        }
    }
}

static void mat_mul_add_lr(gf_t *a, const gf_t *b, const gf_t *c,
                           const int ad, const int bd, const int cd) {
    for (int i1 = 0; i1 < ad; i1++) {
        for (int j1 = 0; j1 < cd; j1++) {
            gf_t sum = 0;
            for (int k1 = 0; k1 < bd; k1++) {
                gf_set_add(&sum, gf_mult(b[i1 * bd + k1],
                                          c[k1 * cd + j1]));
            }
            gf_set_add(&a[i1 * cd + j1], sum);
        }
    }
}

/* Expand a packed signature (BYTES_GF(NUMGF_SIGNATURE)) into a GF array.
 * For q=16 (PACK_GF=2, PACK_BYTES=1) each byte holds two 4-bit values
 * (low nibble first), matching upstream's expand_gf.
 *
 * Returns 0 on success.  We follow the upstream convention strictly. */
static int expand_signature_gf(gf_t *out, const uint8_t *sig_bytes,
                               size_t n_gf) {
#if SNOVA_q == 16
    for (size_t i = 0; i < n_gf; ++i) {
        const uint8_t byte = sig_bytes[i / 2];
        out[i] = (i & 1u) ? (gf_t)((byte >> 4) & 0x0fu)
                          : (gf_t)(byte & 0x0fu);
    }
    return 0;
#else
    (void)out;
    (void)sig_bytes;
    (void)n_gf;
    return -1;  /* not used for the SNOVA-PKB-H q=16 profile */
#endif
}

/* Symmetry rejection used inside upstream verify.  We replicate it so the
 * attack pipeline can decide early whether the chosen honest signature is
 * usable.  Mirrors verify()'s gate exactly. */
#if defined(SYMMETRIC) && (SNOVA_r == SNOVA_l)
static int signature_passes_symmetry_gate(const gf_t *sig_gf) {
    int num_sym = 0;
    for (int idx = 0; idx < SNOVA_n; ++idx) {
        int is_symmetric = 1;
        for (int i1 = 0; i1 < SNOVA_l - 1; i1++) {
            for (int j1 = i1 + 1; j1 < SNOVA_l; j1++) {
                is_symmetric &=
                    sig_gf[idx * SNOVA_l2 + i1 * SNOVA_l + j1]
                  == sig_gf[idx * SNOVA_l2 + j1 * SNOVA_l + i1];
            }
        }
        num_sym += is_symmetric;
    }
#if SNOVA_l > 2
    return num_sym == 0;
#else
    return num_sym <= (SNOVA_n / 4);
#endif
}
#endif

/* Re-implements the verify body up to the hash comparison, returning the
 * verifier's hash_in_GF[GF16_HASH] vector.  Returns 0 on success. */
int snova_pkb_compute_hash_in_gf(gf_t hash_in_GF[GF16_HASH],
                                 const expanded_PK *pkx,
                                 const uint8_t *sig) {
    extern gf_t gf_S[SNOVA_l * SNOVA_l2];

    gf_t signature_in_GF[NUMGF_SIGNATURE];
    if (expand_signature_gf(signature_in_GF, sig, NUMGF_SIGNATURE) != 0) {
        return -1;
    }

#if defined(SYMMETRIC) && (SNOVA_r == SNOVA_l)
    if (!signature_passes_symmetry_gate(signature_in_GF)) {
        memset(hash_in_GF, 0xff, GF16_HASH);  /* signal: gated by symmetry */
        return -1;
    }
#endif

    memset(hash_in_GF, 0, GF16_HASH);
    gf_t sum_t0[SNOVA_m1 * SNOVA_l * SNOVA_n * SNOVA_lr] = {0};
    gf_t sum_t1[SNOVA_m1 * SNOVA_l2 * SNOVA_n * SNOVA_r2] = {0};

    gf_t whipped_sig[SNOVA_l * SNOVA_n * SNOVA_lr] = {0};
    for (int ab = 0; ab < SNOVA_l; ++ab) {
        for (int idx = 0; idx < SNOVA_n; ++idx) {
            for (int i1 = 0; i1 < SNOVA_l; i1++) {
                for (int j1 = 0; j1 < SNOVA_r; j1++) {
                    for (int k1 = 0; k1 < SNOVA_l; k1++) {
                        gf_set_add(
                            &whipped_sig[(ab * SNOVA_n + idx) * SNOVA_lr
                                          + i1 * SNOVA_r + j1],
                            gf_mult(gf_S[ab * SNOVA_l2 + i1 * SNOVA_l + k1],
                                    signature_in_GF[idx * SNOVA_lr
                                                     + k1 * SNOVA_r + j1]));
                    }
                }
            }
        }
    }

    for (int mi = 0; mi < SNOVA_m1; ++mi) {
        for (int ni = 0; ni < SNOVA_n; ++ni) {
            for (int b1 = 0; b1 < SNOVA_l; ++b1) {
                for (int nj = 0; nj < SNOVA_n; ++nj) {
                    mat_mul_add16(
                        &sum_t0[((mi * SNOVA_l + b1) * SNOVA_n + ni) * SNOVA_lr],
                        &pkx->P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2],
                        &whipped_sig[(b1 * SNOVA_n + nj) * SNOVA_lr]);
                }
            }
        }

        for (int a1 = 0; a1 < SNOVA_l; ++a1) {
            for (int b1 = 0; b1 < SNOVA_l; ++b1) {
                for (int ni = 0; ni < SNOVA_n; ++ni) {
                    for (int i1 = 0; i1 < SNOVA_r; i1++) {
                        for (int j1 = 0; j1 < SNOVA_r; j1++) {
                            for (int k1 = 0; k1 < SNOVA_l; k1++) {
                                gf_set_add(
                                    &sum_t1[(mi * SNOVA_l2 + a1 * SNOVA_l + b1)
                                             * SNOVA_r2 + i1 * SNOVA_r + j1],
                                    gf_mult(
                                        whipped_sig[(a1 * SNOVA_n + ni) * SNOVA_lr
                                                     + k1 * SNOVA_r + i1],
                                        sum_t0[((mi * SNOVA_l + b1) * SNOVA_n + ni)
                                                * SNOVA_lr + k1 * SNOVA_r + j1]));
                            }
                        }
                    }
                }
            }
        }
    }

    for (int mi = 0; mi < SNOVA_o; ++mi) {
        for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
            const int mi_prime = (alpha + mi) % SNOVA_m1;

            gf_t gf16m_temp1[SNOVA_r2] = {0};
            gf_t gf16m_temp2[SNOVA_lr] = {0};

            for (int a1 = 0; a1 < SNOVA_l; ++a1) {
                gf_t sumb[SNOVA_r2] = {0};
                for (int b1 = 0; b1 < SNOVA_l; ++b1) {
                    for (int i1 = 0; i1 < SNOVA_r; i1++) {
                        for (int j1 = 0; j1 < SNOVA_r; j1++) {
                            gf_set_add(&sumb[i1 * SNOVA_r + j1],
                                        gf_mult(sum_t1[(mi_prime * SNOVA_l2
                                                         + a1 * SNOVA_l + b1)
                                                        * SNOVA_r2
                                                        + i1 * SNOVA_r + j1],
                                                pkx->q2[(mi * SNOVA_alpha
                                                          + alpha) * SNOVA_l
                                                         + b1]));
                        }
                    }
                }
                for (int i1 = 0; i1 < SNOVA_r; i1++) {
                    for (int j1 = 0; j1 < SNOVA_r; j1++) {
                        gf_set_add(&gf16m_temp1[i1 * SNOVA_r + j1],
                                    gf_mult(sumb[i1 * SNOVA_r + j1],
                                            pkx->q1[(mi * SNOVA_alpha + alpha)
                                                     * SNOVA_l + a1]));
                    }
                }
            }

            mat_mul_add_lr(gf16m_temp2, gf16m_temp1,
                            &(pkx->Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr]),
                            SNOVA_r, SNOVA_r, SNOVA_l);
            mat_mul_add_lr(&hash_in_GF[mi * SNOVA_lr],
                            &(pkx->Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2]),
                            gf16m_temp2, SNOVA_r, SNOVA_r, SNOVA_l);
        }
    }

    return 0;
}

/* Compute signed_gf = hash_combined(digest, pk_seed, salt) → expand_gf.
 * The attack uses this to know the verifier's "target" without needing to
 * decode any internal SNOVA state beyond the public seed. */
int snova_pkb_compute_signed_gf(gf_t signed_gf[GF16_HASH],
                                const uint8_t *digest, size_t digest_len,
                                const uint8_t pk_seed[SEED_LENGTH_PUBLIC],
                                const uint8_t salt[BYTES_SALT]) {
    uint8_t signed_bytes[BYTES_HASH];
    shake_t st;
    shake256_init(&st);
    shake_absorb(&st, pk_seed, SEED_LENGTH_PUBLIC);
    shake_absorb(&st, digest, digest_len);
    shake_absorb(&st, salt, BYTES_SALT);
    shake_finalize(&st);
    shake_squeeze(signed_bytes, BYTES_HASH, &st);
    shake_release(&st);

    return expand_signature_gf(signed_gf, signed_bytes, GF16_HASH);
}
