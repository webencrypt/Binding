/* 100-trial blocking experiment: SNOVA-PKB-H rejects the byte-faithful
 * PKB-1 attack of pkb1_attack_snova.c in every trial.
 *
 * For each trial:
 *   1. Generate a fresh SNOVA-PKB-H keypair (pk, sk).
 *   2. Sign a random message m via SNOVA-PKB-H Sign.  The signature is
 *      valid under SNOVA-PKB-H Verify (round-trip).
 *   3. Mount the byte-faithful PKB-1 substitution on the *upstream* SNOVA
 *      verifier (the attack of pkb1_attack_snova.c), producing pk^star
 *      such that upstream SNOVA verifier accepts (pk^star, sig, digest_synth).
 *   4. Run SNOVA-PKB-H Verify(pk^star, sig, m).  Because SNOVA-PKB-H
 *      recomputes d_pk^star = SHAKE256(pk^star), the digest fed to the
 *      underlying verifier changes; acceptance now requires a target
 *      collision on the public-key digest or a fresh-target hit (16^{-80}
 *      per attempt).  We expect rejection in 100/100 trials. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snova.h"
#include "snova_pkb.h"
#include "symmetric.h"

extern void randombytes_init(unsigned char *entropy, unsigned char *pers,
                             int strength);
extern int  randombytes(unsigned char *x, unsigned long long xlen);
extern uint8_t gf_multtab[SNOVA_q * SNOVA_q];

int snova_pkb_compute_hash_in_gf(uint8_t hash_in_GF[GF16_HASH],
                                 const expanded_PK *pkx,
                                 const uint8_t *sig);

/* ---------- GF(16) helpers (duplicated for self-containment). ----------- */
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    return gf_multtab[a * SNOVA_q + b];
}
static inline uint8_t gf_inv(uint8_t a) {
    for (uint8_t b = 1; b < SNOVA_q; ++b) {
        if (gf_mul(a, b) == 1u) return b;
    }
    return 0u;
}
static void p22_expand(uint8_t gf_out[NUMGF_PK], const uint8_t *bytes) {
    for (size_t i = 0; i < NUMGF_PK / 2; ++i) {
        gf_out[2 * i]     = bytes[i] & 0x0fu;
        gf_out[2 * i + 1] = (bytes[i] >> 4) & 0x0fu;
    }
}
static void p22_compress(uint8_t bytes_out[BYTES_GF(NUMGF_PK)],
                          const uint8_t gf_in[NUMGF_PK]) {
    for (size_t i = 0; i < NUMGF_PK / 2; ++i) {
        bytes_out[i] = (uint8_t)((gf_in[2 * i] & 0x0fu)
                                | ((gf_in[2 * i + 1] & 0x0fu) << 4));
    }
}

static int gf16_find_kernel_vector(uint8_t *out_x,
                                   uint8_t *M_inout, int rows, int cols) {
    int *pivot_col = (int *)calloc((size_t)rows, sizeof(int));
    int *col_pivot = (int *)calloc((size_t)cols, sizeof(int));
    if (pivot_col == NULL || col_pivot == NULL) {
        free(pivot_col); free(col_pivot); return -1;
    }
    for (int c = 0; c < cols; ++c) col_pivot[c] = -1;
    int rank = 0, c = 0;
    while (rank < rows && c < cols) {
        int pivot_row = -1;
        for (int r = rank; r < rows; ++r) {
            if (M_inout[r * cols + c] != 0u) { pivot_row = r; break; }
        }
        if (pivot_row < 0) { ++c; continue; }
        if (pivot_row != rank) {
            for (int k = c; k < cols; ++k) {
                uint8_t tmp = M_inout[rank * cols + k];
                M_inout[rank * cols + k] = M_inout[pivot_row * cols + k];
                M_inout[pivot_row * cols + k] = tmp;
            }
        }
        const uint8_t pv_inv = gf_inv(M_inout[rank * cols + c]);
        for (int k = c; k < cols; ++k) {
            M_inout[rank * cols + k] = gf_mul(M_inout[rank * cols + k], pv_inv);
        }
        for (int r = 0; r < rows; ++r) {
            if (r == rank) continue;
            const uint8_t f = M_inout[r * cols + c];
            if (f == 0u) continue;
            for (int k = c; k < cols; ++k) {
                M_inout[r * cols + k] ^= gf_mul(f, M_inout[rank * cols + k]);
            }
        }
        pivot_col[rank] = c; col_pivot[c] = rank; ++rank; ++c;
    }
    int free_col = -1;
    for (int k = 0; k < cols; ++k) {
        if (col_pivot[k] < 0) { free_col = k; break; }
    }
    if (free_col < 0) { free(pivot_col); free(col_pivot); return -2; }
    for (int k = 0; k < cols; ++k) out_x[k] = 0u;
    out_x[free_col] = 1u;
    for (int r = 0; r < rank; ++r) {
        const uint8_t v = M_inout[r * cols + free_col];
        if (v != 0u) out_x[pivot_col[r]] = v;
    }
    free(pivot_col); free(col_pivot);
    return 0;
}

/* Build a PKB-1 substitute pk^star such that upstream SNOVA verifier
 * accepts (pk^star, sig, digest).  pk_seed is preserved; only P22 is varied. */
static int build_pk_star(uint8_t pk_star[SNOVA_PKB_PK_BYTES],
                          const uint8_t pk[SNOVA_PKB_PK_BYTES],
                          const uint8_t *sig) {
    const int K = 200;
    uint8_t pk_seed[SEED_LENGTH_PUBLIC];
    uint8_t P22_honest_gf[NUMGF_PK];
    memcpy(pk_seed, pk, SEED_LENGTH_PUBLIC);
    p22_expand(P22_honest_gf, pk + SEED_LENGTH_PUBLIC);

    /* hash_in_GF for honest pk (= signed_gf because verify accepts honestly). */
    uint8_t hash_honest[GF16_HASH];
    {
        expanded_PK pkx;
        SNOVA_NAMESPACE(pk_expand)(&pkx, pk);
        if (snova_pkb_compute_hash_in_gf(hash_honest, &pkx, sig) != 0) {
            return -1;
        }
    }

    uint8_t (*deltas)[NUMGF_PK]      = malloc(sizeof(uint8_t[K][NUMGF_PK]));
    uint8_t (*delta_hash)[GF16_HASH] = malloc(sizeof(uint8_t[K][GF16_HASH]));
    if (deltas == NULL || delta_hash == NULL) {
        free(deltas); free(delta_hash); return -1;
    }

    for (int i = 0; i < K; ++i) {
        uint8_t rand_bytes[NUMGF_PK];
        randombytes(rand_bytes, sizeof(rand_bytes));
        uint8_t P22_test_gf[NUMGF_PK];
        for (size_t j = 0; j < NUMGF_PK; ++j) {
            deltas[i][j]   = rand_bytes[j] & 0x0fu;
            P22_test_gf[j] = P22_honest_gf[j] ^ deltas[i][j];
        }
        uint8_t P22_test_bytes[BYTES_GF(NUMGF_PK)];
        p22_compress(P22_test_bytes, P22_test_gf);
        uint8_t pk_test[SNOVA_PKB_PK_BYTES];
        memcpy(pk_test, pk_seed, SEED_LENGTH_PUBLIC);
        memcpy(pk_test + SEED_LENGTH_PUBLIC, P22_test_bytes,
               BYTES_GF(NUMGF_PK));
        expanded_PK pkx_test;
        SNOVA_NAMESPACE(pk_expand)(&pkx_test, pk_test);
        uint8_t hash_test[GF16_HASH];
        snova_pkb_compute_hash_in_gf(hash_test, &pkx_test, sig);
        for (int k = 0; k < GF16_HASH; ++k) {
            delta_hash[i][k] = hash_test[k] ^ hash_honest[k];
        }
    }

    const int rows = GF16_HASH, cols = K;
    uint8_t *M = malloc((size_t)rows * (size_t)cols);
    if (M == NULL) { free(deltas); free(delta_hash); return -1; }
    for (int r = 0; r < rows; ++r) {
        for (int c2 = 0; c2 < cols; ++c2) {
            M[r * cols + c2] = delta_hash[c2][r];
        }
    }
    uint8_t *cvec = malloc((size_t)cols);
    if (cvec == NULL) { free(M); free(deltas); free(delta_hash); return -1; }
    const int kk = gf16_find_kernel_vector(cvec, M, rows, cols);
    if (kk != 0) {
        free(M); free(cvec); free(deltas); free(delta_hash);
        return -1;
    }

    uint8_t delta_final[NUMGF_PK] = {0};
    for (int i = 0; i < cols; ++i) {
        const uint8_t ci = cvec[i];
        if (ci == 0u) continue;
        for (size_t j = 0; j < NUMGF_PK; ++j) {
            delta_final[j] ^= gf_mul(ci, deltas[i][j]);
        }
    }
    uint8_t P22_star_gf[NUMGF_PK];
    for (size_t j = 0; j < NUMGF_PK; ++j) {
        P22_star_gf[j] = P22_honest_gf[j] ^ delta_final[j];
    }
    uint8_t P22_star_bytes[BYTES_GF(NUMGF_PK)];
    p22_compress(P22_star_bytes, P22_star_gf);
    memcpy(pk_star, pk_seed, SEED_LENGTH_PUBLIC);
    memcpy(pk_star + SEED_LENGTH_PUBLIC, P22_star_bytes, BYTES_GF(NUMGF_PK));

    free(M); free(cvec); free(deltas); free(delta_hash);
    return 0;
}

static size_t byte_diff(const uint8_t *a, const uint8_t *b, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) ++c;
    return c;
}

int main(void) {
    const int NUM_TRIALS = 100;

    /* Fixed seed for reproducibility. */
    unsigned char entropy[48];
    for (int i = 0; i < 48; ++i) entropy[i] = (unsigned char)(0xC9 ^ i);
    randombytes_init(entropy, NULL, 256);

    int   accept_pkbh_on_pk_star = 0;
    int   sanity_upstream_accept = 0;
    size_t sum_byte_diff = 0;
    size_t min_byte_diff = SNOVA_PKB_PK_BYTES;
    size_t max_byte_diff = 0;

    for (int t = 0; t < NUM_TRIALS; ++t) {
        /* 1. Fresh SNOVA-PKB-H keypair. */
        uint8_t pk[SNOVA_PKB_PK_BYTES], sk[SNOVA_PKB_SK_BYTES];
        if (snova_pkb_h_keygen(pk, sk) != 0) {
            fprintf(stderr, "[%d] keygen failed\n", t); continue;
        }

        /* 2. Random message and PKB-H Sign. */
        uint8_t msg[32];
        randombytes(msg, sizeof(msg));
        uint8_t sig[SNOVA_PKB_SIG_BYTES];
        if (snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg)) != 0) {
            fprintf(stderr, "[%d] sign failed\n", t); continue;
        }
        if (snova_pkb_h_verify(pk, sig, msg, sizeof(msg)) != 0) {
            fprintf(stderr, "[%d] round-trip verify failed\n", t); continue;
        }

        /* 3. Mount byte-faithful PKB-1 substitution on upstream verifier.
         *    The "digest" the upstream verifier consumes is
         *    SHAKE256(synth(d_pk_honest, m)) -- determined entirely by
         *    pk_seed (via signed_gf) and the signature, NOT by P22. */
        uint8_t pk_star[SNOVA_PKB_PK_BYTES];
        if (build_pk_star(pk_star, pk, sig) != 0) {
            fprintf(stderr, "[%d] kernel search failed\n", t); continue;
        }

        /* 4a. Sanity check: upstream verifier ACCEPTS (pk_star, sig, digest_synth). */
        {
            uint8_t dpk_honest[SNOVA_PKB_DPK_BYTES];
            snova_pkb_pkdigest(dpk_honest, pk, SNOVA_PKB_PK_BYTES);
            size_t synth_len = 0u;
            uint8_t *synth = malloc(sizeof(SNOVA_PKB_DST_TARGET) - 1u
                                     + 1u + SNOVA_PKB_DPK_BYTES + 4u
                                     + sizeof(msg));
            synth_len = snova_pkb_build_synth(synth, 1024,
                                               SNOVA_PKB_PROFILE_ID_H,
                                               dpk_honest, msg, sizeof(msg));
            uint8_t digest_synth[BYTES_DIGEST];
            shake256(digest_synth, BYTES_DIGEST, synth, synth_len);

            expanded_PK pkx_star;
            SNOVA_NAMESPACE(pk_expand)(&pkx_star, pk_star);
            if (SNOVA_NAMESPACE(verify)(&pkx_star, sig,
                                         digest_synth, BYTES_DIGEST) == 0) {
                ++sanity_upstream_accept;
            }
            free(synth);
        }

        /* 4b. Run SNOVA-PKB-H verifier on (pk_star, sig, m).
         *     It will recompute d_pk_star = SHAKE256(pk_star) (a fresh digest)
         *     and feed a *different* synth -> different target -> reject. */
        if (snova_pkb_h_verify(pk_star, sig, msg, sizeof(msg)) == 0) {
            ++accept_pkbh_on_pk_star;
        }

        size_t bd = byte_diff(pk, pk_star, SNOVA_PKB_PK_BYTES);
        sum_byte_diff += bd;
        if (bd < min_byte_diff) min_byte_diff = bd;
        if (bd > max_byte_diff) max_byte_diff = bd;

        if (t % 10 == 0) {
            fprintf(stderr, "  [%d] done, sanity_upstream_accept=%d, "
                            "PKB-H rejects so far=%d\n",
                    t, sanity_upstream_accept,
                    t + 1 - accept_pkbh_on_pk_star);
        }
    }

    printf("=== SNOVA-PKB-H 100-trial blocking experiment ===\n");
    printf("  Trials                     : %d\n", NUM_TRIALS);
    printf("  Sanity (upstream accept    : %d / %d   (must be %d)\n",
           sanity_upstream_accept, NUM_TRIALS, NUM_TRIALS);
    printf("  pk^star  -> upstream verify ACCEPT)\n");
    printf("  PKB-H verifier rejected     : %d / %d   (target: %d)\n",
           NUM_TRIALS - accept_pkbh_on_pk_star, NUM_TRIALS, NUM_TRIALS);
    printf("  PKB-H verifier accepted     : %d / %d\n",
           accept_pkbh_on_pk_star, NUM_TRIALS);
    printf("  Byte distance pk vs pk^star: min=%zu, mean=%zu, max=%zu (/ %u)\n",
           min_byte_diff, sum_byte_diff / (size_t)NUM_TRIALS, max_byte_diff,
           (unsigned)SNOVA_PKB_PK_BYTES);

    return (accept_pkbh_on_pk_star == 0
            && sanity_upstream_accept == NUM_TRIALS) ? 0 : 1;
}
