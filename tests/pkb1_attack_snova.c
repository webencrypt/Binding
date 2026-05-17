/* Byte-faithful PKB-1 attack against UNMODIFIED upstream SNOVA(24,5,16,4).
 *
 * Strategy.  The verifier accepts iff hash_in_GF == signed_gf, where:
 *   - signed_gf depends only on pk_seed, digest, salt (NOT on the secret-
 *     derived P22 component of pk);
 *   - hash_in_GF is a *linear* function of P22 with pk_seed, digest, salt,
 *     and the signature fixed.
 *
 * Therefore, finding pk^* != pk that accepts the same (m, sig) reduces to
 * finding ΔP22 in ker(L), where L : F_16^NUMGF_PK -> F_16^GF16_HASH is the
 * verifier-induced linear map.  Generically the kernel has dimension
 * NUMGF_PK - GF16_HASH = 2000 - 80 = 1920, so the kernel is enormous and
 * a random kernel vector almost certainly flips almost every nibble.
 *
 * We sample K random ΔP22 vectors, evaluate L on each to obtain K column
 * vectors in F_16^80, solve a small linear system to find a nontrivial
 * combination summing to zero, and combine the corresponding ΔP22 samples
 * to obtain a kernel vector.  Finally we re-pack pk^* = pk_seed ||
 * compress(P22 + ΔP22_final) and verify with UNMODIFIED upstream SNOVA. */

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

/* ---------------------------------------------------------------------------
 *  GF(16) helpers (we extern gf_multtab from upstream SNOVA after one warm
 *  call to crypto_sign_open initialises it).
 * --------------------------------------------------------------------------- */
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    return gf_multtab[a * SNOVA_q + b];
}

static inline uint8_t gf_inv(uint8_t a) {
    /* Brute force; SNOVA_q is small.  Result undefined for a=0. */
    for (uint8_t b = 1; b < SNOVA_q; ++b) {
        if (gf_mul(a, b) == 1u) return b;
    }
    return 0u;
}

/* ---------------------------------------------------------------------------
 *  Byte<->GF packing identical to upstream SNOVA for q=16 (PACK_GF=2,
 *  PACK_BYTES=1, low nibble first).
 * --------------------------------------------------------------------------- */
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

/* ---------------------------------------------------------------------------
 *  GF(16) Gaussian elimination on a small dense matrix.  Returns 0 on
 *  success and writes a nontrivial vector x in the right kernel of M to
 *  out_x.  M is rows × cols, row-major.
 * --------------------------------------------------------------------------- */
static int gf16_find_kernel_vector(uint8_t *out_x,
                                   uint8_t *M_inout, int rows, int cols) {
    /* In-place Gauss elimination on M (row-major).  Track pivot column per
     * row in pivot_col[r]; columns without a pivot are free. */
    int *pivot_col = (int *)calloc((size_t)rows, sizeof(int));
    int *col_pivot = (int *)calloc((size_t)cols, sizeof(int));   /* row owning column, or -1 */
    if (pivot_col == NULL || col_pivot == NULL) {
        free(pivot_col); free(col_pivot);
        return -1;
    }
    for (int c = 0; c < cols; ++c) col_pivot[c] = -1;

    int rank = 0;
    int c = 0;
    while (rank < rows && c < cols) {
        /* find pivot in column c at row >= rank */
        int pivot_row = -1;
        for (int r = rank; r < rows; ++r) {
            if (M_inout[r * cols + c] != 0u) {
                pivot_row = r;
                break;
            }
        }
        if (pivot_row < 0) {
            ++c;
            continue;
        }
        /* swap row pivot_row into row rank */
        if (pivot_row != rank) {
            for (int k = c; k < cols; ++k) {
                uint8_t tmp = M_inout[rank * cols + k];
                M_inout[rank * cols + k] = M_inout[pivot_row * cols + k];
                M_inout[pivot_row * cols + k] = tmp;
            }
        }
        /* normalise pivot to 1 */
        const uint8_t pv = M_inout[rank * cols + c];
        const uint8_t pv_inv = gf_inv(pv);
        for (int k = c; k < cols; ++k) {
            M_inout[rank * cols + k] = gf_mul(M_inout[rank * cols + k], pv_inv);
        }
        /* eliminate other rows */
        for (int r = 0; r < rows; ++r) {
            if (r == rank) continue;
            const uint8_t f = M_inout[r * cols + c];
            if (f == 0u) continue;
            for (int k = c; k < cols; ++k) {
                M_inout[r * cols + k] ^= gf_mul(f, M_inout[rank * cols + k]);
            }
        }
        pivot_col[rank] = c;
        col_pivot[c]    = rank;
        ++rank;
        ++c;
    }

    if (rank == cols) {
        /* trivial kernel only */
        free(pivot_col); free(col_pivot);
        return -2;
    }

    /* Pick a random free column (no pivot) and set x[free]=1, x[pivot]=
     * accumulated coefficient. */
    /* deterministic pick: smallest free column */
    int free_col = -1;
    for (int k = 0; k < cols; ++k) {
        if (col_pivot[k] < 0) {
            free_col = k;
            break;
        }
    }
    if (free_col < 0) {
        free(pivot_col); free(col_pivot);
        return -3;
    }

    for (int k = 0; k < cols; ++k) out_x[k] = 0u;
    out_x[free_col] = 1u;
    for (int r = 0; r < rank; ++r) {
        /* row r has pivot at column pivot_col[r], coefficient at free_col
         * after elimination is M[r, free_col].  Then x[pivot_col[r]] += -M[r, free_col]·x[free_col]
         * = M[r, free_col] (in characteristic 2). */
        const uint8_t v = M_inout[r * cols + free_col];
        if (v != 0u) {
            out_x[pivot_col[r]] = v;  /* x[pivot] = M[r, free] (negation is identity in char 2) */
        }
    }

    free(pivot_col); free(col_pivot);
    return 0;
}

/* ---------------------------------------------------------------------------
 *  Main attack pipeline.
 * --------------------------------------------------------------------------- */
static void seed_drbg(uint8_t fixed_seed_id) {
    unsigned char entropy[48];
    for (int i = 0; i < 48; ++i) {
        entropy[i] = (unsigned char)(0xA7u ^ (uint8_t)(i + fixed_seed_id));
    }
    randombytes_init(entropy, NULL, 256);
}

static size_t count_byte_diffs(const uint8_t *a, const uint8_t *b, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) ++c;
    }
    return c;
}

int main(void) {
    const int K = 200;  /* number of random ΔP22 samples */

    seed_drbg(0x01);

    /* 1. Honest KeyGen. */
    uint8_t pk_honest[SNOVA_PKB_PK_BYTES];
    uint8_t sk_inner[SNOVA_PKB_INNER_SK_BYTES];
    {
        uint8_t seed[48];
        randombytes(seed, sizeof(seed));
        if (SNOVA_NAMESPACE(genkeys)(pk_honest, sk_inner, seed) != 0) {
            fprintf(stderr, "genkeys failed\n");
            return 1;
        }
    }

    /* 2. Honest Sign via the NIST-style wrapper (upstream sign.c). */
    const uint8_t msg[] = "PKB1 byte-faithful witness on SNOVA-24_5_16_4.";
    const size_t mlen = sizeof(msg) - 1u;

    uint8_t sig[SNOVA_PKB_SIG_BYTES];
    {
        expanded_SK skx;
        if (SNOVA_NAMESPACE(sk_expand)(&skx, sk_inner) != 0) {
            fprintf(stderr, "sk_expand failed\n");
            return 1;
        }
        uint8_t digest[BYTES_DIGEST];
        shake256(digest, BYTES_DIGEST, msg, mlen);
        uint8_t salt[BYTES_SALT];
        randombytes(salt, BYTES_SALT);
        if (SNOVA_NAMESPACE(sign)(&skx, sig, digest, BYTES_DIGEST, salt) != 0) {
            fprintf(stderr, "sign failed\n");
            return 1;
        }
    }

    /* 3. Verify honestly. */
    {
        expanded_PK pkx;
        SNOVA_NAMESPACE(pk_expand)(&pkx, pk_honest);
        uint8_t digest[BYTES_DIGEST];
        shake256(digest, BYTES_DIGEST, msg, mlen);
        if (SNOVA_NAMESPACE(verify)(&pkx, sig, digest, BYTES_DIGEST) != 0) {
            fprintf(stderr, "honest verify failed -- aborting\n");
            return 1;
        }
    }

    /* 4. Extract pk_seed and the GF-decoded P22 from pk_honest. */
    uint8_t  pk_seed[SEED_LENGTH_PUBLIC];
    uint8_t  P22_honest_gf[NUMGF_PK];
    uint8_t  P22_honest_bytes[BYTES_GF(NUMGF_PK)];
    memcpy(pk_seed, pk_honest, SEED_LENGTH_PUBLIC);
    memcpy(P22_honest_bytes, pk_honest + SEED_LENGTH_PUBLIC,
           BYTES_GF(NUMGF_PK));
    p22_expand(P22_honest_gf, P22_honest_bytes);

    /* 5. Compute hash_in_GF for the honest pk (this equals signed_gf). */
    uint8_t hash_honest[GF16_HASH];
    {
        expanded_PK pkx;
        SNOVA_NAMESPACE(pk_expand)(&pkx, pk_honest);
        if (snova_pkb_compute_hash_in_gf(hash_honest, &pkx, sig) != 0) {
            fprintf(stderr, "hash helper failed on honest pk\n");
            return 1;
        }
    }

    /* 6. Sample K random ΔP22, compute δ_i = L(ΔP22_i). */
    uint8_t (*deltas)[NUMGF_PK]      = malloc(sizeof(uint8_t[K][NUMGF_PK]));
    uint8_t (*delta_hash)[GF16_HASH] = malloc(sizeof(uint8_t[K][GF16_HASH]));
    if (deltas == NULL || delta_hash == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    for (int i = 0; i < K; ++i) {
        uint8_t rand_bytes[NUMGF_PK];
        randombytes(rand_bytes, sizeof(rand_bytes));
        uint8_t P22_test_gf[NUMGF_PK];
        for (size_t j = 0; j < NUMGF_PK; ++j) {
            deltas[i][j]      = rand_bytes[j] & 0x0fu;
            P22_test_gf[j]    = P22_honest_gf[j] ^ deltas[i][j];  /* XOR = add in GF(16) */
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

    /* 7. Solve for c ∈ F_16^K with Σ_i c_i · delta_hash[i] = 0.
     *    Matrix M is GF16_HASH × K, M[r][c] = delta_hash[c][r]. */
    const int rows = GF16_HASH;
    const int cols = K;
    uint8_t *M = malloc((size_t)rows * (size_t)cols);
    if (M == NULL) {
        fprintf(stderr, "M alloc failed\n");
        return 1;
    }
    for (int r = 0; r < rows; ++r) {
        for (int c2 = 0; c2 < cols; ++c2) {
            M[r * cols + c2] = delta_hash[c2][r];
        }
    }

    uint8_t *cvec = malloc((size_t)cols);
    if (cvec == NULL) {
        fprintf(stderr, "cvec alloc failed\n");
        return 1;
    }
    const int kk = gf16_find_kernel_vector(cvec, M, rows, cols);
    if (kk != 0) {
        fprintf(stderr, "kernel search failed: rc=%d (try increasing K)\n", kk);
        return 1;
    }

    /* 8. ΔP22_final[j] = Σ_i cvec[i] * deltas[i][j]. */
    uint8_t delta_final[NUMGF_PK] = {0};
    for (int i = 0; i < cols; ++i) {
        const uint8_t ci = cvec[i];
        if (ci == 0u) continue;
        for (size_t j = 0; j < NUMGF_PK; ++j) {
            delta_final[j] ^= gf_mul(ci, deltas[i][j]);
        }
    }

    /* sanity: at least some nonzero entries */
    size_t nz = 0;
    for (size_t j = 0; j < NUMGF_PK; ++j) if (delta_final[j]) ++nz;

    /* 9. Construct pk_attack. */
    uint8_t P22_attack_gf[NUMGF_PK];
    for (size_t j = 0; j < NUMGF_PK; ++j) {
        P22_attack_gf[j] = P22_honest_gf[j] ^ delta_final[j];
    }
    uint8_t P22_attack_bytes[BYTES_GF(NUMGF_PK)];
    p22_compress(P22_attack_bytes, P22_attack_gf);

    uint8_t pk_attack[SNOVA_PKB_PK_BYTES];
    memcpy(pk_attack, pk_seed, SEED_LENGTH_PUBLIC);
    memcpy(pk_attack + SEED_LENGTH_PUBLIC, P22_attack_bytes,
           BYTES_GF(NUMGF_PK));

    /* 10. Run UNMODIFIED upstream verify. */
    expanded_PK pkx_attack;
    SNOVA_NAMESPACE(pk_expand)(&pkx_attack, pk_attack);
    uint8_t digest[BYTES_DIGEST];
    shake256(digest, BYTES_DIGEST, msg, mlen);

    const int rc_attack =
        SNOVA_NAMESPACE(verify)(&pkx_attack, sig, digest, BYTES_DIGEST);

    /* 11. Byte distance. */
    const size_t nbyte_diff =
        count_byte_diffs(pk_honest, pk_attack, SNOVA_PKB_PK_BYTES);

    const int pk_changed = memcmp(pk_honest, pk_attack, SNOVA_PKB_PK_BYTES) != 0;

    printf("=== SNOVA-24_5_16_4 byte-faithful PKB-1 witness ===\n");
    printf("  Parameter set     : v=%d o=%d q=%d l=%d r=%d (NIST L1)\n",
           SNOVA_v, SNOVA_o, SNOVA_q, SNOVA_l, SNOVA_r);
    printf("  Canonical pk size : %u bytes\n", (unsigned)SNOVA_PKB_PK_BYTES);
    printf("  NUMGF_PK          : %u GF(16) elements\n", (unsigned)NUMGF_PK);
    printf("  Kernel-search K   : %d random P22 samples\n", K);
    printf("  ΔP22 nonzero GF   : %zu / %u\n", nz, (unsigned)NUMGF_PK);
    printf("  Byte distance     : %zu / %u (= %.1f%%)\n",
           nbyte_diff, (unsigned)SNOVA_PKB_PK_BYTES,
           100.0 * (double)nbyte_diff / (double)SNOVA_PKB_PK_BYTES);
    printf("  pk* != pk         : %s\n", pk_changed ? "yes" : "NO (FAIL)");
    printf("  Upstream verify   : %s\n",
           (rc_attack == 0) ? "ACCEPT (PKB-1 witnessed)" : "reject (no witness)");

    /* Also report any unchanged byte ranges. */
    if (rc_attack == 0 && pk_changed) {
        size_t seed_diff = count_byte_diffs(pk_honest, pk_attack,
                                             SEED_LENGTH_PUBLIC);
        size_t p22_diff  = count_byte_diffs(pk_honest + SEED_LENGTH_PUBLIC,
                                             pk_attack + SEED_LENGTH_PUBLIC,
                                             BYTES_GF(NUMGF_PK));
        printf("    seed bytes flipped (must be 0): %zu / %u\n",
               seed_diff, SEED_LENGTH_PUBLIC);
        printf("    P22  bytes flipped            : %zu / %u\n",
               p22_diff, (unsigned)BYTES_GF(NUMGF_PK));
    }

    free(M);
    free(cvec);
    free(deltas);
    free(delta_hash);
    return (rc_attack == 0) ? 0 : 2;
}
