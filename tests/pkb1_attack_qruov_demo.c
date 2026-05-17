/* Byte-faithful PKB-1 violation demonstration on QR-UOV-Ipks-1
 * (q = 127, v = 156, m = 54, L = 3) reference implementation.
 *
 * Threat model (paper Theorem MQ Non-Binding, §3.2):
 *   The plain QR-UOV verifier accepts (pk, msg, sig) iff for every
 *   i in [m]:
 *     msg[i] = ( y^T  Pi1*(seed_pk)  y
 *              + 2 y^T Pi2*(seed_pk) oil
 *              + oil^T Pi3*[i]       oil )[perm(0)]
 *   where msg = Hash( Expand_mu(seed_pk, message), sig.r ).  Substituting
 *   a fresh seed_pk* changes (Pi1*, Pi2*, msg*) but leaves the attacker
 *   free to pick Pi3*[i].  Each i is one F_q linear equation in the
 *   three F_q coefficients of Pi3*[i][0][0] = (c_0, c_1, c_2) in F_q^L;
 *   we set c_0 = (msg*[i] - partial_i) / oil_diag_perm0  and  c_1=c_2=0.
 *
 * Output:
 *   * `honest_verify`   = 1  (sanity)
 *   * `attack_verify`   = 1  (PKB-1 violation: a different pk* accepts
 *                             the same sig on the same message)
 *   * `pk_differs`      = 1  (pk* != pk byte-for-byte)
 *
 * CLI: optional `--trials N` runs N independent trials (default 1).
 *       N>1 prints a compact SUMMARY line; N=1 prints full detail.
 *
 * We compile this file by #include "qruov.c" so the static helpers
 * Expand_mu, Hash, Expand_pk become visible in this translation unit.
 * We do NOT link the upstream qruov.o; CMake's pkb1_attack_qruov_demo
 * target uses pkb1_attack_qruov_demo.o as the qruov compilation unit.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The portable64 sources expect parameters via -D. */
#include "qruov_config.h"
#include "qruov.h"
#include "matrix.h"
#include "Fql.h"
#include "rng.h"

/* Bring the upstream qruov.c (with all its static helpers) into THIS
 * translation unit so we can call Expand_mu, Hash, Expand_pk directly.
 * The non-static symbols (QRUOV_KeyGen, QRUOV_Sign, QRUOV_Verify,
 * store_QRUOV_P3, restore_QRUOV_P3) are exported from this object. */
#include "qruov.c"

/* ----------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------- */
static int bytes_differ(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) return 1;
    return 0;
}

static void hex_dump(const char *label, const uint8_t *buf, size_t n) {
    printf("  %s [", label);
    for (size_t i = 0; i < n && i < 16; i++) printf("%02x", buf[i]);
    if (n > 16) printf("...");
    printf("]  (%zu bytes)\n", n);
}

/* ----------------------------------------------------------------------
 * PKB-1 attack: given (sig, msg, sig.r), construct (seed_pk*, P3*) such
 * that QRUOV_Verify(seed_pk*, P3*, msg, mlen, sig) == 1.
 * -------------------------------------------------------------------- */
static int pkb1_attack(const QRUOV_SEED   seed_pk_honest,
                       const QRUOV_SIGNATURE sig,
                       const uint8_t     *msg,
                       size_t             mlen,
                       QRUOV_SEED         seed_pk_star,   /* out */
                       QRUOV_P3           P3_star) {       /* out */
    /* 1. Pick seed_pk* != seed_pk_honest at random until distinct. */
    do {
        randombytes(seed_pk_star, QRUOV_SEED_LEN);
    } while (memcmp(seed_pk_star, seed_pk_honest, QRUOV_SEED_LEN) == 0);

    /* 2. Compute msg* = Hash( Expand_mu(seed_pk*, msg), sig.r ).
     *    These are the target F_q^m values for the new verifier. */
    uint8_t mu_star[QRUOV_MU_LEN];
    Expand_mu(seed_pk_star, msg, mlen, mu_star);
    Fq msg_star[QRUOV_m];
    Hash(mu_star, sig->r, msg_star);

    /* 3. Extract the signature's vineger and oil components. */
    const Fql *vineger = sig->s;
    const Fql *oil     = sig->s + QRUOV_V;

    /* Precompute oil[0]^2 in F_{q^L}.  Pi3*[i][0][0] = c will contribute
     *   u_final = oil[0] * c * oil[0] = oil[0]^2 * c   (in F_{q^L})
     * and we need u_final[perm(0)] = (msg*[i] - t_final[perm(0)]).  Setting
     * c = (c_0, 0, 0) with c_0 in F_q makes u_final[perm(0)] = c_0 *
     * (oil[0]^2)[perm(0)], so we just need that one F_q coordinate of
     * oil[0]^2 to be invertible.  Otherwise we'd fall back to a
     * different (j0, k0) position. */
    Fql oil0       = oil[0];
    Fql oil0_sq    = Fql_reduction(Fql_mul(oil0, oil0));
    Fq  oil0_sq_p0 = Fql2Fq(oil0_sq, QRUOV_perm(0));
    if (oil0_sq_p0 == 0) {
        fprintf(stderr,
                "[pkb1_attack] oil[0]^2 has zero perm(0) coordinate "
                "(low-prob: fallback to (j0,k0) not implemented in demo)\n");
        return -1;
    }
    Fq inv_oil0_sq_p0 = Fq_inv(oil0_sq_p0);

    /* 4. For each i in [0, m), compute partial verifier value using
     *    seed_pk*'s Pi1*, Pi2* with Pi3=0, then solve for Pi3*[i][0][0]. */
    memset(P3_star, 0, sizeof(QRUOV_P3));

    MATRIX_VxV Pi1;
    MATRIX_VxM Pi2;
    MATRIX_MxV Pi2T;

    QRUOV_PRG_CTX *ctx_pk_star = PRG_init(seed_pk_star);
    for (int i = 0; i < QRUOV_m; i++) {
        Expand_pk(ctx_pk_star, i, Pi1, Pi2);
        MATRIX_TRANSPOSE_VxM(Pi2, Pi2T);

        /* tmp_v[j] = (sum_k Pi2T[k][j] * oil[k]) * 2 + sum_k Pi1[j][k] * vineger[k]
         * t_final  = sum_j vineger[j] * tmp_v[j]
         * Use the upstream-exposed dot-product helpers; they handle Fql
         * reduction.  This mirrors VERIFY_i's first half exactly. */
        Fql tmp_v[QRUOV_V];
        for (int j = 0; j < QRUOV_V; j++) {
            /* (Pi2T row j) . oil ; multiplied by 2 ; + (Pi1 row j) . vineger */
            VECTOR_M row_pi2t;
            for (int k = 0; k < QRUOV_M; k++) row_pi2t[k] = Pi2T[k][j];
            Fql t = VECTOR_M_dot_VECTOR_M(row_pi2t, oil);
            Fql u = VECTOR_V_dot_VECTOR_V(vineger, Pi1[j]);
            tmp_v[j] = Fql_add(Fql_add(t, t), u);
        }
        Fql t_final = VECTOR_V_dot_VECTOR_V(vineger, tmp_v);

        /* We want msg*[i] = (t_final + u_final)[perm(0)].
         * With Pi3*[i] sparse at (0,0)=c=(c_0,0,0), u_final = c_0 * oil[0]^2.
         * So c_0 = (msg*[i] - t_final[perm(0)]) / (oil[0]^2)[perm(0)]. */
        Fq target = Fq_sub(msg_star[i], Fql2Fq(t_final, QRUOV_perm(0)));
        Fq c0 = Fq_mul(target, inv_oil0_sq_p0);
        P3_star[i][0][0] = Fq2Fql_immediate((Fql)c0, (Fql)0, (Fql)0);
    }
    PRG_final(ctx_pk_star);

    return 0;
}


/* ----------------------------------------------------------------------
 * Main driver
 * -------------------------------------------------------------------- */
static const uint8_t default_test_message[] =
    "PKB-1 violation demo on byte-faithful QR-UOV-Ipks-1.\n";

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--trials N]\n"
            "  --trials N   run N independent PKB-1 demonstrations (default 1).\n"
            "               Each trial uses a distinct RNG seed (trial index\n"
            "               XOR-mixed into the reproducible base seed).\n"
            "               N>1 prints a compact summary; N=1 prints full detail.\n",
            prog);
}

/* Returns 0 if PKB-1 violation confirmed (honest verify, attack verify,
 * pk* != pk bytewise). Non-zero exit codes match single-trial main() legacy:
 * 1 attack path failed, 2 honest verify failed, 3 attack construction, 4 OOM.
 * On success and out_diff_bytes non-NULL, writes Hamming distance. */
static int run_one_trial(unsigned trial_index, int verbose,
                         size_t *out_diff_bytes) {
    uint8_t rng_seed[48];
    for (int i = 0; i < 48; i++) rng_seed[i] = (uint8_t)(i * 17 + 5);
    rng_seed[0] ^= (uint8_t)(trial_index & 0xffu);
    rng_seed[1] ^= (uint8_t)((trial_index >> 8) & 0xffu);
    rng_seed[2] ^= (uint8_t)((trial_index >> 16) & 0xffu);
    rng_seed[3] ^= (uint8_t)((trial_index >> 24) & 0xffu);
    randombytes_init(rng_seed, NULL, 256);

    QRUOV_SEED seed_sk, seed_pk;
    randombytes(seed_sk, QRUOV_SEED_LEN);
    randombytes(seed_pk, QRUOV_SEED_LEN);

    static QRUOV_P3 P3;
    QRUOV_KeyGen(seed_sk, seed_pk, P3);

    QRUOV_SEED seed_y, seed_r, seed_sol;
    randombytes(seed_y, QRUOV_SEED_LEN);
    randombytes(seed_r, QRUOV_SEED_LEN);
    randombytes(seed_sol, QRUOV_SEED_LEN);

    QRUOV_SIGNATURE sig;
    QRUOV_Sign(seed_sk, seed_pk, seed_y, seed_r, seed_sol,
               default_test_message, sizeof(default_test_message) - 1, sig);

    if (verbose) {
        printf("Honest key generation and signing: OK\n");
        hex_dump("seed_pk     ", seed_pk, QRUOV_SEED_LEN);
        hex_dump("sig.r (salt)", sig->r, QRUOV_SALT_LEN);
    }

    int honest_ok = QRUOV_Verify(seed_pk, P3, default_test_message,
                                 sizeof(default_test_message) - 1, sig);
    if (verbose)
        printf("Honest verify: %s\n\n", honest_ok ? "OK" : "FAIL");
    if (!honest_ok) {
        if (!verbose)
            fprintf(stderr, "trial %u: honest verify FAIL\n", trial_index);
        return 2;
    }

    QRUOV_SEED seed_pk_star;
    static QRUOV_P3 P3_star;
    int attack_rc =
        pkb1_attack(seed_pk, sig, default_test_message,
                    sizeof(default_test_message) - 1, seed_pk_star, P3_star);
    if (attack_rc != 0) {
        if (!verbose)
            fprintf(stderr, "trial %u: attack construction failed rc=%d\n",
                    trial_index, attack_rc);
        else
            fprintf(stderr, "Attack construction failed (rc=%d)\n", attack_rc);
        return 3;
    }
    if (verbose) {
        printf("PKB-1 attack construction: OK\n");
        hex_dump("seed_pk*    ", seed_pk_star, QRUOV_SEED_LEN);
    }

    int attack_ok =
        QRUOV_Verify(seed_pk_star, P3_star, default_test_message,
                     sizeof(default_test_message) - 1, sig);
    if (verbose)
        printf("Attack verify under pk*: %s\n", attack_ok ? "OK" : "FAIL");

    const size_t pk_bits =
        (size_t)QRUOV_SEED_LEN * 8
        + (size_t)QRUOV_m * (size_t)QRUOV_M * (size_t)(QRUOV_M + 1) / 2
                 * (size_t)QRUOV_L * (size_t)QRUOV_ceil_log_2_q;
    const size_t pk_bytes_len = (pk_bits + 7) / 8;
    uint8_t *pk_bytes = calloc(pk_bytes_len + 16, 1);
    uint8_t *pk_star_bytes = calloc(pk_bytes_len + 16, 1);
    if (!pk_bytes || !pk_star_bytes) {
        free(pk_bytes);
        free(pk_star_bytes);
        fprintf(stderr, "OOM\n");
        return 4;
    }

    size_t bits = 0;
    store_QRUOV_SEED(seed_pk, pk_bytes, &bits);
    store_QRUOV_P3(P3, pk_bytes, &bits);

    bits = 0;
    store_QRUOV_SEED(seed_pk_star, pk_star_bytes, &bits);
    store_QRUOV_P3(P3_star, pk_star_bytes, &bits);

    int pk_differs = bytes_differ(pk_bytes, pk_star_bytes, pk_bytes_len);
    size_t diff_bytes = 0;
    for (size_t i = 0; i < pk_bytes_len; i++)
        if (pk_bytes[i] != pk_star_bytes[i]) diff_bytes++;

    if (verbose) {
        printf("pk size (computed): %zu bytes\n", pk_bytes_len);
        printf("pk* != pk (bytewise): %s\n", pk_differs ? "OK" : "FAIL");
        printf("bytes that differ: %zu / %zu (%.2f%%)\n\n", diff_bytes,
               pk_bytes_len, 100.0 * diff_bytes / pk_bytes_len);
    }

    free(pk_bytes);
    free(pk_star_bytes);

    if (out_diff_bytes)
        *out_diff_bytes = diff_bytes;

    if (honest_ok && attack_ok && pk_differs)
        return 0;
    if (!verbose)
        fprintf(stderr,
                "trial %u: attack failed (honest=%d, attack=%d, differ=%d)\n",
                trial_index, honest_ok, attack_ok, pk_differs);
    return 1;
}

int main(int argc, char **argv) {
    unsigned long trials = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trials") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            char *end = NULL;
            trials = strtoul(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || trials == 0
                || trials > 1000000UL) {
                fprintf(stderr, "%s: invalid --trials value\n", argv[0]);
                print_usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "%s: unknown argument `%s`\n", argv[0], argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("=================================================\n");
    printf(" Byte-faithful PKB-1 violation: QR-UOV-Ipks-1\n");
    printf(" Parameters: q=%d, v=%d, m=%d, L=%d\n",
           QRUOV_q, QRUOV_v, QRUOV_m, QRUOV_L);
    printf(" Trials: %lu\n", trials);
    printf("=================================================\n\n");

    if (trials == 1) {
        size_t diff_bytes = 0;
        int rc = run_one_trial(0, 1, &diff_bytes);
        printf("=================================================\n");
        if (rc == 0) {
            printf(" RESULT: PKB-1 violation operationally confirmed\n");
            printf("         on byte-faithful QR-UOV-Ipks-1 reference\n");
            printf("         (q=%d, v=%d, m=%d, L=%d).\n",
                   QRUOV_q, QRUOV_v, QRUOV_m, QRUOV_L);
            printf("=================================================\n");
            return 0;
        }
        printf(" RESULT: attack failed (exit %d)\n", rc);
        printf("=================================================\n");
        return rc;
    }

    unsigned long ok = 0;
    size_t first_diff = 0;
    for (unsigned long t = 0; t < trials; t++) {
        size_t diff = 0;
        int rc = run_one_trial((unsigned)t, 0, &diff);
        if (rc == 0) {
            ok++;
            if (ok == 1)
                first_diff = diff;
        }
    }

    printf("SUMMARY: %lu / %lu trials PKB-1 violation confirmed "
           "(honest verify, attack verify, pk* != pk)\n",
           ok, trials);
    if (ok == trials)
        printf("All trials succeeded.\n");
    else
        printf("Some trials failed; see stderr for per-trial messages.\n");
    if (ok > 0)
        printf("Example Hamming distance (trial 0 success path): %zu bytes "
               "differ (first successful trial).\n",
               first_diff);

    return (ok == trials) ? 0 : 1;
}
