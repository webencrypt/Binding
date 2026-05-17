/* QR-UOV-PKB-H blocks the byte-faithful PKB-1 attack.
 *
 * This experiment connects the upstream-level byte-faithful PKB-1 attack
 * (see tests/pkb1_attack_qruov_demo.c) to the QR-UOV-PKB-H verifier and
 * shows that the same attack that succeeds against the upstream QR-UOV
 * verifier is rejected by PKB-H Open with overwhelming probability.
 *
 *   Threat model: an adversary obtains a PKB-H signed message
 *     sm = sigma_base (200 B) || m
 *   together with the honest public key pk. The adversary may inspect the
 *   PKB-H specification and reconstruct the synthetic target the wrapper
 *   passed to upstream QR-UOV:
 *     synth = build_synth(d_pk_honest, m).
 *   The adversary then runs the upstream-level byte-faithful PKB-1 attack
 *   on (seed_pk_honest, sig, synth) to produce a distinct public key
 *     pk_star = (seed_pk_star, P3_star)
 *   such that the upstream verifier QRUOV_Verify(seed_pk_star, P3_star,
 *   synth, synth_len, sig) = 1.
 *
 *   Wrapper defence: PKB-H Open recomputes d_pk_star := SHAKE(pk_star),
 *   builds synth_star := build_synth(d_pk_star, m), and calls
 *     QRUOV_Verify(seed_pk_star, P3_star, synth_star, synth_star_len, sig).
 *   Since d_pk_star != d_pk_honest with probability 1 - q/2^{256} (target
 *   collision), synth_star != synth, and the upstream verifier rejects.
 *
 * We compile this file with `#include "qruov.c"` so we can call the static
 * helpers Expand_mu, Hash, Expand_pk needed to mount the PKB-1 attack.
 * The non-static symbols (QRUOV_KeyGen, QRUOV_Sign, QRUOV_Verify,
 * store/restore_QRUOV_P3, store/restore_QRUOV_SIGNATURE,
 * store/restore_QRUOV_SEED) are then exported from this translation unit,
 * so we do NOT link upstream qruov.c (CMake's PKB1_BLOCK_SOURCES list).
 *
 * CLI:
 *   ./pkb1_attack_qruov_pkb_block               # 100 trials (default)
 *   ./pkb1_attack_qruov_pkb_block --trials N    # custom trial count
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qruov_config.h"
#include "qruov.h"
#include "matrix.h"
#include "Fql.h"
#include "rng.h"

/* Bring upstream qruov.c (and its statics Expand_mu/Hash/Expand_pk) into
 * this translation unit. */
#include "qruov.c"

#include "params_qruov_pkb.h"
#include "qruov_pkb_pkdigest.h"
#include "qruov_pkb_h.h"

/* ---------------------------------------------------------------- */
/* Byte-faithful PKB-1 attack against the upstream verifier.        */
/* Identical to tests/pkb1_attack_qruov_demo.c::pkb1_attack but kept */
/* local so the two demos can evolve independently.                  */
/* ---------------------------------------------------------------- */
static int pkb1_attack_upstream(const QRUOV_SEED   seed_pk_honest,
                                const QRUOV_SIGNATURE sig,
                                const uint8_t     *msg,
                                size_t             mlen,
                                QRUOV_SEED         seed_pk_star,
                                QRUOV_P3           P3_star) {
    do {
        randombytes(seed_pk_star, QRUOV_SEED_LEN);
    } while (memcmp(seed_pk_star, seed_pk_honest, QRUOV_SEED_LEN) == 0);

    uint8_t mu_star[QRUOV_MU_LEN];
    Expand_mu(seed_pk_star, msg, mlen, mu_star);
    Fq msg_star[QRUOV_m];
    Hash(mu_star, sig->r, msg_star);

    const Fql *vineger = sig->s;
    const Fql *oil     = sig->s + QRUOV_V;

    Fql oil0       = oil[0];
    Fql oil0_sq    = Fql_reduction(Fql_mul(oil0, oil0));
    Fq  oil0_sq_p0 = Fql2Fq(oil0_sq, QRUOV_perm(0));
    if (oil0_sq_p0 == 0) return -1;
    Fq inv_oil0_sq_p0 = Fq_inv(oil0_sq_p0);

    memset(P3_star, 0, sizeof(QRUOV_P3));

    MATRIX_VxV Pi1;
    MATRIX_VxM Pi2;
    MATRIX_MxV Pi2T;

    QRUOV_PRG_CTX *ctx_pk_star = PRG_init(seed_pk_star);
    for (int i = 0; i < QRUOV_m; i++) {
        Expand_pk(ctx_pk_star, i, Pi1, Pi2);
        MATRIX_TRANSPOSE_VxM(Pi2, Pi2T);

        Fql tmp_v[QRUOV_V];
        for (int j = 0; j < QRUOV_V; j++) {
            VECTOR_M row_pi2t;
            for (int k = 0; k < QRUOV_M; k++) row_pi2t[k] = Pi2T[k][j];
            Fql t = VECTOR_M_dot_VECTOR_M(row_pi2t, oil);
            Fql u = VECTOR_V_dot_VECTOR_V(vineger, Pi1[j]);
            tmp_v[j] = Fql_add(Fql_add(t, t), u);
        }
        Fql t_final = VECTOR_V_dot_VECTOR_V(vineger, tmp_v);

        Fq target = Fq_sub(msg_star[i], Fql2Fq(t_final, QRUOV_perm(0)));
        Fq c0 = Fq_mul(target, inv_oil0_sq_p0);
        P3_star[i][0][0] = Fq2Fql_immediate((Fql)c0, (Fql)0, (Fql)0);
    }
    PRG_final(ctx_pk_star);
    return 0;
}

/* Pack (seed_pk, P3) into the canonical pk byte layout used by the PKB-H
 * wrapper (16-byte seed_pk || P3_packed). */
static void pack_pk_canonical(uint8_t *pk_out,
                              const QRUOV_SEED seed_pk,
                              QRUOV_P3 P3) {
    size_t pool_bits = 0;
    store_QRUOV_SEED(seed_pk, pk_out, &pool_bits);
    store_QRUOV_P3(P3, pk_out, &pool_bits);
    /* The store_* helpers leave pool_bits possibly non-multiple-of-8; the
     * canonical pk byte count is QRUOV_PKB_PK_BYTES and any trailing bits
     * inside the last byte are zero-padded by store_QRUOV_P3. */
}

/* ---------------------------------------------------------------- */
/* Per-trial driver                                                  */
/* ---------------------------------------------------------------- */
typedef struct {
    int upstream_attack_success;  /* 1 if QRUOV_Verify accepted pk_star */
    int pkb_h_rejected;           /* 1 if qruov_pkb_h_open rejected pk_star */
    int pk_differs;               /* 1 if pk_star != pk_honest bytewise */
    int dpk_differs;              /* 1 if d_pk_star != d_pk_honest        */
    size_t hamming_bytes;         /* number of differing bytes pk vs pk*  */
} trial_result_t;

static int run_one_trial(unsigned trial_index, trial_result_t *out, int verbose) {
    memset(out, 0, sizeof(*out));

    /* Per-trial deterministic DRBG reseed (same pattern as pkb1 demo). */
    uint8_t rng_seed[48];
    for (int i = 0; i < 48; i++) rng_seed[i] = (uint8_t)(i * 23 + 11);
    rng_seed[0] ^= (uint8_t)(trial_index & 0xffu);
    rng_seed[1] ^= (uint8_t)((trial_index >> 8) & 0xffu);
    rng_seed[2] ^= (uint8_t)((trial_index >> 16) & 0xffu);
    rng_seed[3] ^= (uint8_t)((trial_index >> 24) & 0xffu);
    randombytes_init(rng_seed, NULL, 256);

    /* 1. PKB-H KeyGen + Sign. */
    uint8_t *pk = (uint8_t *)malloc(QRUOV_PKB_PK_BYTES);
    if (!pk) return -1;
    uint8_t sk[QRUOV_PKB_SK_BYTES];
    if (qruov_pkb_h_keypair(pk, sk) != 0) { free(pk); return -2; }

    const uint8_t test_msg[] = "PKB-H blocks byte-faithful PKB-1 attack.";
    const size_t  mlen       = sizeof(test_msg) - 1;

    const size_t sm_b = QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen;
    uint8_t *sm = (uint8_t *)malloc(sm_b);
    if (!sm) { free(pk); return -3; }
    unsigned long long smlen = 0;
    if (qruov_pkb_h_sign(sm, &smlen, test_msg, mlen, sk) != 0) {
        free(pk); free(sm); return -4;
    }

    /* Sanity: honest PKB-H Open accepts. */
    uint8_t m_out[64];
    unsigned long long mlen_out = 0;
    if (qruov_pkb_h_open(m_out, &mlen_out, sm, smlen, pk) != 0) {
        free(pk); free(sm); return -5;
    }

    /* 2. Adversary inspects the wrapper spec and reconstructs the
     *    synthetic message that upstream Sign actually signed. */
    const uint8_t *dpk_honest = sk + QRUOV_PKB_SK_DPK_OFFSET;
    const size_t synth_len = qruov_pkb_h_synth_len(mlen);
    uint8_t *synth = (uint8_t *)malloc(synth_len);
    if (!synth) { free(pk); free(sm); return -6; }
    qruov_pkb_h_build_synth(synth, dpk_honest, test_msg, mlen);

    /* 3. Adversary reconstructs the upstream signature object from
     *    sigma_base = sm[0..200]. */
    QRUOV_SIGNATURE sig;
    size_t sig_pool_bits = 0;
    restore_QRUOV_SIGNATURE(sm + QRUOV_PKB_H_SM_SIG_BASE_OFFSET,
                            &sig_pool_bits, sig);

    /* 4. Adversary extracts honest seed_pk from pk[0..16]. */
    QRUOV_SEED seed_pk_honest;
    memcpy(seed_pk_honest, pk, QRUOV_SEED_LEN);

    /* Sanity check (independent of attack): upstream-level honest verify
     * succeeds on synth, since that is what was actually signed. We need P3
     * to do this, so we restore it from pk[16..]. We allocate P3 on the heap
     * because sizeof(QRUOV_P3) ~ 24 KB. */
    QRUOV_P3 *P3_honest = (QRUOV_P3 *)malloc(sizeof(QRUOV_P3));
    if (!P3_honest) { free(pk); free(sm); free(synth); return -7; }
    {
        size_t pool_bits = QRUOV_SEED_LEN * 8u;
        restore_QRUOV_P3(pk, &pool_bits, *P3_honest);
    }
    int honest_upstream_ok = QRUOV_Verify(seed_pk_honest, *P3_honest,
                                          synth, synth_len, sig);
    if (!honest_upstream_ok) {
        free(P3_honest); free(pk); free(sm); free(synth);
        return -8;  /* should never happen if PKB-H is consistent */
    }

    /* 5. Mount the upstream-level byte-faithful PKB-1 attack on synth. */
    QRUOV_SEED seed_pk_star;
    QRUOV_P3  *P3_star = (QRUOV_P3 *)malloc(sizeof(QRUOV_P3));
    if (!P3_star) {
        free(P3_honest); free(pk); free(sm); free(synth);
        return -9;
    }
    int attack_rc = pkb1_attack_upstream(seed_pk_honest, sig,
                                         synth, synth_len,
                                         seed_pk_star, *P3_star);
    if (attack_rc != 0) {
        /* Low-probability degenerate (oil[0]^2 has zero perm(0) coord);
         * count as inconclusive trial. */
        free(P3_star); free(P3_honest); free(pk); free(sm); free(synth);
        if (verbose) fprintf(stderr, "[trial %u] attack construction degenerate\n", trial_index);
        return -10;
    }

    /* 6. Verify upstream-level PKB-1 violation. */
    out->upstream_attack_success =
        QRUOV_Verify(seed_pk_star, *P3_star, synth, synth_len, sig);

    /* 7. Pack pk_star canonically and check pk_star != pk. */
    uint8_t *pk_star = (uint8_t *)malloc(QRUOV_PKB_PK_BYTES);
    if (!pk_star) {
        free(P3_star); free(P3_honest); free(pk); free(sm); free(synth);
        return -11;
    }
    pack_pk_canonical(pk_star, seed_pk_star, *P3_star);

    size_t diff = 0;
    for (size_t i = 0; i < QRUOV_PKB_PK_BYTES; i++)
        if (pk[i] != pk_star[i]) diff++;
    out->pk_differs    = (diff != 0);
    out->hamming_bytes = diff;

    /* 8. Compare d_pk values. */
    uint8_t dpk_star[QRUOV_PKB_DPK_BYTES];
    qruov_pkb_compute_dpk(dpk_star, pk_star);
    out->dpk_differs = (memcmp(dpk_star, dpk_honest, QRUOV_PKB_DPK_BYTES) != 0);

    /* 9. The key claim: PKB-H Open rejects pk_star. */
    int pkb_h_rc = qruov_pkb_h_open(m_out, &mlen_out, sm, smlen, pk_star);
    out->pkb_h_rejected = (pkb_h_rc != 0);

    if (verbose) {
        printf("  upstream_attack_success = %d\n", out->upstream_attack_success);
        printf("  pk_differs              = %d  (%zu / %u bytes differ)\n",
               out->pk_differs, out->hamming_bytes, (unsigned)QRUOV_PKB_PK_BYTES);
        printf("  d_pk_differs            = %d\n", out->dpk_differs);
        printf("  pkb_h_open returned     = %d  -> PKB-H rejected = %d\n",
               pkb_h_rc, out->pkb_h_rejected);
    }

    free(pk_star); free(P3_star); free(P3_honest);
    free(pk); free(sm); free(synth);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--trials N]\n"
            "  --trials N   run N independent trials (default 100).\n"
            "               Each trial uses a deterministic reseed of the DRBG.\n",
            prog);
}

int main(int argc, char **argv) {
    unsigned long trials = 100;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trials") == 0) {
            if (i + 1 >= argc) { print_usage(argv[0]); return 1; }
            char *end = NULL;
            trials = strtoul(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || trials == 0
                || trials > 1000000UL) {
                fprintf(stderr, "%s: invalid --trials value\n", argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unknown argument `%s`\n", argv[0], argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("=========================================================\n");
    printf(" PKB-H blocks byte-faithful PKB-1 attack on QR-UOV-Ipks-1\n");
    printf(" Parameters: q=%d, v=%d, m=%d, L=%d   trials = %lu\n",
           QRUOV_q, QRUOV_v, QRUOV_m, QRUOV_L, trials);
    printf("=========================================================\n");

    unsigned long upstream_succ = 0;
    unsigned long pkb_h_rej     = 0;
    unsigned long pk_diff       = 0;
    unsigned long dpk_diff      = 0;
    unsigned long degenerate    = 0;
    unsigned long pkb_h_accepted_pk_star = 0;
    size_t        first_diff_bytes       = 0;

    for (unsigned long t = 0; t < trials; t++) {
        trial_result_t r;
        int rc = run_one_trial((unsigned)t, &r, (trials == 1) ? 1 : 0);
        if (rc == -10) { degenerate++; continue; }
        if (rc != 0) {
            fprintf(stderr, "trial %lu: setup failed rc=%d\n", t, rc);
            return 1;
        }
        if (r.upstream_attack_success) upstream_succ++;
        if (r.pkb_h_rejected) pkb_h_rej++;
        else if (r.pk_differs)                 pkb_h_accepted_pk_star++;
        if (r.pk_differs) pk_diff++;
        if (r.dpk_differs) dpk_diff++;
        if (upstream_succ == 1 && first_diff_bytes == 0)
            first_diff_bytes = r.hamming_bytes;
    }

    const unsigned long valid_trials = trials - degenerate;

    printf("\n--- RESULTS over %lu trials (%lu degenerate, %lu valid) ---\n",
           trials, degenerate, valid_trials);
    printf("  Upstream PKB-1 attack succeeded   : %lu / %lu  (target: %lu)\n",
           upstream_succ, valid_trials, valid_trials);
    printf("  pk_star != pk (bytewise)          : %lu / %lu\n",
           pk_diff, valid_trials);
    printf("  d_pk_star != d_pk_honest          : %lu / %lu\n",
           dpk_diff, valid_trials);
    printf("  PKB-H Open rejected pk_star       : %lu / %lu  (target: %lu)\n",
           pkb_h_rej, valid_trials, valid_trials);
    if (pkb_h_accepted_pk_star > 0)
        printf("  *** WARNING: PKB-H Open ACCEPTED %lu adversarial pk* ***\n",
               pkb_h_accepted_pk_star);
    if (first_diff_bytes)
        printf("  Example Hamming distance pk vs pk*: %zu / %u bytes\n",
               first_diff_bytes, (unsigned)QRUOV_PKB_PK_BYTES);

    int strong_claim = (upstream_succ == valid_trials)
                    && (pkb_h_rej     == valid_trials)
                    && (valid_trials  >  0);

    printf("\n");
    if (strong_claim) {
        printf("RESULT: PKB-H blocks the byte-faithful PKB-1 attack in\n");
        printf("        %lu / %lu valid trials (100%%).\n",
               pkb_h_rej, valid_trials);
        return 0;
    }
    printf("RESULT: PKB-H blocked %lu / %lu valid trials.\n",
           pkb_h_rej, valid_trials);
    return (pkb_h_accepted_pk_star == 0) ? 0 : 2;
}
