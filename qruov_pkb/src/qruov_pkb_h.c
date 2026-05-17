/* QR-UOV-PKB-H (digest-in-target) implementation.
 *
 * Strategy: the wrapper feeds upstream QRUOV_Sign / QRUOV_Verify a
 * *synthetic* message
 *
 *   synth = "QRUOV-PKB-target/v1" || param_id || d_pk || u32_le(mlen) || m
 *
 * so the upstream verification target
 *
 *   y = Hash( Expand_mu(seed_pk, synth), salt )
 *
 * becomes a deterministic function of the *full* public key encoding (via
 * d_pk = SHAKE(pk_raw)), not just the 16-byte seed_pk. This closes the
 * byte-faithful PKB-1 gap that the upstream verifier leaves open: an
 * adversary who keeps seed_pk fixed and replaces P3 produces a pk_raw* that
 * has a different d_pk, hence a different synthetic message, hence a
 * different signing target, and the upstream Verify rejects.
 *
 * Wire format:
 *
 *   sm = sigma_base (200 B) || m (mlen B)            smlen = 200 + mlen
 *
 * Notably, the PKB-H signature is byte-identical to upstream QR-UOV's
 * signature format. No additional tag is appended. The PKB binding lives
 * inside the target hash.
 *
 * No upstream source file is modified.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_pkdigest.h"
#include "qruov_pkb_h.h"

#include "qruov.h"

extern int randombytes(unsigned char *x, unsigned long long xlen);
extern void restore_QRUOV_P3(const uint8_t *pool, size_t *pool_bits, QRUOV_P3 P3);

int qruov_pkb_h_keypair(uint8_t *pk, uint8_t *sk) {
    return qruov_pkb_keygen_internal(pk, sk);
}

int qruov_pkb_h_sign(uint8_t *sm, unsigned long long *smlen,
                     const uint8_t *m, unsigned long long mlen,
                     const uint8_t *sk) {
    const uint8_t *seed_sk = sk + QRUOV_PKB_SK_SEED_SK_OFFSET;
    const uint8_t *seed_pk = sk + QRUOV_PKB_SK_SEED_PK_OFFSET;
    const uint8_t *dpk     = sk + QRUOV_PKB_SK_DPK_OFFSET;

    /* Build the synthetic message that we feed to upstream Sign. */
    const size_t synth_len = qruov_pkb_h_synth_len((size_t)mlen);
    uint8_t *synth = (uint8_t *)malloc(synth_len);
    if (!synth) return -1;
    qruov_pkb_h_build_synth(synth, dpk, m, (size_t)mlen);

    /* Per-signature randomness. */
    QRUOV_SEED seed_y, seed_r, seed_sol;
    if (randombytes(seed_y,   QRUOV_PKB_INNER_SEED_BYTES) != 0) { free(synth); return -2; }
    if (randombytes(seed_r,   QRUOV_PKB_INNER_SEED_BYTES) != 0) { free(synth); return -2; }
    if (randombytes(seed_sol, QRUOV_PKB_INNER_SEED_BYTES) != 0) { free(synth); return -2; }

    /* Run upstream Sign on the synthetic message. */
    QRUOV_SIGNATURE sig;
    QRUOV_Sign((const uint8_t *)seed_sk,
               (const uint8_t *)seed_pk,
               seed_y, seed_r, seed_sol,
               synth, synth_len, sig);

    /* Pack the base signature. Bit-packed; pool_bits is not byte-aligned
     * at the tail (see qruov_pkb_keygen.c for the same observation on pk). */
    uint8_t sigma_base[QRUOV_PKB_INNER_SIG_BYTES];
    size_t pool_bits = 0;
    store_QRUOV_SIGNATURE(sig, sigma_base, &pool_bits);

    free(synth);

    /* sm = sigma_base || m  (the user message, NOT the synthetic one). */
    memcpy(sm + QRUOV_PKB_H_SM_SIG_BASE_OFFSET, sigma_base, QRUOV_PKB_INNER_SIG_BYTES);
    if (mlen) memcpy(sm + QRUOV_PKB_H_SM_MSG_OFFSET, m, (size_t)mlen);
    *smlen = QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen;

    return 0;
}

int qruov_pkb_h_open(uint8_t *m, unsigned long long *mlen,
                     const uint8_t *sm, unsigned long long smlen,
                     const uint8_t *pk) {
    if (smlen < QRUOV_PKB_H_SM_PREAMBLE_BYTES) return -1;
    const unsigned long long inner_mlen = smlen - QRUOV_PKB_H_SM_PREAMBLE_BYTES;

    const uint8_t *sigma_base = sm + QRUOV_PKB_H_SM_SIG_BASE_OFFSET;
    const uint8_t *m_in       = sm + QRUOV_PKB_H_SM_MSG_OFFSET;

    /* Recompute d_pk', then synthetic message synth' = build_synth(d_pk', m). */
    uint8_t dpk_calc[QRUOV_PKB_DPK_BYTES];
    qruov_pkb_compute_dpk(dpk_calc, pk);

    const size_t synth_len = qruov_pkb_h_synth_len((size_t)inner_mlen);
    uint8_t *synth = (uint8_t *)malloc(synth_len);
    if (!synth) return -10;
    qruov_pkb_h_build_synth(synth, dpk_calc, m_in, (size_t)inner_mlen);

    /* Unpack pk and the base signature. */
    size_t pool_bits = 0;
    QRUOV_SEED seed_pk_inner;
    restore_QRUOV_SEED(pk, &pool_bits, seed_pk_inner);

    QRUOV_P3 *P3 = (QRUOV_P3 *)malloc(sizeof(QRUOV_P3));
    if (!P3) { free(synth); return -11; }
    restore_QRUOV_P3(pk, &pool_bits, *P3);

    size_t sig_pool_bits = 0;
    QRUOV_SIGNATURE sig;
    restore_QRUOV_SIGNATURE(sigma_base, &sig_pool_bits, sig);

    int ok = QRUOV_Verify((const uint8_t *)seed_pk_inner, *P3,
                          synth, synth_len, sig);
    free(P3);
    free(synth);
    if (!ok) return -2;

    if (inner_mlen) memcpy(m, m_in, (size_t)inner_mlen);
    *mlen = inner_mlen;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Self-test                                                           */
/* ------------------------------------------------------------------ */

int qruov_pkb_h_selftest(void) {
    uint8_t *pk = (uint8_t *)malloc(QRUOV_PKB_PK_BYTES);
    uint8_t sk[QRUOV_PKB_SK_BYTES];
    if (!pk) return -1;

    if (qruov_pkb_h_keypair(pk, sk) != 0) { free(pk); return -2; }

    const unsigned long long mlen = 64;
    uint8_t msg[64];

    uint8_t *sm = (uint8_t *)malloc(QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen);
    uint8_t *m_out = (uint8_t *)malloc(mlen);
    if (!sm || !m_out) { free(pk); free(sm); free(m_out); return -3; }

    /* 8 random round-trips. */
    for (int t = 0; t < 8; t++) {
        for (int i = 0; i < (int)mlen; i++)
            msg[i] = (uint8_t)((t * 53 + i * 11) & 0xFFu);

        unsigned long long smlen = 0;
        if (qruov_pkb_h_sign(sm, &smlen, msg, mlen, sk) != 0) {
            free(pk); free(sm); free(m_out); return -4;
        }
        if (smlen != QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen) {
            free(pk); free(sm); free(m_out); return -5;
        }

        unsigned long long mlen2 = 0;
        if (qruov_pkb_h_open(m_out, &mlen2, sm, smlen, pk) != 0) {
            free(pk); free(sm); free(m_out); return -6;
        }
        if (mlen2 != mlen || memcmp(msg, m_out, (size_t)mlen) != 0) {
            free(pk); free(sm); free(m_out); return -7;
        }
    }

    /* Negative tests. */
    for (int i = 0; i < (int)mlen; i++) msg[i] = (uint8_t)(0x55 ^ i);
    unsigned long long smlen = 0;
    if (qruov_pkb_h_sign(sm, &smlen, msg, mlen, sk) != 0) {
        free(pk); free(sm); free(m_out); return -8;
    }

    unsigned long long m2len;

    /* (N1) flip byte of sigma_base -> reject. */
    sm[QRUOV_PKB_H_SM_SIG_BASE_OFFSET + 13] ^= 0x40u;
    if (qruov_pkb_h_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -20;
    }
    sm[QRUOV_PKB_H_SM_SIG_BASE_OFFSET + 13] ^= 0x40u;

    /* (N2) flip byte of the message body -> reject (synth message changes). */
    if (mlen > 0) {
        sm[QRUOV_PKB_H_SM_MSG_OFFSET] ^= 0x10u;
        if (qruov_pkb_h_open(m_out, &m2len, sm, smlen, pk) == 0) {
            free(pk); free(sm); free(m_out); return -21;
        }
        sm[QRUOV_PKB_H_SM_MSG_OFFSET] ^= 0x10u;
    }

    /* (N3) flip a byte of pk in the P3 region (does NOT change seed_pk,
     * mirrors the byte-faithful PKB-1 attack scenario) -> reject. */
    pk[QRUOV_PKB_INNER_SEED_BYTES + 7] ^= 0x80u;
    if (qruov_pkb_h_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -22;
    }
    pk[QRUOV_PKB_INNER_SEED_BYTES + 7] ^= 0x80u;

    /* (N4) flip a byte of seed_pk in pk -> reject. */
    pk[2] ^= 0x04u;
    if (qruov_pkb_h_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -23;
    }
    pk[2] ^= 0x04u;

    /* (N5) truncated sm -> reject. */
    if (qruov_pkb_h_open(m_out, &m2len, sm,
                         QRUOV_PKB_H_SM_PREAMBLE_BYTES - 1, pk) == 0) {
        free(pk); free(sm); free(m_out); return -24;
    }

    /* (N6) trailing-byte tamper -> reject (synth message length mismatch). */
    {
        uint8_t *sm2 = (uint8_t *)malloc(smlen + 1);
        uint8_t *m_out2 = (uint8_t *)malloc(mlen + 1);
        if (!sm2 || !m_out2) {
            free(sm2); free(m_out2);
            free(pk); free(sm); free(m_out); return -25;
        }
        memcpy(sm2, sm, smlen);
        sm2[smlen] = 0xC3u;
        if (qruov_pkb_h_open(m_out2, &m2len, sm2, smlen + 1, pk) == 0) {
            free(sm2); free(m_out2);
            free(pk); free(sm); free(m_out); return -26;
        }
        free(sm2); free(m_out2);
    }

    /* (N7) independent random signatures verify, and are bit-distinct. */
    unsigned long long smlen_a = 0, smlen_b = 0;
    uint8_t *sm_a = (uint8_t *)malloc(QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen);
    uint8_t *sm_b = (uint8_t *)malloc(QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen);
    if (!sm_a || !sm_b) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -27;
    }
    if (qruov_pkb_h_sign(sm_a, &smlen_a, msg, mlen, sk) != 0
     || qruov_pkb_h_sign(sm_b, &smlen_b, msg, mlen, sk) != 0) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -28;
    }
    if (memcmp(sm_a, sm_b, (size_t)smlen_a) == 0) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -29;
    }
    if (qruov_pkb_h_open(m_out, &m2len, sm_a, smlen_a, pk) != 0
     || qruov_pkb_h_open(m_out, &m2len, sm_b, smlen_b, pk) != 0) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -30;
    }
    free(sm_a); free(sm_b);

    free(pk); free(sm); free(m_out);
    return 0;
}
