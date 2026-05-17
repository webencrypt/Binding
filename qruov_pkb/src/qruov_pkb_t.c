/* QR-UOV-PKB-T (tag-only) implementation.
 *
 * KeyGen: sample upstream (seed_sk, seed_pk), run QRUOV_KeyGen, pack pk_raw,
 *         compute d_pk over pk_raw, cache (seed_sk, seed_pk, d_pk) in sk.
 *
 * Sign:   re-read (seed_sk, seed_pk, d_pk) from sk; sample upstream
 *         (seed_y, seed_r, seed_sol); call QRUOV_Sign on the user message m;
 *         pack the resulting signature as sigma_base[200]; compute
 *         tau = H( tag || param_id || d_pk || u32_le(mlen) || m || sigma_base );
 *         output sm = sigma_base || tau || m.
 *
 * Open:   compute d_pk' from pk_raw, parse sm into (sigma_base, tau_recv, m),
 *         recompute tau_calc and constant-time compare (reject early on
 *         mismatch), unpack the upstream sig and P3, call QRUOV_Verify.
 *
 * The upstream QR-UOV primitives QRUOV_KeyGen, QRUOV_Sign, QRUOV_Verify and
 * the byte-packers store_QRUOV_SEED / store_QRUOV_P3 /
 * store_QRUOV_SIGNATURE / restore_QRUOV_SEED / restore_QRUOV_P3 /
 * restore_QRUOV_SIGNATURE are called as black boxes; no upstream source
 * file is modified.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_pkdigest.h"
#include "qruov_pkb_t.h"

/* Upstream headers. qruov.h pulls in matrix.h / Fql.h via its includes. */
#include "qruov.h"

/* Upstream global RNG.  rng.h declares randombytes(); we call it for the
 * five 16-byte seeds (sk, pk, y, r, sol). */
extern int randombytes(unsigned char *x, unsigned long long xlen);

/* Upstream packers (declared inline-static or extern in qruov.h /
 * matrix.c). */
extern void store_QRUOV_P3(const QRUOV_P3 P3, uint8_t *pool, size_t *pool_bits);
extern void restore_QRUOV_P3(const uint8_t *pool, size_t *pool_bits, QRUOV_P3 P3);

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int qruov_pkb_t_keypair(uint8_t *pk, uint8_t *sk) {
    /* Shared keygen lives in qruov_pkb_keygen.c. */
    return qruov_pkb_keygen_internal(pk, sk);
}

int qruov_pkb_t_sign(uint8_t *sm, unsigned long long *smlen,
                     const uint8_t *m, unsigned long long mlen,
                     const uint8_t *sk) {
    /* Re-read seeds and cached digest from sk. */
    const uint8_t *seed_sk = sk + QRUOV_PKB_SK_SEED_SK_OFFSET;
    const uint8_t *seed_pk = sk + QRUOV_PKB_SK_SEED_PK_OFFSET;
    const uint8_t *dpk     = sk + QRUOV_PKB_SK_DPK_OFFSET;

    /* Per-signature randomness for upstream QR-UOV. Upstream expects three
     * 16-byte seeds (y, r, sol). */
    QRUOV_SEED seed_y, seed_r, seed_sol;
    if (randombytes(seed_y,   QRUOV_PKB_INNER_SEED_BYTES) != 0) return -1;
    if (randombytes(seed_r,   QRUOV_PKB_INNER_SEED_BYTES) != 0) return -1;
    if (randombytes(seed_sol, QRUOV_PKB_INNER_SEED_BYTES) != 0) return -1;

    /* Cast away const to satisfy upstream API which is not const-correct
     * on the seed parameters. The values are not modified. */
    QRUOV_SIGNATURE sig;
    QRUOV_Sign((const uint8_t *)seed_sk,
               (const uint8_t *)seed_pk,
               seed_y, seed_r, seed_sol,
               m, (size_t)mlen, sig);

    /* Pack sig into sigma_base[200]. Upstream's store_QRUOV_SIGNATURE
     * writes a bit-packed signature whose tail bits are zero-padded inside
     * the final byte; the canonical byte count is QRUOV_PKB_INNER_SIG_BYTES
     * by spec. */
    uint8_t sigma_base[QRUOV_PKB_INNER_SIG_BYTES];
    size_t pool_bits = 0;
    store_QRUOV_SIGNATURE(sig, sigma_base, &pool_bits);

    /* Compute tau = H( tag || param_id || d_pk || u32_le(mlen) || m || sigma_base ). */
    uint8_t tau[QRUOV_PKB_TAU_BYTES];
    qruov_pkb_compute_tau_t(tau, dpk, m, (size_t)mlen, sigma_base);

    /* sm = sigma_base || tau || m */
    memcpy(sm + QRUOV_PKB_T_SM_SIG_BASE_OFFSET, sigma_base, QRUOV_PKB_INNER_SIG_BYTES);
    memcpy(sm + QRUOV_PKB_T_SM_TAU_OFFSET,      tau,        QRUOV_PKB_TAU_BYTES);
    if (mlen) memcpy(sm + QRUOV_PKB_T_SM_MSG_OFFSET, m, (size_t)mlen);
    *smlen = QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen;

    return 0;
}

int qruov_pkb_t_open(uint8_t *m, unsigned long long *mlen,
                     const uint8_t *sm, unsigned long long smlen,
                     const uint8_t *pk) {
    /* Length sanity: at minimum we need the preamble (sigma_base || tau). */
    if (smlen < QRUOV_PKB_T_SM_PREAMBLE_BYTES) return -1;
    const unsigned long long inner_mlen = smlen - QRUOV_PKB_T_SM_PREAMBLE_BYTES;

    const uint8_t *sigma_base = sm + QRUOV_PKB_T_SM_SIG_BASE_OFFSET;
    const uint8_t *tau_recv   = sm + QRUOV_PKB_T_SM_TAU_OFFSET;
    const uint8_t *m_in       = sm + QRUOV_PKB_T_SM_MSG_OFFSET;

    /* Recompute d_pk' from pk and tau' from (d_pk', m, sigma_base). */
    uint8_t dpk_calc[QRUOV_PKB_DPK_BYTES];
    qruov_pkb_compute_dpk(dpk_calc, pk);

    uint8_t tau_calc[QRUOV_PKB_TAU_BYTES];
    qruov_pkb_compute_tau_t(tau_calc, dpk_calc, m_in, (size_t)inner_mlen, sigma_base);

    if (!qruov_pkb_ct_eq16(tau_recv, tau_calc)) return -2;

    /* Tag accepted; now run upstream QR-UOV verification on (pk, m, sig). */
    size_t pool_bits = 0;
    QRUOV_SEED seed_pk_inner;
    restore_QRUOV_SEED(pk, &pool_bits, seed_pk_inner);

    QRUOV_P3 *P3 = (QRUOV_P3 *)malloc(sizeof(QRUOV_P3));
    if (!P3) return -10;
    restore_QRUOV_P3(pk, &pool_bits, *P3);

    size_t sig_pool_bits = 0;
    QRUOV_SIGNATURE sig;
    restore_QRUOV_SIGNATURE(sigma_base, &sig_pool_bits, sig);

    int ok = QRUOV_Verify((const uint8_t *)seed_pk_inner, *P3,
                          m_in, (size_t)inner_mlen, sig);
    free(P3);
    if (!ok) return -3;

    if (inner_mlen) memcpy(m, m_in, (size_t)inner_mlen);
    *mlen = inner_mlen;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Self-test                                                           */
/* ------------------------------------------------------------------ */

int qruov_pkb_t_selftest(void) {
    uint8_t *pk = (uint8_t *)malloc(QRUOV_PKB_PK_BYTES);
    uint8_t sk[QRUOV_PKB_SK_BYTES];
    if (!pk) return -1;

    if (qruov_pkb_t_keypair(pk, sk) != 0) { free(pk); return -2; }

    const unsigned long long mlen = 64;
    uint8_t msg[64];

    uint8_t *sm = (uint8_t *)malloc(QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen);
    uint8_t *m_out = (uint8_t *)malloc(mlen);
    if (!sm || !m_out) { free(pk); free(sm); free(m_out); return -3; }

    /* 8 random round-trips. */
    for (int t = 0; t < 8; t++) {
        for (int i = 0; i < (int)mlen; i++)
            msg[i] = (uint8_t)((t * 31 + i * 7) & 0xFFu);

        unsigned long long smlen = 0;
        if (qruov_pkb_t_sign(sm, &smlen, msg, mlen, sk) != 0) {
            free(pk); free(sm); free(m_out); return -4;
        }
        if (smlen != QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen) {
            free(pk); free(sm); free(m_out); return -5;
        }

        unsigned long long mlen2 = 0;
        if (qruov_pkb_t_open(m_out, &mlen2, sm, smlen, pk) != 0) {
            free(pk); free(sm); free(m_out); return -6;
        }
        if (mlen2 != mlen || memcmp(msg, m_out, (size_t)mlen) != 0) {
            free(pk); free(sm); free(m_out); return -7;
        }
    }

    /* Negative test pack: produce one honest signature, then mutate. */
    for (int i = 0; i < (int)mlen; i++) msg[i] = (uint8_t)(0xAA ^ i);
    unsigned long long smlen = 0;
    if (qruov_pkb_t_sign(sm, &smlen, msg, mlen, sk) != 0) {
        free(pk); free(sm); free(m_out); return -8;
    }

    /* (N1) flip byte 0 of tau -> reject (-2). */
    sm[QRUOV_PKB_T_SM_TAU_OFFSET] ^= 0x01u;
    unsigned long long m2len;
    if (qruov_pkb_t_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -20;
    }
    sm[QRUOV_PKB_T_SM_TAU_OFFSET] ^= 0x01u; /* restore */

    /* (N2) flip a byte of sigma_base -> reject. */
    sm[QRUOV_PKB_T_SM_SIG_BASE_OFFSET + 7] ^= 0x80u;
    if (qruov_pkb_t_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -21;
    }
    sm[QRUOV_PKB_T_SM_SIG_BASE_OFFSET + 7] ^= 0x80u;

    /* (N3) flip a byte of the message body -> reject. */
    if (mlen > 0) {
        sm[QRUOV_PKB_T_SM_MSG_OFFSET] ^= 0x10u;
        if (qruov_pkb_t_open(m_out, &m2len, sm, smlen, pk) == 0) {
            free(pk); free(sm); free(m_out); return -22;
        }
        sm[QRUOV_PKB_T_SM_MSG_OFFSET] ^= 0x10u;
    }

    /* (N4) flip a byte of pk (the P3 region, not seed_pk) -> reject. */
    pk[QRUOV_PKB_INNER_SEED_BYTES + 11] ^= 0x40u;
    if (qruov_pkb_t_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -23;
    }
    pk[QRUOV_PKB_INNER_SEED_BYTES + 11] ^= 0x40u;

    /* (N5) flip a byte of pk's seed region -> reject (changes both d_pk
     * and upstream verification target). */
    pk[3] ^= 0x02u;
    if (qruov_pkb_t_open(m_out, &m2len, sm, smlen, pk) == 0) {
        free(pk); free(sm); free(m_out); return -24;
    }
    pk[3] ^= 0x02u;

    /* (N6) truncated sm (shorter than preamble) -> reject (-1). */
    if (qruov_pkb_t_open(m_out, &m2len, sm,
                         QRUOV_PKB_T_SM_PREAMBLE_BYTES - 1, pk) == 0) {
        free(pk); free(sm); free(m_out); return -25;
    }

    /* (N7) trailing-byte tamper: append 1 byte to sm; preamble parses fine,
     * but the recomputed tau covers (mlen+1) bytes of msg, so reject. */
    {
        uint8_t *sm2 = (uint8_t *)malloc(smlen + 1);
        if (!sm2) { free(pk); free(sm); free(m_out); return -26; }
        memcpy(sm2, sm, smlen);
        sm2[smlen] = 0x99u;
        uint8_t *m_out2 = (uint8_t *)malloc(mlen + 1);
        if (!m_out2) { free(sm2); free(pk); free(sm); free(m_out); return -27; }
        if (qruov_pkb_t_open(m_out2, &m2len, sm2, smlen + 1, pk) == 0) {
            free(sm2); free(m_out2);
            free(pk); free(sm); free(m_out); return -28;
        }
        free(sm2); free(m_out2);
    }

    /* (N8) determinism: same sk + same msg + reused randomness chain ->
     * upstream Sign is randomized via per-call randombytes; we cannot
     * trivially compare bit-identical signatures here. We instead verify
     * that two fresh independent Sign calls each verify successfully and
     * that they produce distinct signed-message blobs (with overwhelming
     * probability). */
    unsigned long long smlen_a = 0, smlen_b = 0;
    uint8_t *sm_a = (uint8_t *)malloc(QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen);
    uint8_t *sm_b = (uint8_t *)malloc(QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen);
    if (!sm_a || !sm_b) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -29;
    }
    if (qruov_pkb_t_sign(sm_a, &smlen_a, msg, mlen, sk) != 0
     || qruov_pkb_t_sign(sm_b, &smlen_b, msg, mlen, sk) != 0) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -30;
    }
    if (memcmp(sm_a, sm_b, (size_t)smlen_a) == 0) {
        /* Either upstream RNG is degenerate or seeds happened to collide;
         * both indicate a problem worth surfacing in a self-test. */
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -31;
    }
    if (qruov_pkb_t_open(m_out, &m2len, sm_a, smlen_a, pk) != 0
     || qruov_pkb_t_open(m_out, &m2len, sm_b, smlen_b, pk) != 0) {
        free(sm_a); free(sm_b);
        free(pk); free(sm); free(m_out); return -32;
    }
    free(sm_a); free(sm_b);

    free(pk); free(sm); free(m_out);
    return 0;
}
