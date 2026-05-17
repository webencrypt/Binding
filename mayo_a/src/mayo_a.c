/* MAYO-PKB wrapper (paper §5.2).
 *
 * Digest-tag transform of Lemma~\ref{lem:generic-pkb} applied to MAYO
 * with no anchor.  The PKB layer derives:
 *
 *   pk    = inner MAYO compact pk                 (canonical, 1420 B at L1)
 *   d_pk  = SHAKE256(pk || "MAYO-PKB-v1/pk-digest")[:DPK_BYTES]   -- derived
 *   sk    = master_seed (32 B) || d_pk_cache (DPK_BYTES)          -- impl
 *   sigma = sigma_MAYO || tau                     (470 B at L1)
 *   tau   = SHAKE256(d_pk || msg || sigma_MAYO ||
 *                    "MAYO-PKB-v1/sig-bind")[:TAU_BYTES]
 *
 * KeyGen (paper §5.2):
 *   1. sample / accept 32 B master_seed
 *   2. seed_sk := SHAKE-Derive(master_seed || "MAYO-PKB-v1/mayo-sk")
 *   3. preset randombytes() -> seed_sk; call mayo_keypair() unchanged
 *   4. compute d_pk over the resulting canonical pk; cache in sk
 *
 * Sign (paper §5.2):
 *   1. re-derive seed_sk from sk[0..32] = master_seed
 *   2. mayo_sign(sm, &inner_smlen, msg, mlen, seed_sk) places sigma_MAYO||msg
 *   3. compute tau over (sk[32..] = d_pk_cache, msg, sigma_MAYO)
 *   4. shift msg right by TAU_BYTES, splice tau between sigma_MAYO and msg
 *
 * Open (paper §5.2):
 *   1. compute d_pk' = SHAKE256(pk || "MAYO-PKB-v1/pk-digest")
 *   2. read tau from sm[INNER..INNER+TAU]
 *   3. recompute tau' from (d_pk', msg, sigma_MAYO); reject in constant time
 *      if tau != tau' (MAYO-check-before-tag-check; see Vrfy algorithm)
 *   4. assemble sigma_MAYO || msg in a temp buffer and call mayo_open
 *
 * The MAYO inner primitives are unchanged; the PKB layer is implemented
 * by this wrapper alone.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mayo_a.h"
#include "mayo_a_rng.h"

#include "mayo.h"
#include "fips202.h"

#ifdef ENABLE_PARAMS_DYNAMIC
#  if MAYO_A_LEVEL == 1
extern const mayo_params_t MAYO_1;
#    define MAYO_A_INNER_PARAMS (&MAYO_1)
#  elif MAYO_A_LEVEL == 3
extern const mayo_params_t MAYO_3;
#    define MAYO_A_INNER_PARAMS (&MAYO_3)
#  else
#    error "Unsupported MAYO_A_LEVEL"
#  endif
#else
#define MAYO_A_INNER_PARAMS ((const mayo_params_t *)0)
#endif

/* ------------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------*/

static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Tagged-SHAKE helper: out := SHAKE256(seed || tag).  The trailing
 * domain-separation tag is appended without a NUL terminator. */
static void tagged_shake256(uint8_t *out, size_t outlen,
                            const uint8_t *seed, size_t seedlen,
                            const char *tag) {
    size_t taglen = strlen(tag);
    size_t inlen  = seedlen + taglen;
    uint8_t *buf  = (uint8_t *)malloc(inlen);
    if (!buf) abort();
    memcpy(buf,            seed, seedlen);
    memcpy(buf + seedlen,  tag,  taglen);
    shake256(out, outlen, buf, inlen);
    free(buf);
}

/* Derive the MAYO inner seed_sk from the canonical master_seed. */
static void derive_inner_seed(uint8_t inner_seed[MAYO_A_INNER_SEED_BYTES],
                              const uint8_t master_seed[MAYO_A_MASTER_SEED_BYTES]) {
    tagged_shake256(inner_seed, MAYO_A_INNER_SEED_BYTES,
                    master_seed, MAYO_A_MASTER_SEED_BYTES,
                    MAYO_A_TAG_MAYO_SK);
}

/* ------------------------------------------------------------------------
 * PKB-layer helpers (paper §5.2).
 *
 * mayo_a_compute_dpk:
 *   d_pk := SHAKE256(pk || "MAYO-PKB-v1/pk-digest")[:DPK_BYTES].
 *
 * mayo_a_compute_tau:
 *   tau := SHAKE256(d_pk || msg || sigma_inner ||
 *                   "MAYO-PKB-v1/sig-bind")[:TAU_BYTES].
 * ----------------------------------------------------------------------*/

void mayo_a_compute_dpk(uint8_t dpk[MAYO_A_DPK_BYTES],
                        const uint8_t pk[MAYO_A_PK_BYTES]) {
    tagged_shake256(dpk, MAYO_A_DPK_BYTES,
                    pk, MAYO_A_PK_BYTES,
                    MAYO_A_TAG_PK_DIGEST);
}

void mayo_a_compute_tau(uint8_t tau[MAYO_A_TAU_BYTES],
                        const uint8_t dpk[MAYO_A_DPK_BYTES],
                        const uint8_t *msg, size_t mlen,
                        const uint8_t sigma_inner[MAYO_A_INNER_SIG_BYTES]) {
    size_t prefix_len = (size_t)MAYO_A_DPK_BYTES + mlen + (size_t)MAYO_A_INNER_SIG_BYTES;
    uint8_t *buf = (uint8_t *)malloc(prefix_len);
    if (!buf) abort();
    memcpy(buf,                                    dpk,         MAYO_A_DPK_BYTES);
    memcpy(buf + MAYO_A_DPK_BYTES,                 msg,         mlen);
    memcpy(buf + MAYO_A_DPK_BYTES + mlen,          sigma_inner, MAYO_A_INNER_SIG_BYTES);
    tagged_shake256(tau, MAYO_A_TAU_BYTES,
                    buf, prefix_len,
                    MAYO_A_TAG_SIG_BIND);
    free(buf);
}

/* ------------------------------------------------------------------------
 * KeyGen
 * ----------------------------------------------------------------------*/

int mayo_a_keypair_with_seed(uint8_t *pk, uint8_t *sk,
                             const uint8_t *master_seed) {
    uint8_t inner_seed[MAYO_A_INNER_SEED_BYTES];
    uint8_t inner_sk[MAYO_A_INNER_SK_BYTES];

    derive_inner_seed(inner_seed, master_seed);

    /* Feed inner_seed deterministically to MAYO via the randombytes shim. */
    mayo_a_rng_preset(inner_seed, sizeof(inner_seed));
    int rc = mayo_keypair(MAYO_A_INNER_PARAMS, pk, inner_sk);
    mayo_a_rng_clear();
    if (rc != MAYO_OK) return -1;

    /* Implementation sk = master_seed || d_pk_cache.  The canonical sk in
     * the paper is the 32-byte master_seed alone; caching d_pk lets Sign
     * produce tau without recomputing the full public key. */
    memcpy(sk, master_seed, MAYO_A_MASTER_SEED_BYTES);
    mayo_a_compute_dpk(sk + MAYO_A_SK_DPK_OFFSET, pk);

    return 0;
}

int mayo_a_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t master_seed[MAYO_A_MASTER_SEED_BYTES];
    extern int randombytes(unsigned char *x, size_t xlen);
    if (randombytes(master_seed, MAYO_A_MASTER_SEED_BYTES) != 0) return -1;
    return mayo_a_keypair_with_seed(pk, sk, master_seed);
}

/* ------------------------------------------------------------------------
 * Sign:  sm = sigma_MAYO || tau || msg
 * ----------------------------------------------------------------------*/

int mayo_a_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    /* Step 1: re-derive the inner MAYO seed from the canonical master_seed. */
    uint8_t inner_seed[MAYO_A_INNER_SEED_BYTES];
    derive_inner_seed(inner_seed, sk);

    /* Step 2: inner MAYO sign.  mayo_sign writes sigma_MAYO || msg into sm. */
    size_t inner_smlen = 0;
    int rc = mayo_sign(MAYO_A_INNER_PARAMS, sm, &inner_smlen, m, mlen,
                       inner_seed);
    if (rc != MAYO_OK) return rc;
    if (inner_smlen != (size_t)MAYO_A_INNER_SIG_BYTES + mlen) return -2;

    /* Step 3: compute tau over (d_pk_cache, msg, sigma_MAYO).  The msg used
     * here must be the caller-supplied buffer m, not the in-place copy
     * sitting in sm, to avoid confusion if the caller passes m == sm. */
    uint8_t tau[MAYO_A_TAU_BYTES];
    mayo_a_compute_tau(tau, sk + MAYO_A_SK_DPK_OFFSET, m, mlen, sm);

    /* Step 4: shift msg right by TAU_BYTES so we can splice tau in between. */
    memmove(sm + MAYO_A_INNER_SIG_BYTES + MAYO_A_TAU_BYTES,
            sm + MAYO_A_INNER_SIG_BYTES,
            mlen);
    memcpy(sm + MAYO_A_INNER_SIG_BYTES, tau, MAYO_A_TAU_BYTES);

    *smlen = (size_t)MAYO_A_INNER_SIG_BYTES + (size_t)MAYO_A_TAU_BYTES + mlen;
    return 0;
}

/* ------------------------------------------------------------------------
 * Open (verify)
 * ----------------------------------------------------------------------*/

int mayo_a_open(uint8_t *m, size_t *mlen,
                const uint8_t *sm, size_t smlen,
                const uint8_t *pk) {
    if (smlen < (size_t)MAYO_A_INNER_SIG_BYTES + (size_t)MAYO_A_TAU_BYTES)
        return -1;
    size_t plain_len = smlen - MAYO_A_INNER_SIG_BYTES - MAYO_A_TAU_BYTES;

    /* Step 1: recompute d_pk from the canonical public key. */
    uint8_t dpk[MAYO_A_DPK_BYTES];
    mayo_a_compute_dpk(dpk, pk);

    /* Step 2: recompute tau from (d_pk, msg, sigma_MAYO). */
    const uint8_t *sigma_inner = sm;
    const uint8_t *tau_in      = sm + MAYO_A_INNER_SIG_BYTES;
    const uint8_t *msg_in      = sm + MAYO_A_INNER_SIG_BYTES + MAYO_A_TAU_BYTES;

    uint8_t tau_check[MAYO_A_TAU_BYTES];
    mayo_a_compute_tau(tau_check, dpk, msg_in, plain_len, sigma_inner);

    if (!ct_memeq(tau_in, tau_check, MAYO_A_TAU_BYTES))
        return -2;

    /* Step 3: PKB-layer tag accepted; assemble (sigma_MAYO || msg) into a
     * fresh buffer and run the unmodified MAYO verifier. */
    size_t inner_smlen = (size_t)MAYO_A_INNER_SIG_BYTES + plain_len;
    uint8_t *inner_sm = (uint8_t *)malloc(inner_smlen);
    if (!inner_sm) return -3;
    memcpy(inner_sm,                             sigma_inner, MAYO_A_INNER_SIG_BYTES);
    memcpy(inner_sm + MAYO_A_INNER_SIG_BYTES,    msg_in,      plain_len);

    int rc = mayo_open(MAYO_A_INNER_PARAMS, m, mlen, inner_sm, inner_smlen,
                       pk);
    free(inner_sm);
    return rc;
}

/* ------------------------------------------------------------------------
 * Self-test: KeyGen + Sign + Open round-trips on synthetic messages.
 * ----------------------------------------------------------------------*/

int mayo_a_selftest(int num_samples) {
    uint8_t pk[MAYO_A_PK_BYTES];
    uint8_t sk[MAYO_A_SK_BYTES];

    if (mayo_a_keypair(pk, sk) != 0) return -1;

    /* Sanity: cached d_pk in sk must match the on-the-fly recomputation. */
    uint8_t dpk_check[MAYO_A_DPK_BYTES];
    mayo_a_compute_dpk(dpk_check, pk);
    if (!ct_memeq(sk + MAYO_A_SK_DPK_OFFSET, dpk_check, MAYO_A_DPK_BYTES))
        return -2;

    for (int t = 0; t < num_samples; t++) {
        uint8_t msg[64];
        for (int i = 0; i < 64; i++) msg[i] = (uint8_t)((t * 31 + i * 7) & 0xFF);

        size_t smlen = 0;
        uint8_t sm[MAYO_A_SIG_BYTES + 64];
        if (mayo_a_sign(sm, &smlen, msg, 64, sk) != 0) return -3;
        if (smlen != (size_t)MAYO_A_SIG_BYTES + 64)    return -4;

        size_t mlen2 = 0;
        uint8_t m2[64];
        if (mayo_a_open(m2, &mlen2, sm, smlen, pk) != 0) return -5;
        if (mlen2 != 64)                                  return -6;
        if (memcmp(msg, m2, 64) != 0)                     return -7;
    }
    return 0;
}
