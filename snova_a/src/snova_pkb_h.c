/* SNOVA-PKB-H wrapper: digest-in-target binding on upstream SNOVA(24,5,16,4).
 *
 * The wrapper does not modify upstream SNOVA source files.  It calls
 *   SNOVA_NAMESPACE(genkeys), SNOVA_NAMESPACE(sk_expand),
 *   SNOVA_NAMESPACE(pk_expand), SNOVA_NAMESPACE(sign), SNOVA_NAMESPACE(verify)
 * as black-box low-level primitives.  The only modification relative to the
 * stock NIST API path (sign.c) is that the digest fed to upstream sign/verify
 * is taken over the *synthetic* message
 *   synth = "SNOVA-PKB-target/v1" || id || d_pk || u32_LE(|m|) || m
 * instead of the raw user message. */

#include "snova_pkb.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rng.h"
#include "snova.h"
#include "symmetric.h"

/* The synthetic message buffer is allocated on the heap so the wrapper
 * imposes no static upper bound on |m|.  For embedded contexts a caller
 * may pre-allocate; the heap path is fine for the experiments and
 * benchmarks reported in the paper. */
static uint8_t *snova_pkb_alloc_synth(uint8_t id,
                                      const uint8_t d_pk[SNOVA_PKB_DPK_BYTES],
                                      const uint8_t *m, size_t mlen,
                                      size_t *out_len) {
    const size_t cap = sizeof(SNOVA_PKB_DST_TARGET) - 1u
                     + 1u
                     + SNOVA_PKB_DPK_BYTES
                     + 4u
                     + mlen;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        return NULL;
    }
    const size_t written = snova_pkb_build_synth(buf, cap, id, d_pk, m, mlen);
    if (written == 0u) {
        free(buf);
        return NULL;
    }
    *out_len = written;
    return buf;
}

int snova_pkb_h_keygen_with_seed(uint8_t pk[SNOVA_PKB_PK_BYTES],
                                 uint8_t sk[SNOVA_PKB_SK_BYTES],
                                 const uint8_t seed[48]) {
    uint8_t inner_sk[SNOVA_PKB_INNER_SK_BYTES];
    const int rc = SNOVA_NAMESPACE(genkeys)(pk, inner_sk, seed);
    if (rc != 0) {
        return rc;
    }
    memcpy(sk, inner_sk, SNOVA_PKB_INNER_SK_BYTES);
    snova_pkb_pkdigest(sk + SNOVA_PKB_INNER_SK_BYTES, pk, SNOVA_PKB_PK_BYTES);
    return 0;
}

int snova_pkb_h_keygen(uint8_t pk[SNOVA_PKB_PK_BYTES],
                       uint8_t sk[SNOVA_PKB_SK_BYTES]) {
    uint8_t seed[48];
    randombytes(seed, sizeof(seed));
    return snova_pkb_h_keygen_with_seed(pk, sk, seed);
}

int snova_pkb_h_sign(uint8_t sig[SNOVA_PKB_SIG_BYTES],
                     const uint8_t sk[SNOVA_PKB_SK_BYTES],
                     const uint8_t *pk_for_check,
                     const uint8_t *m, size_t mlen) {
    /* Recover d_pk: either trust the cache or recompute from pk_for_check. */
    uint8_t d_pk[SNOVA_PKB_DPK_BYTES];
    if (pk_for_check != NULL) {
        snova_pkb_pkdigest(d_pk, pk_for_check, SNOVA_PKB_PK_BYTES);
        if (memcmp(d_pk, sk + SNOVA_PKB_INNER_SK_BYTES,
                   SNOVA_PKB_DPK_BYTES) != 0) {
            return -1;  /* pk/sk inconsistency */
        }
    } else {
        memcpy(d_pk, sk + SNOVA_PKB_INNER_SK_BYTES, SNOVA_PKB_DPK_BYTES);
    }

    size_t synth_len = 0u;
    uint8_t *synth = snova_pkb_alloc_synth(SNOVA_PKB_PROFILE_ID_H,
                                           d_pk, m, mlen, &synth_len);
    if (synth == NULL) {
        return -1;
    }

    expanded_SK skx;
    if (SNOVA_NAMESPACE(sk_expand)(&skx, sk) != 0) {
        free(synth);
        return -1;
    }

    uint8_t digest[BYTES_DIGEST];
    shake256(digest, BYTES_DIGEST, synth, synth_len);

    uint8_t salt[BYTES_SALT];
    randombytes(salt, BYTES_SALT);

    const int rc = SNOVA_NAMESPACE(sign)(&skx, sig, digest, BYTES_DIGEST, salt);

    free(synth);
    return rc;
}

int snova_pkb_h_verify(const uint8_t pk[SNOVA_PKB_PK_BYTES],
                       const uint8_t sig[SNOVA_PKB_SIG_BYTES],
                       const uint8_t *m, size_t mlen) {
    uint8_t d_pk[SNOVA_PKB_DPK_BYTES];
    snova_pkb_pkdigest(d_pk, pk, SNOVA_PKB_PK_BYTES);

    size_t synth_len = 0u;
    uint8_t *synth = snova_pkb_alloc_synth(SNOVA_PKB_PROFILE_ID_H,
                                           d_pk, m, mlen, &synth_len);
    if (synth == NULL) {
        return -1;
    }

    expanded_PK pkx;
    if (SNOVA_NAMESPACE(pk_expand)(&pkx, pk) != 0) {
        free(synth);
        return -1;
    }

    uint8_t digest[BYTES_DIGEST];
    shake256(digest, BYTES_DIGEST, synth, synth_len);

    const int rc = SNOVA_NAMESPACE(verify)(&pkx, sig, digest, BYTES_DIGEST);

    free(synth);
    return rc;
}
