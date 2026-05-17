#ifndef QRUOV_PKB_PARAMS_H
#define QRUOV_PKB_PARAMS_H

/* QR-UOV-PKB-Ipks-1: Public-Key Binding wrappers around QR-UOV-Ipks-1
 * (NIST L1, Round 2 spec).
 *
 * Two profiles, sharing identical KeyGen and identical public-key digest:
 *
 *   QR-UOV-PKB-T (tag-only):
 *     Vrfy checks (i) upstream QR-UOV verification on (pk_raw, m, sigma_base)
 *     and (ii) tau == H(d_pk || m || sigma_base).
 *     Same-byte-transcript binding under target-collision resistance of
 *     H_pk and H_tag.
 *
 *   QR-UOV-PKB-H (digest-in-target):
 *     Sign and Vrfy call upstream QR-UOV with a synthetic message
 *     "QRUOV-PKB-target/v1" || param_id || d_pk || u32_le(mlen) || m
 *     so that the QR-UOV signing target is a deterministic function of
 *     (pk_raw, m). The signature itself is unchanged byte-for-byte from
 *     upstream QR-UOV.
 *
 * Both profiles:
 *   - leave upstream QR-UOV's KeyGen/Sign/Vrfy primitives untouched
 *     (call them as black boxes via the documented low-level API);
 *   - use the same canonical public-key encoding as upstream:
 *     pk_raw = seed_pk (16 B) || P3_packed (24240 B), total 24256 B;
 *   - cache d_pk in the secret key so Sign needs no pk_raw input;
 *   - use the same lambda_pkb = 128 (NIST L1) and TCR-conservative
 *     digest length 2 lambda_pkb / 8 = 32 B for d_pk, lambda_pkb / 8 = 16 B
 *     for tau (only PKB-T has tau).
 *
 * Public key layout:
 *   [0, 16):       seed_pk_inner          (16 B, upstream QR-UOV public seed)
 *   [16, 24256):   P3_packed              (24240 B, upstream QR-UOV P3)
 *   Total pk = 24256 B  (== upstream QR-UOV CRYPTO_PUBLICKEYBYTES, byte-faithful)
 *
 * Secret key layout (64 B, both profiles):
 *   [0, 16):       seed_sk_inner          (16 B)
 *   [16, 32):      seed_pk_inner          (16 B; cached for Sign/Vrfy convenience)
 *   [32, 64):      d_pk_cache             (32 B)
 *
 * Signature layout:
 *   PKB-T:  sm = sigma_base (200 B) || tau (16 B) || message (mlen B), smlen = 216 + mlen
 *   PKB-H:  sm = sigma_base (200 B) || message (mlen B), smlen = 200 + mlen
 */

#include <stddef.h>
#include <stdint.h>

/* ---- Inner QR-UOV-Ipks-1 sizes (must match upstream CRYPTO_*) ---- */
#define QRUOV_PKB_INNER_PK_BYTES    24256u   /* upstream CRYPTO_PUBLICKEYBYTES   */
#define QRUOV_PKB_INNER_SK_BYTES    32u      /* upstream CRYPTO_SECRETKEYBYTES   */
#define QRUOV_PKB_INNER_SIG_BYTES   200u     /* upstream CRYPTO_BYTES            */
#define QRUOV_PKB_INNER_SEED_BYTES  16u      /* upstream QRUOV_SEED_LEN          */

/* ---- PKB security parameter and digest/tag sizes ---- */
#define QRUOV_PKB_LAMBDA_BITS       128u     /* NIST L1                          */
#define QRUOV_PKB_DPK_BYTES         (2u * QRUOV_PKB_LAMBDA_BITS / 8u)   /* 32 */
#define QRUOV_PKB_TAU_BYTES         (QRUOV_PKB_LAMBDA_BITS / 8u)        /* 16 */

/* ---- Canonical layout ---- */
#define QRUOV_PKB_PK_BYTES          QRUOV_PKB_INNER_PK_BYTES            /* 24256 */
#define QRUOV_PKB_SK_BYTES          (2u * QRUOV_PKB_INNER_SEED_BYTES \
                                     + QRUOV_PKB_DPK_BYTES)             /* 64 */

/* PKB-T overhead is tau bytes only; PKB-H overhead is zero on the signature
 * (the binding lives in the target hash). */
#define QRUOV_PKB_T_SIG_OVERHEAD    QRUOV_PKB_TAU_BYTES                 /* 16 */
#define QRUOV_PKB_H_SIG_OVERHEAD    0u

/* ---- SK field offsets ---- */
#define QRUOV_PKB_SK_SEED_SK_OFFSET 0u
#define QRUOV_PKB_SK_SEED_PK_OFFSET QRUOV_PKB_INNER_SEED_BYTES          /* 16 */
#define QRUOV_PKB_SK_DPK_OFFSET     (2u * QRUOV_PKB_INNER_SEED_BYTES)   /* 32 */

/* ---- SM (signed message) offsets in the PKB-T layout ---- */
#define QRUOV_PKB_T_SM_SIG_BASE_OFFSET 0u
#define QRUOV_PKB_T_SM_TAU_OFFSET      QRUOV_PKB_INNER_SIG_BYTES        /* 200 */
#define QRUOV_PKB_T_SM_MSG_OFFSET      (QRUOV_PKB_INNER_SIG_BYTES + QRUOV_PKB_TAU_BYTES) /* 216 */
#define QRUOV_PKB_T_SM_PREAMBLE_BYTES  QRUOV_PKB_T_SM_MSG_OFFSET        /* 216 */

/* ---- SM offsets in the PKB-H layout ---- */
#define QRUOV_PKB_H_SM_SIG_BASE_OFFSET 0u
#define QRUOV_PKB_H_SM_MSG_OFFSET      QRUOV_PKB_INNER_SIG_BYTES        /* 200 */
#define QRUOV_PKB_H_SM_PREAMBLE_BYTES  QRUOV_PKB_H_SM_MSG_OFFSET        /* 200 */

/* ---- Domain separation tags (ASCII, length-prefixed by upstream SHAKE) ---- */
#define QRUOV_PKB_TAG_PK_DIGEST     "QRUOV-PKB-pk/v1"      /* d_pk derivation  */
#define QRUOV_PKB_TAG_T_TAU         "QRUOV-PKB-tag/v1"     /* PKB-T tag input  */
#define QRUOV_PKB_TAG_H_TARGET      "QRUOV-PKB-target/v1"  /* PKB-H synthetic  */

/* Parameter-set identifier: byte-stable across compilations. 0x01 is
 * QR-UOV-Ipks-1 (NIST L1, q=127, v=156, m=54, L=3). Future parameter sets
 * receive distinct ids so cross-parameter KAT confusion is impossible. */
#define QRUOV_PKB_PARAM_ID_IPKS1    ((uint8_t)0x01)
#define QRUOV_PKB_PARAM_ID          QRUOV_PKB_PARAM_ID_IPKS1

#endif /* QRUOV_PKB_PARAMS_H */
