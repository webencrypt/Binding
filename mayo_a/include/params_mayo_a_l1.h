#ifndef MAYO_A_PARAMS_L1_H
#define MAYO_A_PARAMS_L1_H

/* MAYO-PKB-1 (paper §5.2): MAYO-1 with the digest-tag transform
 * (Lemma~\ref{lem:generic-pkb}).  The PKB layer is a wrapper around the
 * unmodified MAYO inner KeyGen/Sign/Vrfy; no anchor and no MLWE.
 *
 * Base scheme: MAYO-1 (NIST round-2 spec).
 *   n=86, m=78, o=8, k=10, q=16
 *   csk_bytes = 24, cpk_bytes = 1420, sig_bytes = 454, sk_seed_bytes = 24
 *
 * Public-key layout (canonical, transmitted on the wire):
 *   [0, 1420): MAYO compact pk = (seed_h || P_{3,packed})
 * Total pk = 1420 B.  d_pk is *derived* from pk, not transmitted.
 *
 * Secret-key layout (implementation; the canonical/conceptual sk is the
 * 32-byte master_seed alone, see paper §5.2):
 *   [0,  32): master_seed (32 B)
 *   [32, 64): d_pk cache  (2 lambda_PKB / 8 = 32 B at L1)
 *
 * Signature layout (sm = sig || msg in NIST API):
 *   [0,    INNER): MAYO sigma  (454 B at L1)
 *   [INNER, INNER+TAU): tau     (lambda_PKB/8 = 16 B at L1)
 *   [INNER+TAU, ...):  msg
 *
 * PKB layer (paper §5.2):
 *   seed_sk := SHAKE-Derive(master_seed || "MAYO-PKB-v1/mayo-sk")[:inner_seed]
 *   d_pk    := SHAKE-Derive(pk          || "MAYO-PKB-v1/pk-digest")[:2 lam/8]
 *   tau     := SHAKE-Derive(d_pk || m || sigma_MAYO ||
 *                           "MAYO-PKB-v1/sig-bind")[:lam/8]
 */

#include <stddef.h>
#include <stdint.h>

/* Canonical master-seed length (paper §5.2 sk = master_seed). */
#define MAYO_A_MASTER_SEED_BYTES   32u

/* Native MAYO-1 inner seed length (rho). */
#define MAYO_A_INNER_SEED_BYTES    24u

#define MAYO_A_INNER_PK_BYTES   1420u  /* MAYO-1 cpk_bytes */
#define MAYO_A_INNER_SK_BYTES   24u    /* MAYO-1 csk_bytes */
#define MAYO_A_INNER_SIG_BYTES  454u   /* MAYO-1 sig_bytes */

/* Canonical pk = MAYO inner pk (byte-identical to upstream MAYO-1). */
#define MAYO_A_PK_BYTES   MAYO_A_INNER_PK_BYTES                          /* 1420 */

/* PKB security level (classical-RO calibration; see paper §5.1).
 * L1: lambda_PKB = 128 bits. d_pk = 2 lambda_PKB / 8 = 32 B (collision
 * resistance), tau = lambda_PKB / 8 = 16 B (target-collision resistance). */
#define MAYO_A_LAMBDA_PKB_BITS    128u
#define MAYO_A_DPK_BYTES          (2u * MAYO_A_LAMBDA_PKB_BITS / 8u)     /* 32 */
#define MAYO_A_TAU_BYTES          (MAYO_A_LAMBDA_PKB_BITS / 8u)          /* 16 */

/* Implementation sk caches d_pk immediately after master_seed. */
#define MAYO_A_SK_DPK_OFFSET      MAYO_A_MASTER_SEED_BYTES               /* 32 */
#define MAYO_A_SK_BYTES           (MAYO_A_MASTER_SEED_BYTES + MAYO_A_DPK_BYTES)
                                                                          /* 64 */

/* Signature: sigma_MAYO || tau. */
#define MAYO_A_SIG_TAU_OFFSET     MAYO_A_INNER_SIG_BYTES                 /* 454 */
#define MAYO_A_SIG_BYTES          (MAYO_A_INNER_SIG_BYTES + MAYO_A_TAU_BYTES)
                                                                          /* 470 */

/* Domain-separation tags (ASCII strings, no NUL terminator) used by the
 * MAYO-PKB SHAKE-Derive calls.  All disjoint by string prefix. */
#define MAYO_A_TAG_MAYO_SK      "MAYO-PKB-v1/mayo-sk"     /* master -> inner seed_sk */
#define MAYO_A_TAG_PK_DIGEST    "MAYO-PKB-v1/pk-digest"   /* pk     -> d_pk          */
#define MAYO_A_TAG_SIG_BIND     "MAYO-PKB-v1/sig-bind"    /* d_pk||m||sig -> tau     */

#endif
