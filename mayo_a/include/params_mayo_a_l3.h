#ifndef MAYO_A_PARAMS_L3_H
#define MAYO_A_PARAMS_L3_H

/* MAYO-PKB-3 (paper §5.2; L3 variant): MAYO-3 with the digest-tag
 * transform (Lemma~\ref{lem:generic-pkb}).  The PKB layer is a wrapper
 * around the unmodified MAYO-3 inner KeyGen/Sign/Vrfy; no anchor and no
 * MLWE.  See params_mayo_a_l1.h for the full PKB-layer description.
 *
 * Base scheme: MAYO-3 (NIST round-2 spec).
 *   n=118, m=108, o=10, k=11, q=16
 *   csk_bytes = 32, cpk_bytes = 2986, sig_bytes = 681, sk_seed_bytes = 32
 *
 * L3 PKB parameters: lambda_PKB = 192 bits, |d_pk| = 48 B, |tau| = 24 B.
 */

#include <stddef.h>
#include <stdint.h>

/* Canonical master-seed length (paper §5.2). */
#define MAYO_A_MASTER_SEED_BYTES   32u

/* Native MAYO-3 inner seed length (rho).  Differs from L1's 24 bytes. */
#define MAYO_A_INNER_SEED_BYTES    32u

#define MAYO_A_INNER_PK_BYTES   2986u  /* MAYO-3 cpk_bytes */
#define MAYO_A_INNER_SK_BYTES   32u    /* MAYO-3 csk_bytes */
#define MAYO_A_INNER_SIG_BYTES  681u   /* MAYO-3 sig_bytes */

/* Canonical pk = MAYO inner pk (byte-identical to upstream MAYO-3). */
#define MAYO_A_PK_BYTES   MAYO_A_INNER_PK_BYTES                          /* 2986 */

/* PKB security level (classical-RO calibration; see paper §5.1).
 * L3: lambda_PKB = 192 bits. d_pk = 2 lambda_PKB / 8 = 48 B (collision
 * resistance), tau = lambda_PKB / 8 = 24 B (target-collision resistance). */
#define MAYO_A_LAMBDA_PKB_BITS    192u
#define MAYO_A_DPK_BYTES          (2u * MAYO_A_LAMBDA_PKB_BITS / 8u)     /* 48 */
#define MAYO_A_TAU_BYTES          (MAYO_A_LAMBDA_PKB_BITS / 8u)          /* 24 */

/* Implementation sk caches d_pk immediately after master_seed. */
#define MAYO_A_SK_DPK_OFFSET      MAYO_A_MASTER_SEED_BYTES               /* 32 */
#define MAYO_A_SK_BYTES           (MAYO_A_MASTER_SEED_BYTES + MAYO_A_DPK_BYTES)
                                                                          /* 80 */

/* Signature: sigma_MAYO || tau. */
#define MAYO_A_SIG_TAU_OFFSET     MAYO_A_INNER_SIG_BYTES                 /* 681 */
#define MAYO_A_SIG_BYTES          (MAYO_A_INNER_SIG_BYTES + MAYO_A_TAU_BYTES)
                                                                          /* 705 */

/* Domain-separation tags (level-agnostic, shared with L1). */
#define MAYO_A_TAG_MAYO_SK      "MAYO-PKB-v1/mayo-sk"     /* master -> inner seed_sk */
#define MAYO_A_TAG_PK_DIGEST    "MAYO-PKB-v1/pk-digest"   /* pk     -> d_pk          */
#define MAYO_A_TAG_SIG_BIND     "MAYO-PKB-v1/sig-bind"    /* d_pk||m||sig -> tau     */

#endif
