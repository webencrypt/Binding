#ifndef MAYO_A_H
#define MAYO_A_H

#include <stddef.h>
#include <stdint.h>

#include "params_mayo_a.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MAYO-PKB NIST-style API (compact form: signed message sm = sig || msg).
 *
 * Sizes (L1 / L3):
 *   pk: MAYO_A_PK_BYTES = 1420 / 2986   (canonical MAYO compact pk)
 *   sk: MAYO_A_SK_BYTES = 64   / 80     (master_seed || d_pk cache)
 *   sig: MAYO_A_SIG_BYTES = 470 / 705   (MAYO sigma || tau)
 *
 * Semantics (paper §5.2): MAYO-PKB applies the digest-tag transform to
 * MAYO with no anchor.  The canonical public key is byte-identical to
 * the upstream MAYO compact public key; the digest d_pk is derived from
 * pk and is not transmitted.
 */

int mayo_a_keypair(uint8_t *pk, uint8_t *sk);

int mayo_a_keypair_with_seed(uint8_t *pk, uint8_t *sk,
                             const uint8_t *master_seed);

int mayo_a_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

int mayo_a_open(uint8_t *m, size_t *mlen,
                const uint8_t *sm, size_t smlen,
                const uint8_t *pk);

int mayo_a_selftest(int num_samples);

/* PKB-layer helpers (exposed for testing / KAT cross-check). */
void mayo_a_compute_dpk(uint8_t dpk[MAYO_A_DPK_BYTES],
                        const uint8_t pk[MAYO_A_PK_BYTES]);

void mayo_a_compute_tau(uint8_t tau[MAYO_A_TAU_BYTES],
                        const uint8_t dpk[MAYO_A_DPK_BYTES],
                        const uint8_t *msg, size_t mlen,
                        const uint8_t sigma_inner[MAYO_A_INNER_SIG_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
