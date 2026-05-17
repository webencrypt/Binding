#ifndef QRUOV_PKB_T_H
#define QRUOV_PKB_T_H

#include <stdint.h>
#include <stddef.h>

#include "params_qruov_pkb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QR-UOV-PKB-T (tag-only) public API.
 *
 * Output buffer sizes:
 *   pk[QRUOV_PKB_PK_BYTES]                   = 24256 B
 *   sk[QRUOV_PKB_SK_BYTES]                   = 64 B
 *   sm[QRUOV_PKB_T_SM_PREAMBLE_BYTES + mlen] = 216 + mlen B
 *
 * Return values:
 *    0  success
 *   <0  failure (out-of-memory or upstream error)
 *
 * qruov_pkb_t_open returns:
 *    0  signature accepted
 *   -1  smlen too short to parse
 *   -2  tau mismatch (constant-time compare)
 *   -3  upstream QR-UOV verification rejected
 */
int qruov_pkb_t_keypair(uint8_t *pk, uint8_t *sk);

int qruov_pkb_t_sign(uint8_t *sm, unsigned long long *smlen,
                     const uint8_t *m, unsigned long long mlen,
                     const uint8_t *sk);

int qruov_pkb_t_open(uint8_t *m, unsigned long long *mlen,
                     const uint8_t *sm, unsigned long long smlen,
                     const uint8_t *pk);

/* Self-test: random KeyGen, 8 round-trip Sign+Open, 8 tamper checks.
 * Returns 0 on success, negative on the first failure. */
int qruov_pkb_t_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* QRUOV_PKB_T_H */
