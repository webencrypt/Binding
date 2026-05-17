#ifndef QRUOV_PKB_H_H
#define QRUOV_PKB_H_H

#include <stdint.h>
#include <stddef.h>

#include "params_qruov_pkb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QR-UOV-PKB-H (digest-in-target) public API.
 *
 * The signature is byte-faithfully identical to upstream QR-UOV's signature
 * format (200 B), placed at the head of sm; the user message follows.
 *
 *   pk[QRUOV_PKB_PK_BYTES]                   = 24256 B
 *   sk[QRUOV_PKB_SK_BYTES]                   = 64 B
 *   sm[QRUOV_PKB_H_SM_PREAMBLE_BYTES + mlen] = 200 + mlen B
 *
 * Return values:
 *    0  success / accepted
 *   <0  signature rejected or internal error (see source)
 */
int qruov_pkb_h_keypair(uint8_t *pk, uint8_t *sk);

int qruov_pkb_h_sign(uint8_t *sm, unsigned long long *smlen,
                     const uint8_t *m, unsigned long long mlen,
                     const uint8_t *sk);

int qruov_pkb_h_open(uint8_t *m, unsigned long long *mlen,
                     const uint8_t *sm, unsigned long long smlen,
                     const uint8_t *pk);

int qruov_pkb_h_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* QRUOV_PKB_H_H */
