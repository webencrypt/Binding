#ifndef QRUOV_PKB_PKDIGEST_H
#define QRUOV_PKB_PKDIGEST_H

#include <stdint.h>
#include <stddef.h>

#include "params_qruov_pkb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* d_pk := SHAKE256( QRUOV_PKB_TAG_PK_DIGEST || param_id || pk_raw )[: 32 ]
 *
 * pk_raw must point to the canonical QR-UOV-Ipks-1 public-key encoding
 * (QRUOV_PKB_INNER_PK_BYTES bytes, byte-faithful to upstream).
 */
void qruov_pkb_compute_dpk(uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                           const uint8_t *pk_raw);

/* PKB-T binding tag:
 *   tau := SHAKE256( QRUOV_PKB_TAG_T_TAU || param_id || d_pk
 *                    || u32_le(mlen) || m || sigma_base )[: 16 ]
 *
 * sigma_base must point to the QRUOV_PKB_INNER_SIG_BYTES upstream signature
 * bytes (200 B).
 */
void qruov_pkb_compute_tau_t(uint8_t tau[QRUOV_PKB_TAU_BYTES],
                             const uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                             const uint8_t *msg, size_t mlen,
                             const uint8_t *sigma_base);

/* PKB-H synthetic message length, given the user message length.
 * The synthetic message is the input that the wrapper feeds to upstream
 * QRUOV_Sign / QRUOV_Verify in place of the user message. */
static inline size_t qruov_pkb_h_synth_len(size_t mlen) {
    /* domain tag length is fixed by the macro; sizeof - 1 strips the NUL */
    return (sizeof(QRUOV_PKB_TAG_H_TARGET) - 1u)
         + 1u                              /* param_id          */
         + QRUOV_PKB_DPK_BYTES             /* d_pk              */
         + 4u                              /* u32_le(mlen)      */
         + mlen;                           /* user message body */
}

/* Build the PKB-H synthetic message buffer.
 *   buf:    caller-allocated, length >= qruov_pkb_h_synth_len(mlen)
 *   dpk:    32-byte public-key digest (from qruov_pkb_compute_dpk)
 *   msg:    user message
 *   mlen:   user message length in bytes
 *
 * Returns the number of bytes written (== qruov_pkb_h_synth_len(mlen)).
 */
size_t qruov_pkb_h_build_synth(uint8_t *buf,
                               const uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                               const uint8_t *msg, size_t mlen);

/* Constant-time equality on tau-length buffers.
 * Returns 1 if equal, 0 otherwise. */
int qruov_pkb_ct_eq16(const uint8_t a[16], const uint8_t b[16]);

/* Shared KeyGen used by both PKB-T and PKB-H profiles.
 * Samples upstream seeds via randombytes(), runs upstream QRUOV_KeyGen,
 * packs the canonical pk_raw, computes and caches d_pk.
 *
 *   pk[QRUOV_PKB_PK_BYTES]   = 24256 B  (canonical, byte-faithful)
 *   sk[QRUOV_PKB_SK_BYTES]   = 64 B     (seed_sk || seed_pk || d_pk)
 *
 * Returns 0 on success, negative on failure.
 */
int qruov_pkb_keygen_internal(uint8_t *pk, uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* QRUOV_PKB_PKDIGEST_H */
