/* Shared digest helpers for QR-UOV-PKB-T and QR-UOV-PKB-H.
 *
 * Uses OpenSSL EVP_shake256 throughout (upstream QR-UOV already links
 * libcrypto, so no new dependency).
 *
 * Domain separation strategy:
 *   Every SHAKE input begins with a fixed-length ASCII domain tag, then
 *   the parameter-set identifier byte, then the per-call payload. Tags
 *   are pairwise distinct strings, so SHAKE inputs from different
 *   call-sites are unambiguously parseable and cannot collide unless
 *   SHAKE itself has a collision on the relevant prefix.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_pkdigest.h"

/* shake256 of (tag || param_id || payload). All inputs are length-fixed by
 * the tag and parameter-id prefixes; SHAKE handles arbitrary trailing
 * length. */
static void shake256_tagged(uint8_t *out, size_t outlen,
                            const char *tag, size_t taglen,
                            uint8_t param_id,
                            const uint8_t *payload, size_t payload_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) abort();
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) abort();
    if (EVP_DigestUpdate(ctx, tag, taglen) != 1) abort();
    if (EVP_DigestUpdate(ctx, &param_id, 1) != 1) abort();
    if (payload_len) {
        if (EVP_DigestUpdate(ctx, payload, payload_len) != 1) abort();
    }
    if (EVP_DigestFinalXOF(ctx, out, outlen) != 1) abort();
    EVP_MD_CTX_free(ctx);
}

void qruov_pkb_compute_dpk(uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                           const uint8_t *pk_raw) {
    shake256_tagged(dpk, QRUOV_PKB_DPK_BYTES,
                    QRUOV_PKB_TAG_PK_DIGEST,
                    sizeof(QRUOV_PKB_TAG_PK_DIGEST) - 1u,
                    QRUOV_PKB_PARAM_ID,
                    pk_raw, QRUOV_PKB_INNER_PK_BYTES);
}

void qruov_pkb_compute_tau_t(uint8_t tau[QRUOV_PKB_TAU_BYTES],
                             const uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                             const uint8_t *msg, size_t mlen,
                             const uint8_t *sigma_base) {
    /* Build d_pk || u32_le(mlen) || msg || sigma_base into one buffer,
     * then call shake256_tagged with the binding domain tag. */
    const size_t payload_len = (size_t)QRUOV_PKB_DPK_BYTES + 4u
                             + mlen + (size_t)QRUOV_PKB_INNER_SIG_BYTES;
    uint8_t *buf = (uint8_t *)malloc(payload_len);
    if (!buf) abort();

    size_t off = 0;
    memcpy(buf + off, dpk, QRUOV_PKB_DPK_BYTES);
    off += QRUOV_PKB_DPK_BYTES;
    buf[off++] = (uint8_t)((mlen      ) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >>  8) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >> 16) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >> 24) & 0xFFu);
    if (mlen) {
        memcpy(buf + off, msg, mlen);
        off += mlen;
    }
    memcpy(buf + off, sigma_base, QRUOV_PKB_INNER_SIG_BYTES);
    off += QRUOV_PKB_INNER_SIG_BYTES;

    shake256_tagged(tau, QRUOV_PKB_TAU_BYTES,
                    QRUOV_PKB_TAG_T_TAU,
                    sizeof(QRUOV_PKB_TAG_T_TAU) - 1u,
                    QRUOV_PKB_PARAM_ID,
                    buf, payload_len);

    /* Best-effort scrub; tau itself is public. */
    memset(buf, 0, payload_len);
    free(buf);
}

size_t qruov_pkb_h_build_synth(uint8_t *buf,
                               const uint8_t dpk[QRUOV_PKB_DPK_BYTES],
                               const uint8_t *msg, size_t mlen) {
    const size_t taglen = sizeof(QRUOV_PKB_TAG_H_TARGET) - 1u;
    size_t off = 0;

    /* domain tag (ASCII, no NUL) */
    memcpy(buf + off, QRUOV_PKB_TAG_H_TARGET, taglen);
    off += taglen;

    /* parameter-set identifier */
    buf[off++] = QRUOV_PKB_PARAM_ID;

    /* d_pk */
    memcpy(buf + off, dpk, QRUOV_PKB_DPK_BYTES);
    off += QRUOV_PKB_DPK_BYTES;

    /* u32_le(mlen) */
    buf[off++] = (uint8_t)((mlen      ) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >>  8) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >> 16) & 0xFFu);
    buf[off++] = (uint8_t)((mlen >> 24) & 0xFFu);

    /* user message body */
    if (mlen) {
        memcpy(buf + off, msg, mlen);
        off += mlen;
    }

    return off;
}

int qruov_pkb_ct_eq16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t acc = 0;
    for (int i = 0; i < 16; i++) acc |= (uint8_t)(a[i] ^ b[i]);
    /* Map nonzero -> 0, zero -> 1 in constant time. */
    uint32_t v = acc;
    v = (v - 1u) >> 31; /* 1 if acc == 0, else 0 */
    return (int)v;
}
