/* Public-key digest for SNOVA-PKB.
 *
 * d_pk = SHAKE256(canonical pk bytes, SNOVA_PKB_DPK_BYTES)
 * synth = "SNOVA-PKB-target/v1" || id || d_pk || u32_LE(|m|) || m
 *
 * The wrapper reuses SNOVA's own SHAKE256 implementation (symmetric.h). */

#include "snova_pkb.h"

#include <stdint.h>
#include <string.h>

#include "symmetric.h"

void snova_pkb_pkdigest(uint8_t d_pk[SNOVA_PKB_DPK_BYTES],
                        const uint8_t *pk_bytes, size_t pk_bytes_len) {
    shake256(d_pk, SNOVA_PKB_DPK_BYTES, pk_bytes, pk_bytes_len);
}

size_t snova_pkb_build_synth(uint8_t *out, size_t out_cap,
                             uint8_t id,
                             const uint8_t d_pk[SNOVA_PKB_DPK_BYTES],
                             const uint8_t *m, size_t mlen) {
    const size_t dst_len = sizeof(SNOVA_PKB_DST_TARGET) - 1u;  /* drop NUL */
    const size_t needed = dst_len + 1u + SNOVA_PKB_DPK_BYTES + 4u + mlen;
    if (out == NULL || out_cap < needed) {
        return 0u;
    }

    size_t off = 0u;
    memcpy(out + off, SNOVA_PKB_DST_TARGET, dst_len);
    off += dst_len;

    out[off++] = id;

    memcpy(out + off, d_pk, SNOVA_PKB_DPK_BYTES);
    off += SNOVA_PKB_DPK_BYTES;

    /* u32_LE(|m|).  We do not need to protect against huge messages here;
     * SHAKE absorbs arbitrarily many bytes regardless. */
    const uint32_t mlen_le = (uint32_t)mlen;
    out[off++] = (uint8_t)(mlen_le & 0xffu);
    out[off++] = (uint8_t)((mlen_le >> 8) & 0xffu);
    out[off++] = (uint8_t)((mlen_le >> 16) & 0xffu);
    out[off++] = (uint8_t)((mlen_le >> 24) & 0xffu);

    if (mlen > 0u) {
        memcpy(out + off, m, mlen);
        off += mlen;
    }

    return off;
}
