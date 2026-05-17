/* Shared KeyGen for both QR-UOV-PKB-T and QR-UOV-PKB-H.
 *
 * Both profiles use byte-faithfully identical public/secret keys; the only
 * difference between them is how signatures bind to the public key
 * (tag-only vs digest-in-target). KeyGen is therefore profile-agnostic and
 * factored into this translation unit.
 *
 *   pk = store_QRUOV_SEED(seed_pk)          (16 B)
 *      || store_QRUOV_P3(QRUOV_KeyGen(...))  (24240 B)
 *
 *   sk = seed_sk || seed_pk || d_pk         (64 B)
 *   d_pk = SHAKE256( "QRUOV-PKB-pk/v1" || param_id || pk )[: 32 ]
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_pkdigest.h"

#include "qruov.h"

extern int randombytes(unsigned char *x, unsigned long long xlen);
extern void store_QRUOV_P3(const QRUOV_P3 P3, uint8_t *pool, size_t *pool_bits);

int qruov_pkb_keygen_internal(uint8_t *pk, uint8_t *sk) {
    QRUOV_SEED seed_sk;
    QRUOV_SEED seed_pk;

    if (randombytes(seed_sk, QRUOV_PKB_INNER_SEED_BYTES) != 0) return -1;
    if (randombytes(seed_pk, QRUOV_PKB_INNER_SEED_BYTES) != 0) return -2;

    /* QRUOV_P3 is a large multi-dimensional array typedef; keep on heap. */
    QRUOV_P3 *P3 = (QRUOV_P3 *)malloc(sizeof(QRUOV_P3));
    if (!P3) return -3;

    QRUOV_KeyGen(seed_sk, seed_pk, *P3);

    size_t pool_bits = 0;
    store_QRUOV_SEED(seed_pk, pk, &pool_bits);
    store_QRUOV_P3(*P3, pk, &pool_bits);

    /* Note: upstream packs Fql entries (21 bits each at q=127) into the pk
     * pool without byte-aligning the tail, so the final pool_bits is not a
     * multiple of 8 and (pool_bits >> 3) is QRUOV_PKB_PK_BYTES - 1. The
     * trailing bits within the last byte are zero-padding by virtue of
     * upstream's bit-packing, and the final byte count of upstream's
     * canonical pk is exactly QRUOV_PKB_PK_BYTES. No extra check needed. */

    memcpy(sk + QRUOV_PKB_SK_SEED_SK_OFFSET, seed_sk, QRUOV_PKB_INNER_SEED_BYTES);
    memcpy(sk + QRUOV_PKB_SK_SEED_PK_OFFSET, seed_pk, QRUOV_PKB_INNER_SEED_BYTES);
    qruov_pkb_compute_dpk(sk + QRUOV_PKB_SK_DPK_OFFSET, pk);

    free(P3);
    return 0;
}
