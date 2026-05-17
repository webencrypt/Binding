/* MAYO-PKB Known Answer Tests generator (paper §5.2 digest-tag).
 *
 * Outputs N deterministic key/signature records to stdout in a NIST-style
 * response format.  Each record contains:
 *   count        : record index in [0, KAT_COUNT)
 *   master_seed  : 32-byte canonical secret seed input to KeyGen
 *   pk           : canonical public key (1420 B at L1 / 2986 B at L3,
 *                  byte-identical to upstream MAYO compact pk)
 *   sk           : implementation sk = master_seed || d_pk_cache
 *                  (64 B at L1 / 80 B at L3)
 *   d_pk         : SHAKE256(pk || pk-digest-tag) for cross-check
 *   msg          : 33-byte test message
 *   smlen        : sm length (sigma_MAYO || tau || msg)
 *   sm           : full sm (470 + 33 = 503 B at L1)
 *   tau          : extracted from sm[INNER..INNER+TAU]
 *
 * The signer's tau and the verifier's recomputed tau are checked by a
 * round-trip mayo_a_open call before every record is emitted; the binary
 * additionally aborts with a non-zero exit code on any mismatch so that an
 * independent reference (e.g. a Sage/Python rewrite of MAYO-PKB) can
 * compare its own output byte-for-byte.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mayo_a.h"

#define KAT_COUNT 100

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s = ", label);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

int main(void) {
    int pass = 0;

#if MAYO_A_LEVEL == 3
    printf("# MAYO-PKB-3 Known Answer Tests (paper §5.2 digest-tag)\n");
#else
    printf("# MAYO-PKB-1 Known Answer Tests (paper §5.2 digest-tag)\n");
#endif
    printf("# count            = %d\n", KAT_COUNT);
    printf("# pk_bytes         = %u\n", (unsigned)MAYO_A_PK_BYTES);
    printf("# sk_bytes         = %u\n", (unsigned)MAYO_A_SK_BYTES);
    printf("# sig_bytes        = %u\n", (unsigned)MAYO_A_SIG_BYTES);
    printf("# d_pk_bytes       = %u\n", (unsigned)MAYO_A_DPK_BYTES);
    printf("# tau_bytes        = %u\n", (unsigned)MAYO_A_TAU_BYTES);
    printf("# inner_sig_bytes  = %u\n", (unsigned)MAYO_A_INNER_SIG_BYTES);
    printf("# domain_pk_digest = \"%s\"\n", MAYO_A_TAG_PK_DIGEST);
    printf("# domain_sig_bind  = \"%s\"\n\n", MAYO_A_TAG_SIG_BIND);

    for (int t = 0; t < KAT_COUNT; t++) {
        uint8_t master_seed[MAYO_A_MASTER_SEED_BYTES];
        for (unsigned i = 0; i < MAYO_A_MASTER_SEED_BYTES; i++)
            master_seed[i] = (uint8_t)((t * 31 + i * 7) & 0xFF);

        uint8_t pk[MAYO_A_PK_BYTES], sk[MAYO_A_SK_BYTES];
        if (mayo_a_keypair_with_seed(pk, sk, master_seed) != 0) {
            fprintf(stderr, "[KAT %d] keygen failed\n", t);
            return 1;
        }

        uint8_t dpk_check[MAYO_A_DPK_BYTES];
        mayo_a_compute_dpk(dpk_check, pk);
        if (memcmp(dpk_check, sk + MAYO_A_SK_DPK_OFFSET,
                   MAYO_A_DPK_BYTES) != 0) {
            fprintf(stderr, "[KAT %d] d_pk cache mismatch\n", t);
            return 1;
        }

        uint8_t msg[33];
        for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)((t + i) & 0xFF);

        uint8_t sm[MAYO_A_SIG_BYTES + sizeof(msg)];
        size_t smlen = 0;
        if (mayo_a_sign(sm, &smlen, msg, sizeof(msg), sk) != 0) {
            fprintf(stderr, "[KAT %d] sign failed\n", t);
            return 1;
        }

        uint8_t m2[sizeof(msg) + 16];
        size_t mlen2 = 0;
        if (mayo_a_open(m2, &mlen2, sm, smlen, pk) != 0 ||
            mlen2 != sizeof(msg) || memcmp(msg, m2, sizeof(msg)) != 0) {
            fprintf(stderr, "[KAT %d] open mismatch\n", t);
            return 1;
        }

        printf("count = %d\n", t);
        print_hex("master_seed", master_seed, sizeof(master_seed));
        print_hex("pk",  pk,  sizeof(pk));
        print_hex("sk",  sk,  sizeof(sk));
        print_hex("d_pk", dpk_check, sizeof(dpk_check));
        print_hex("msg", msg, sizeof(msg));
        printf("smlen = %zu\n", smlen);
        print_hex("sm",  sm,  smlen);
        print_hex("tau", sm + MAYO_A_INNER_SIG_BYTES, MAYO_A_TAU_BYTES);
        printf("\n");
        pass++;
    }

    fprintf(stderr, "[KAT] %d/%d pass\n", pass, KAT_COUNT);
    return (pass == KAT_COUNT) ? 0 : 1;
}
