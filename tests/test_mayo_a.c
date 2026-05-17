/* MAYO-PKB test driver (paper §5.2):
 *   master_seed = 32 B, sk = master_seed || d_pk_cache (64 B at L1),
 *   sig = sigma_MAYO || tau (470 B at L1), pk = MAYO compact pk (1420 B at L1).
 *
 * Tests cover:
 *   1.  end-to-end self-test (mayo_a_selftest)
 *   2.  determinism on fixed master_seed
 *   3.  d_pk-cache consistency (cached d_pk == on-the-fly recomputation)
 *   4.  signature-tamper detection through mayo_a_open (Vrfy-side)
 *   5.  PKB-1 rejection: signature for one pk does NOT verify under a
 *       perturbed pk (single-byte tamper at three offsets) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mayo_a.h"

static void hexdump(const char *label, const uint8_t *buf, size_t len) {
    printf("  %s (%zu B): ", label, len);
    size_t shown = (len < 16 ? len : 16);
    for (size_t i = 0; i < shown; i++) printf("%02x", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

int main(void) {
    int total = 0, pass = 0;

    printf("\n========================================\n");
#if MAYO_A_LEVEL == 3
    printf(" MAYO-PKB-3 self-test (paper §5.2 digest-tag)\n");
#else
    printf(" MAYO-PKB-1 self-test (paper §5.2 digest-tag)\n");
#endif
    printf("========================================\n\n");
    printf("Sizes: pk=%u  sk=%u  sig=%u  master_seed=%u  d_pk=%u  tau=%u\n",
           (unsigned)MAYO_A_PK_BYTES,
           (unsigned)MAYO_A_SK_BYTES,
           (unsigned)MAYO_A_SIG_BYTES,
           (unsigned)MAYO_A_MASTER_SEED_BYTES,
           (unsigned)MAYO_A_DPK_BYTES,
           (unsigned)MAYO_A_TAU_BYTES);

    /* Test 1: self-test (KeyGen + 64 Sign/Open round-trips). */
    total++;
    int rc = mayo_a_selftest(64);
    if (rc == 0) { pass++; printf("[OK]  selftest(64)\n"); }
    else         { printf("[FAIL] selftest(64) rc=%d\n", rc); }

    /* Test 2: determinism (same master_seed -> identical pk and sk). */
    total++;
    {
        uint8_t seed[MAYO_A_MASTER_SEED_BYTES];
        for (int i = 0; i < (int)sizeof(seed); i++) seed[i] = (uint8_t)i;
        uint8_t pk1[MAYO_A_PK_BYTES], sk1[MAYO_A_SK_BYTES];
        uint8_t pk2[MAYO_A_PK_BYTES], sk2[MAYO_A_SK_BYTES];
        int r1 = mayo_a_keypair_with_seed(pk1, sk1, seed);
        int r2 = mayo_a_keypair_with_seed(pk2, sk2, seed);
        if (r1 == 0 && r2 == 0 &&
            memcmp(pk1, pk2, MAYO_A_PK_BYTES) == 0 &&
            memcmp(sk1, sk2, MAYO_A_SK_BYTES) == 0) {
            pass++;
            printf("[OK]  determinism\n");
            hexdump("    pk[0..]", pk1, sizeof(pk1));
            hexdump("    sk[0..]", sk1, sizeof(sk1));
        } else {
            printf("[FAIL] determinism\n");
        }
    }

    /* Test 3: d_pk-cache consistency. */
    total++;
    {
        uint8_t seed[MAYO_A_MASTER_SEED_BYTES];
        for (int i = 0; i < (int)sizeof(seed); i++) seed[i] = (uint8_t)(0xA0 + i);
        uint8_t pk[MAYO_A_PK_BYTES], sk[MAYO_A_SK_BYTES];
        if (mayo_a_keypair_with_seed(pk, sk, seed) != 0) {
            printf("[FAIL] d_pk-cache: keygen\n");
        } else {
            uint8_t dpk_check[MAYO_A_DPK_BYTES];
            mayo_a_compute_dpk(dpk_check, pk);
            if (memcmp(sk + MAYO_A_SK_DPK_OFFSET, dpk_check,
                       MAYO_A_DPK_BYTES) == 0) {
                pass++; printf("[OK]  d_pk-cache consistency\n");
            } else {
                printf("[FAIL] d_pk-cache consistency\n");
            }
        }
    }

    /* Test 4: sig-tamper detection (1-bit flip anywhere in sm -> reject).
     * The flip is targeted into each of the three sm regions in turn:
     * sigma_MAYO, tau, and msg.  All three must be detected. */
    total++;
    {
        uint8_t seed[MAYO_A_MASTER_SEED_BYTES];
        for (int i = 0; i < (int)sizeof(seed); i++) seed[i] = (uint8_t)(0x55 ^ i);
        uint8_t pk[MAYO_A_PK_BYTES], sk[MAYO_A_SK_BYTES];
        const uint8_t msg[] = "hello mayo-pkb";
        uint8_t sm[MAYO_A_SIG_BYTES + sizeof(msg)];
        size_t smlen = 0;
        int ok = (mayo_a_keypair_with_seed(pk, sk, seed) == 0) &&
                 (mayo_a_sign(sm, &smlen, msg, sizeof(msg), sk) == 0);
        if (!ok) {
            printf("[FAIL] sig-tamper: setup\n");
        } else {
            size_t flip_offsets[3] = {
                /* inside sigma_MAYO */ 4,
                /* inside tau        */ (size_t)MAYO_A_INNER_SIG_BYTES + 1,
                /* inside msg payload*/ (size_t)MAYO_A_INNER_SIG_BYTES + (size_t)MAYO_A_TAU_BYTES + 2
            };
            int detected = 0;
            for (int trial = 0; trial < 3; trial++) {
                uint8_t sm2[sizeof(sm)];
                memcpy(sm2, sm, smlen);
                sm2[flip_offsets[trial]] ^= 0x01;
                uint8_t m2[sizeof(msg) + 16]; size_t mlen2 = 0;
                int orc = mayo_a_open(m2, &mlen2, sm2, smlen, pk);
                int round_trip_ok = (orc == 0 && mlen2 == sizeof(msg) &&
                                     memcmp(msg, m2, sizeof(msg)) == 0);
                if (!round_trip_ok) detected++;
            }
            if (detected == 3) { pass++; printf("[OK]  sig-tamper detection (%d/3 regions)\n", detected); }
            else               { printf("[FAIL] sig-tamper detection (%d/3 regions)\n", detected); }
        }
    }

    /* Test 5: PKB-1 rejection.  A signature produced under pk1 must not
     * verify under any pk2 != pk1.  We perturb pk at three distinct byte
     * offsets and verify Open rejects in each. */
    total++;
    {
        uint8_t seed[MAYO_A_MASTER_SEED_BYTES];
        for (int i = 0; i < (int)sizeof(seed); i++) seed[i] = (uint8_t)(0x80 ^ i);
        uint8_t pk[MAYO_A_PK_BYTES], sk[MAYO_A_SK_BYTES];
        const uint8_t msg[] = "pkb-1 binding probe";
        uint8_t sm[MAYO_A_SIG_BYTES + sizeof(msg)];
        size_t smlen = 0;
        int ok = (mayo_a_keypair_with_seed(pk, sk, seed) == 0) &&
                 (mayo_a_sign(sm, &smlen, msg, sizeof(msg), sk) == 0);
        if (!ok) {
            printf("[FAIL] pkb-1: setup\n");
        } else {
            uint8_t m2[sizeof(msg) + 16]; size_t mlen2 = 0;
            int sane = (mayo_a_open(m2, &mlen2, sm, smlen, pk) == 0 &&
                        mlen2 == sizeof(msg) && memcmp(msg, m2, sizeof(msg)) == 0);
            if (!sane) {
                printf("[FAIL] pkb-1: legitimate pk verification round-trip\n");
            } else {
                /* Three byte offsets spanning the canonical pk (seed_h
                 * region, low P_3 region, high P_3 region). */
                size_t pk_flip[3] = { 3, 17, MAYO_A_PK_BYTES / 2 };
                const char *region[3] = { "low", "mid", "high" };
                int detected = 0;
                for (int trial = 0; trial < 3; trial++) {
                    uint8_t pk2[MAYO_A_PK_BYTES];
                    memcpy(pk2, pk, sizeof(pk2));
                    pk2[pk_flip[trial]] ^= 0x01;
                    uint8_t buf[sizeof(msg) + 16]; size_t blen = 0;
                    int orc = mayo_a_open(buf, &blen, sm, smlen, pk2);
                    int wrongly_accepted = (orc == 0 && blen == sizeof(msg) &&
                                            memcmp(msg, buf, sizeof(msg)) == 0);
                    if (!wrongly_accepted) {
                        detected++;
                    } else {
                        printf("    [PKB-1 LEAK] tamper %s region accepted!\n", region[trial]);
                    }
                }
                if (detected == 3) {
                    pass++;
                    printf("[OK]  PKB-1 rejection: pk tamper at {low, mid, high} all rejected\n");
                } else {
                    printf("[FAIL] PKB-1 rejection (%d/3 regions)\n", detected);
                }
            }
        }
    }

    printf("\n========================================\n");
    printf(" %d/%d tests passed\n", pass, total);
    printf("========================================\n");
    return (pass == total) ? 0 : 1;
}
