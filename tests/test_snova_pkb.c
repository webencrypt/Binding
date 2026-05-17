/* test_snova_pkb: self-test for SNOVA-PKB-H wrapper.
 *
 * Coverage:
 *   1. KeyGen + Sign + Vrfy round-trip on a single sample.
 *   2. Cached d_pk in sk matches digest of pk.
 *   3. Determinism of pkdigest.
 *   4. Tamper detection:
 *       (a) flip random byte of pk -> verify must fail.
 *       (b) flip random byte of sig -> verify must fail.
 *       (c) flip random byte of message -> verify must fail.
 *       (d) cross-key replay (sig from key A on key B) -> verify must fail. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "snova_pkb.h"

extern void randombytes_init(unsigned char *entropy, unsigned char *pers,
                             int strength);

static void seed_drbg(void) {
    unsigned char entropy[48];
    for (int i = 0; i < 48; ++i) {
        entropy[i] = (unsigned char)(0xC3 ^ i);
    }
    randombytes_init(entropy, NULL, 256);
}

static void prng_bytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)rand();
    }
}

static int test_round_trip(void) {
    uint8_t pk[SNOVA_PKB_PK_BYTES];
    uint8_t sk[SNOVA_PKB_SK_BYTES];
    if (snova_pkb_h_keygen(pk, sk) != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    /* Cached d_pk in sk must match digest of pk. */
    uint8_t dpk[SNOVA_PKB_DPK_BYTES];
    snova_pkb_pkdigest(dpk, pk, SNOVA_PKB_PK_BYTES);
    if (memcmp(dpk, sk + SNOVA_PKB_INNER_SK_BYTES, SNOVA_PKB_DPK_BYTES) != 0) {
        fprintf(stderr, "cached d_pk mismatch\n");
        return 1;
    }

    const uint8_t msg[] = "SNOVA-PKB-H round-trip / 32-byte msg.";
    uint8_t sig[SNOVA_PKB_SIG_BYTES];
    if (snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg) - 1) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    if (snova_pkb_h_verify(pk, sig, msg, sizeof(msg) - 1) != 0) {
        fprintf(stderr, "round-trip verify failed\n");
        return 1;
    }
    fprintf(stdout, "[1] round-trip OK\n");
    return 0;
}

static int test_determinism(void) {
    const uint8_t pk_bytes[8] = "ABCDEFGH";
    uint8_t d1[SNOVA_PKB_DPK_BYTES];
    uint8_t d2[SNOVA_PKB_DPK_BYTES];
    snova_pkb_pkdigest(d1, pk_bytes, sizeof(pk_bytes));
    snova_pkb_pkdigest(d2, pk_bytes, sizeof(pk_bytes));
    if (memcmp(d1, d2, SNOVA_PKB_DPK_BYTES) != 0) {
        fprintf(stderr, "pkdigest not deterministic\n");
        return 1;
    }
    fprintf(stdout, "[2] pkdigest deterministic OK\n");
    return 0;
}

static int test_tamper_pk(void) {
    uint8_t pk[SNOVA_PKB_PK_BYTES];
    uint8_t sk[SNOVA_PKB_SK_BYTES];
    if (snova_pkb_h_keygen(pk, sk) != 0) {
        return 1;
    }
    const uint8_t msg[16] = "tamper-pk-byte!!";
    uint8_t sig[SNOVA_PKB_SIG_BYTES];
    if (snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg)) != 0) {
        return 1;
    }
    if (snova_pkb_h_verify(pk, sig, msg, sizeof(msg)) != 0) {
        return 1;
    }
    uint8_t pk_t[SNOVA_PKB_PK_BYTES];
    memcpy(pk_t, pk, SNOVA_PKB_PK_BYTES);
    pk_t[rand() % SNOVA_PKB_PK_BYTES] ^= 0xa5u;
    if (snova_pkb_h_verify(pk_t, sig, msg, sizeof(msg)) == 0) {
        fprintf(stderr, "tampered pk passed (FAIL)\n");
        return 1;
    }
    fprintf(stdout, "[3] tampered pk rejected OK\n");
    return 0;
}

static int test_tamper_sig(void) {
    uint8_t pk[SNOVA_PKB_PK_BYTES];
    uint8_t sk[SNOVA_PKB_SK_BYTES];
    if (snova_pkb_h_keygen(pk, sk) != 0) {
        return 1;
    }
    const uint8_t msg[16] = "tamper-sig-byte!";
    uint8_t sig[SNOVA_PKB_SIG_BYTES];
    if (snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg)) != 0) {
        return 1;
    }
    uint8_t sig_t[SNOVA_PKB_SIG_BYTES];
    memcpy(sig_t, sig, SNOVA_PKB_SIG_BYTES);
    sig_t[rand() % SNOVA_PKB_SIG_BYTES] ^= 0xc3u;
    if (snova_pkb_h_verify(pk, sig_t, msg, sizeof(msg)) == 0) {
        fprintf(stderr, "tampered sig passed (FAIL)\n");
        return 1;
    }
    fprintf(stdout, "[4] tampered sig rejected OK\n");
    return 0;
}

static int test_tamper_msg(void) {
    uint8_t pk[SNOVA_PKB_PK_BYTES];
    uint8_t sk[SNOVA_PKB_SK_BYTES];
    if (snova_pkb_h_keygen(pk, sk) != 0) {
        return 1;
    }
    uint8_t msg[32];
    prng_bytes(msg, sizeof(msg));
    uint8_t sig[SNOVA_PKB_SIG_BYTES];
    if (snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg)) != 0) {
        return 1;
    }
    uint8_t msg_t[32];
    memcpy(msg_t, msg, sizeof(msg));
    msg_t[rand() % sizeof(msg_t)] ^= 0x5au;
    if (snova_pkb_h_verify(pk, sig, msg_t, sizeof(msg_t)) == 0) {
        fprintf(stderr, "tampered message passed (FAIL)\n");
        return 1;
    }
    fprintf(stdout, "[5] tampered msg rejected OK\n");
    return 0;
}

static int test_cross_key(void) {
    uint8_t pkA[SNOVA_PKB_PK_BYTES], skA[SNOVA_PKB_SK_BYTES];
    uint8_t pkB[SNOVA_PKB_PK_BYTES], skB[SNOVA_PKB_SK_BYTES];
    if (snova_pkb_h_keygen(pkA, skA) != 0) return 1;
    if (snova_pkb_h_keygen(pkB, skB) != 0) return 1;
    const uint8_t msg[16] = "cross-key-replay";
    uint8_t sigA[SNOVA_PKB_SIG_BYTES];
    if (snova_pkb_h_sign(sigA, skA, pkA, msg, sizeof(msg)) != 0) return 1;

    /* Replaying sigA under pkB must fail (digest-in-target binds pkA). */
    if (snova_pkb_h_verify(pkB, sigA, msg, sizeof(msg)) == 0) {
        fprintf(stderr, "cross-key replay passed (FAIL)\n");
        return 1;
    }
    fprintf(stdout, "[6] cross-key replay rejected OK\n");
    return 0;
}

int main(void) {
    seed_drbg();
    srand(0x534e4f56u);

    int rc = 0;
    rc |= test_round_trip();
    rc |= test_determinism();
    rc |= test_tamper_pk();
    rc |= test_tamper_sig();
    rc |= test_tamper_msg();
    rc |= test_cross_key();

    if (rc == 0) {
        fprintf(stdout, "SNOVA-PKB-H selftest: ALL PASS\n");
    } else {
        fprintf(stderr, "SNOVA-PKB-H selftest: FAILED (rc=%d)\n", rc);
    }
    return rc;
}
