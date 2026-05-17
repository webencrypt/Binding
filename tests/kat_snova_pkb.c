/* KAT generator for SNOVA-PKB-H.
 *
 * Emits 100 deterministic test vectors to PQCsignKAT_SNOVA_PKB_H.rsp in the
 * standard NIST .rsp format.  Each entry contains: count, seed, mlen, msg,
 * pk, sk, smlen, sm (= sig || msg).  The DRBG is reseeded once per vector
 * with NIST_init(seed) so the file format matches PQCgenKAT_sign. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snova_pkb.h"

extern void randombytes_init(unsigned char *entropy, unsigned char *pers,
                             int strength);
extern int  randombytes(unsigned char *x, unsigned long long xlen);

#define NUM_KATS 100

static void fprint_bytes(FILE *fp, const char *name,
                          const uint8_t *bytes, size_t n) {
    fprintf(fp, "%s = ", name);
    for (size_t i = 0; i < n; ++i) {
        fprintf(fp, "%02X", bytes[i]);
    }
    fprintf(fp, "\n");
}

int main(int argc, char **argv) {
    const char *out_path = (argc > 1) ? argv[1] : "PQCsignKAT_SNOVA_PKB_H.rsp";
    FILE *fp = fopen(out_path, "w");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    fprintf(fp, "# SNOVA-PKB-H -- digest-in-target wrapper on SNOVA(24,5,16,4)\n\n");

    /* Top-level seed reproduces NIST KAT convention: a fixed 48-byte
     * entropy block, with each vector reseeded from a 48-byte seed derived
     * from i. */
    for (int i = 0; i < NUM_KATS; ++i) {
        uint8_t seed[48];
        for (int j = 0; j < 48; ++j) {
            seed[j] = (uint8_t)((j + 1) * (i + 1));
        }
        randombytes_init(seed, NULL, 256);

        uint8_t pk[SNOVA_PKB_PK_BYTES];
        uint8_t sk[SNOVA_PKB_SK_BYTES];
        if (snova_pkb_h_keygen(pk, sk) != 0) {
            fprintf(stderr, "keygen failed at %d\n", i);
            fclose(fp);
            return 1;
        }
        const size_t mlen = 33u + (size_t)i;  /* 33..132 */
        uint8_t *msg = malloc(mlen);
        if (msg == NULL) { fclose(fp); return 1; }
        randombytes(msg, mlen);

        uint8_t sig[SNOVA_PKB_SIG_BYTES];
        if (snova_pkb_h_sign(sig, sk, pk, msg, mlen) != 0) {
            fprintf(stderr, "sign failed at %d\n", i);
            free(msg); fclose(fp); return 1;
        }
        if (snova_pkb_h_verify(pk, sig, msg, mlen) != 0) {
            fprintf(stderr, "verify failed at %d\n", i);
            free(msg); fclose(fp); return 1;
        }

        /* sm = sig || msg, smlen = SIG + mlen */
        const size_t smlen = SNOVA_PKB_SIG_BYTES + mlen;
        uint8_t *sm = malloc(smlen);
        if (sm == NULL) { free(msg); fclose(fp); return 1; }
        memcpy(sm, sig, SNOVA_PKB_SIG_BYTES);
        memcpy(sm + SNOVA_PKB_SIG_BYTES, msg, mlen);

        fprintf(fp, "count = %d\n", i);
        fprint_bytes(fp, "seed", seed, 48);
        fprintf(fp, "mlen = %zu\n", mlen);
        fprint_bytes(fp, "msg", msg, mlen);
        fprint_bytes(fp, "pk", pk, SNOVA_PKB_PK_BYTES);
        fprint_bytes(fp, "sk", sk, SNOVA_PKB_SK_BYTES);
        fprintf(fp, "smlen = %zu\n", smlen);
        fprint_bytes(fp, "sm", sm, smlen);
        fprintf(fp, "\n");

        free(msg);
        free(sm);
    }

    fclose(fp);
    fprintf(stdout, "Wrote %d KAT vectors to %s\n", NUM_KATS, out_path);
    return 0;
}
