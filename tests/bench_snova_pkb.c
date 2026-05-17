/* Benchmark for upstream SNOVA(24,5,16,4) baseline vs. SNOVA-PKB-H.
 * Reports median cycles over ROUNDS trials. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "snova.h"
#include "snova_pkb.h"

extern void randombytes_init(unsigned char *entropy, unsigned char *pers,
                             int strength);
extern int  randombytes(unsigned char *x, unsigned long long xlen);
extern int  crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int  crypto_sign(unsigned char *sm, unsigned long long *smlen,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);
extern int  crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                              const unsigned char *sm,
                              unsigned long long smlen,
                              const unsigned char *pk);

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
static inline uint64_t cycles(void) { return __rdtsc(); }
#else
static inline uint64_t cycles(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

#ifndef ROUNDS
#define ROUNDS 200
#endif

static int cmpu64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/* Upstream SNOVA baseline uses BYTES_PK / BYTES_SK from the api.h.  We hard-
 * code matching constants here; the upstream lengths are the same as our
 * inner sizes. */
#define UPSTREAM_PK   SNOVA_PKB_PK_BYTES        /* 1016 */
#define UPSTREAM_SK   SNOVA_PKB_INNER_SK_BYTES  /* 48 */
#define UPSTREAM_SIG  SNOVA_PKB_SIG_BYTES       /* 248 */

int main(void) {
    /* Seed DRBG so the run is reproducible. */
    unsigned char entropy[48];
    for (int i = 0; i < 48; ++i) entropy[i] = (unsigned char)(0x77 ^ i);
    randombytes_init(entropy, NULL, 256);

    uint8_t msg[32];
    randombytes(msg, sizeof(msg));

    uint64_t kg_base[ROUNDS], sg_base[ROUNDS], vf_base[ROUNDS];
    uint64_t kg_pkbh[ROUNDS], sg_pkbh[ROUNDS], vf_pkbh[ROUNDS];

    /* --------- Upstream SNOVA(24,5,16,4) baseline --------- */
    for (int i = 0; i < ROUNDS; ++i) {
        uint8_t pk[UPSTREAM_PK], sk[UPSTREAM_SK];
        uint64_t t0 = cycles();
        crypto_sign_keypair(pk, sk);
        kg_base[i] = cycles() - t0;

        uint8_t sm[UPSTREAM_SIG + sizeof(msg)];
        unsigned long long smlen = 0ULL;
        t0 = cycles();
        crypto_sign(sm, &smlen, msg, (unsigned long long)sizeof(msg), sk);
        sg_base[i] = cycles() - t0;

        uint8_t m_out[sizeof(msg)];
        unsigned long long mlen = 0ULL;
        t0 = cycles();
        const int rc = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
        vf_base[i] = cycles() - t0;
        if (rc != 0) {
            fprintf(stderr, "baseline verify failed at %d\n", i);
            return 1;
        }
    }

    /* --------- SNOVA-PKB-H --------- */
    for (int i = 0; i < ROUNDS; ++i) {
        uint8_t pk[SNOVA_PKB_PK_BYTES], sk[SNOVA_PKB_SK_BYTES];
        uint64_t t0 = cycles();
        snova_pkb_h_keygen(pk, sk);
        kg_pkbh[i] = cycles() - t0;

        uint8_t sig[SNOVA_PKB_SIG_BYTES];
        t0 = cycles();
        snova_pkb_h_sign(sig, sk, pk, msg, sizeof(msg));
        sg_pkbh[i] = cycles() - t0;

        t0 = cycles();
        const int rc = snova_pkb_h_verify(pk, sig, msg, sizeof(msg));
        vf_pkbh[i] = cycles() - t0;
        if (rc != 0) {
            fprintf(stderr, "PKB-H verify failed at %d\n", i);
            return 1;
        }
    }

    qsort(kg_base, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(sg_base, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(vf_base, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(kg_pkbh, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(sg_pkbh, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(vf_pkbh, ROUNDS, sizeof(uint64_t), cmpu64);

    const uint64_t kg_b = kg_base[ROUNDS / 2];
    const uint64_t sg_b = sg_base[ROUNDS / 2];
    const uint64_t vf_b = vf_base[ROUNDS / 2];
    const uint64_t kg_h = kg_pkbh[ROUNDS / 2];
    const uint64_t sg_h = sg_pkbh[ROUNDS / 2];
    const uint64_t vf_h = vf_pkbh[ROUNDS / 2];

    printf("SNOVA(24,5,16,4) NIST L1 -- median over %d trials, %u-B msg\n\n",
           ROUNDS, (unsigned)sizeof(msg));
    printf("scheme          KeyGen(Mcyc)  Sign(Mcyc)  Vrfy(Mcyc)   "
           "ΔSign     ΔVrfy\n");
    printf("--------------  ------------  ----------  ----------   "
           "-------   -------\n");
    printf("SNOVA baseline   %12.2f  %10.2f  %10.2f     -         -\n",
           kg_b / 1e6, sg_b / 1e6, vf_b / 1e6);
    printf("SNOVA-PKB-H      %12.2f  %10.2f  %10.2f   %+6.2f%%   %+6.2f%%\n",
           kg_h / 1e6, sg_h / 1e6, vf_h / 1e6,
           100.0 * ((double)sg_h - (double)sg_b) / (double)sg_b,
           100.0 * ((double)vf_h - (double)vf_b) / (double)vf_b);
    return 0;
}
