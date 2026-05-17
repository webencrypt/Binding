/* Benchmark driver for unmodified QR-UOV-Ipks-1 (Round 2 reference). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "qruov.h"

#define CRYPTO_PUBLICKEYBYTES 24256u
#define CRYPTO_SECRETKEYBYTES 32u
#define CRYPTO_BYTES          200u

extern int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *sk);
extern int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                            const unsigned char *sm, unsigned long long smlen,
                            const unsigned char *pk);
extern void randombytes_init(unsigned char* entropy_input,
                             unsigned char* personalization_string,
                             int security_strength);

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

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

#define ROUNDS 30

static int cmpu64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

int main(void) {
    unsigned char entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (unsigned char)(i + 1);
    randombytes_init(entropy, NULL, 256);

    printf("=== QR-UOV-Ipks-1 baseline benchmark ===\n");
    printf("  pk = %u B, sig = %u B, sk = %u B, rounds = %d\n",
           (unsigned)CRYPTO_PUBLICKEYBYTES, (unsigned)CRYPTO_BYTES,
           (unsigned)CRYPTO_SECRETKEYBYTES, ROUNDS);

    uint64_t kg_c[ROUNDS], sg_c[ROUNDS], vf_c[ROUNDS];
    double kg_ms = 0, sg_ms = 0, vf_ms = 0;

    uint8_t *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t  sk[CRYPTO_SECRETKEYBYTES];
    if (!pk) { printf("malloc pk\n"); return 1; }

    for (int r = 0; r < ROUNDS; r++) {
        double t0 = now_ms();
        uint64_t c0 = cycles();
        if (crypto_sign_keypair(pk, sk) != 0) { printf("KeyGen failed\n"); return 1; }
        kg_c[r] = cycles() - c0;
        kg_ms += now_ms() - t0;

        uint8_t msg[32]; for (int i = 0; i < 32; i++) msg[i] = (uint8_t)((r * 7 + i) & 0xFF);
        unsigned long long smlen = 0;
        uint8_t sm[CRYPTO_BYTES + 32];

        t0 = now_ms();
        c0 = cycles();
        if (crypto_sign(sm, &smlen, msg, 32, sk) != 0) { printf("Sign failed\n"); return 1; }
        sg_c[r] = cycles() - c0;
        sg_ms += now_ms() - t0;

        unsigned long long mlen2 = 0;
        uint8_t m2[32];

        t0 = now_ms();
        c0 = cycles();
        if (crypto_sign_open(m2, &mlen2, sm, smlen, pk) != 0) { printf("Vrfy failed\n"); return 1; }
        vf_c[r] = cycles() - c0;
        vf_ms += now_ms() - t0;
    }

    qsort(kg_c, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(sg_c, ROUNDS, sizeof(uint64_t), cmpu64);
    qsort(vf_c, ROUNDS, sizeof(uint64_t), cmpu64);

    printf("\nMedian cycles (lower is better):\n");
    printf("  KeyGen : %12llu  cycles\n", (unsigned long long)kg_c[ROUNDS / 2]);
    printf("  Sign   : %12llu  cycles\n", (unsigned long long)sg_c[ROUNDS / 2]);
    printf("  Vrfy   : %12llu  cycles\n", (unsigned long long)vf_c[ROUNDS / 2]);
    printf("\nMean wall-time:\n");
    printf("  KeyGen : %.3f ms\n", kg_ms / ROUNDS);
    printf("  Sign   : %.3f ms\n", sg_ms / ROUNDS);
    printf("  Vrfy   : %.3f ms\n", vf_ms / ROUNDS);
    free(pk);
    return 0;
}
