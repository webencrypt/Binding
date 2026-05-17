/* Benchmark for QR-UOV-PKB-T and QR-UOV-PKB-H.
 *
 * Reports median cycles (rdtsc on x86_64; wall-time fallback elsewhere)
 * over ROUNDS trials, plus mean wall-time in milliseconds. The wrapper
 * overhead can be read directly against the upstream baseline produced
 * by bench_qruov_baseline.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_t.h"
#include "qruov_pkb_h.h"

extern void randombytes_init(unsigned char *entropy_input,
                             unsigned char *personalization_string,
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

#ifndef ROUNDS
#define ROUNDS 200
#endif

static int cmpu64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

typedef int (*keypair_fn)(uint8_t *pk, uint8_t *sk);
typedef int (*sign_fn)(uint8_t *sm, unsigned long long *smlen,
                       const uint8_t *m, unsigned long long mlen,
                       const uint8_t *sk);
typedef int (*open_fn)(uint8_t *m, unsigned long long *mlen,
                       const uint8_t *sm, unsigned long long smlen,
                       const uint8_t *pk);

static int run_bench(const char *name,
                     unsigned sig_overhead,
                     keypair_fn kp, sign_fn sg, open_fn op) {
    const unsigned pk_b  = (unsigned)QRUOV_PKB_PK_BYTES;
    const unsigned sk_b  = (unsigned)QRUOV_PKB_SK_BYTES;
    const unsigned sig_b = (unsigned)QRUOV_PKB_INNER_SIG_BYTES + sig_overhead;
    const size_t   msglen = 32;
    const size_t   sm_b   = sig_b + msglen;

    printf("=== QR-UOV-PKB-%s benchmark ===\n", name);
    printf("  pk = %u B, sig = %u B (overhead = %u), sk = %u B, msg = %zu B, rounds = %d\n",
           pk_b, sig_b, sig_overhead, sk_b, msglen, ROUNDS);

    uint64_t *kg_c = (uint64_t *)malloc(sizeof(uint64_t) * ROUNDS);
    uint64_t *sg_c = (uint64_t *)malloc(sizeof(uint64_t) * ROUNDS);
    uint64_t *vf_c = (uint64_t *)malloc(sizeof(uint64_t) * ROUNDS);
    uint8_t  *pk   = (uint8_t  *)malloc(pk_b);
    uint8_t  *sm   = (uint8_t  *)malloc(sm_b);
    uint8_t   sk[QRUOV_PKB_SK_BYTES];
    uint8_t   m2[64];
    if (!kg_c || !sg_c || !vf_c || !pk || !sm) {
        printf("malloc failed\n");
        free(kg_c); free(sg_c); free(vf_c); free(pk); free(sm);
        return 1;
    }

    double kg_ms = 0, sg_ms = 0, vf_ms = 0;
    for (int r = 0; r < ROUNDS; r++) {
        double t0 = now_ms();
        uint64_t c0 = cycles();
        if (kp(pk, sk) != 0) { printf("KeyGen failed\n"); goto fail; }
        kg_c[r] = cycles() - c0;
        kg_ms += now_ms() - t0;

        uint8_t msg[32];
        for (size_t i = 0; i < msglen; i++)
            msg[i] = (uint8_t)((r * 7 + (int)i * 13 + 0x42) & 0xFF);

        unsigned long long smlen = 0;
        t0 = now_ms();
        c0 = cycles();
        if (sg(sm, &smlen, msg, msglen, sk) != 0) { printf("Sign failed\n"); goto fail; }
        sg_c[r] = cycles() - c0;
        sg_ms += now_ms() - t0;

        unsigned long long mlen2 = 0;
        t0 = now_ms();
        c0 = cycles();
        if (op(m2, &mlen2, sm, smlen, pk) != 0) { printf("Open failed\n"); goto fail; }
        vf_c[r] = cycles() - c0;
        vf_ms += now_ms() - t0;

        if (mlen2 != msglen || memcmp(msg, m2, msglen) != 0) {
            printf("Open returned wrong message at r=%d\n", r);
            goto fail;
        }
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
    printf("\n");

    free(kg_c); free(sg_c); free(vf_c); free(pk); free(sm);
    return 0;

fail:
    free(kg_c); free(sg_c); free(vf_c); free(pk); free(sm);
    return 1;
}

int main(void) {
    unsigned char entropy[48];
    for (int i = 0; i < 48; i++) entropy[i] = (unsigned char)(i + 7);
    randombytes_init(entropy, NULL, 256);

    int rc_t = run_bench("T", QRUOV_PKB_T_SIG_OVERHEAD,
                         qruov_pkb_t_keypair, qruov_pkb_t_sign, qruov_pkb_t_open);
    if (rc_t != 0) return rc_t;

    int rc_h = run_bench("H", QRUOV_PKB_H_SIG_OVERHEAD,
                         qruov_pkb_h_keypair, qruov_pkb_h_sign, qruov_pkb_h_open);
    return rc_h;
}
