/* MAYO-PKB benchmark driver (paper §5.2).
 *
 * Reports wall-clock per-call cost over N=200 trials (median, mean, p5, p95)
 * for KeyGen / Sign / Open.  Uses clock_gettime(CLOCK_MONOTONIC) to avoid
 * the rdtsc-vs-frequency ambiguity that would arise under WSL or
 * frequency-scaled hosts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mayo_a.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec * 1e-6;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void summarise(const char *name, double *v, int n) {
    qsort(v, n, sizeof(*v), cmp_d);
    double sum = 0.0; for (int i = 0; i < n; i++) sum += v[i];
    int p5  = n / 20;
    int p50 = n / 2;
    int p95 = (19 * n) / 20;
    printf("  %-7s : median %.3f ms | mean %.3f ms | p5 %.3f | p95 %.3f\n",
           name, v[p50], sum / n, v[p5], v[p95]);
}

int main(void) {
    enum { N = 200 };
    static double t_keygen[N], t_sign[N], t_open[N];
    uint8_t pk[MAYO_A_PK_BYTES], sk[MAYO_A_SK_BYTES];
    static uint8_t sm[MAYO_A_SIG_BYTES + 64], m2[64];
#if MAYO_A_LEVEL == 3
    const uint8_t msg[] = "MAYO-PKB-3 benchmark message ------------";
#else
    const uint8_t msg[] = "MAYO-PKB-1 benchmark message ------------";
#endif

    printf("\n========================================\n");
#if MAYO_A_LEVEL == 3
    printf(" MAYO-PKB-3 benchmark (N=%d trials)\n", N);
#else
    printf(" MAYO-PKB-1 benchmark (N=%d trials)\n", N);
#endif
    printf("========================================\n\n");
    printf("Sizes: pk=%u  sk=%u  sig=%u  d_pk=%u  tau=%u\n\n",
           (unsigned)MAYO_A_PK_BYTES,
           (unsigned)MAYO_A_SK_BYTES,
           (unsigned)MAYO_A_SIG_BYTES,
           (unsigned)MAYO_A_DPK_BYTES,
           (unsigned)MAYO_A_TAU_BYTES);

    for (int i = 0; i < N; i++) {
        double t0;

        t0 = now_ms();
        if (mayo_a_keypair(pk, sk) != 0) { printf("KeyGen failed\n"); return 1; }
        t_keygen[i] = now_ms() - t0;

        size_t smlen = 0;
        t0 = now_ms();
        if (mayo_a_sign(sm, &smlen, msg, sizeof(msg), sk) != 0) { printf("Sign failed\n"); return 1; }
        t_sign[i] = now_ms() - t0;

        size_t mlen2 = 0;
        t0 = now_ms();
        if (mayo_a_open(m2, &mlen2, sm, smlen, pk) != 0) { printf("Open failed\n"); return 1; }
        t_open[i] = now_ms() - t0;
    }

    summarise("KeyGen", t_keygen, N);
    summarise("Sign",   t_sign,   N);
    summarise("Open",   t_open,   N);

    return 0;
}
