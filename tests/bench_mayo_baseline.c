/* Baseline MAYO reference benchmark for direct comparison with the
 * MAYO-PKB wrapper.  Same harness as bench_mayo_a.c (wall-clock,
 * N=200 trials, median/mean/p5/p95).  Build with -DMAYO_A_LEVEL=3 to
 * benchmark MAYO-3 baseline. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mayo.h"
#include "params_mayo_a.h"

#if MAYO_A_LEVEL == 3
#  define MAYO_BASELINE_LABEL  "MAYO-3"
#else
#  define MAYO_BASELINE_LABEL  "MAYO-1"
#endif

#ifdef ENABLE_PARAMS_DYNAMIC
#  if MAYO_A_LEVEL == 3
extern const mayo_params_t MAYO_3;
#    define MAYO_BASELINE_PARAMS (&MAYO_3)
#  else
extern const mayo_params_t MAYO_1;
#    define MAYO_BASELINE_PARAMS (&MAYO_1)
#  endif
#else
#  define MAYO_BASELINE_PARAMS ((const mayo_params_t *)0)
#endif

/* Concrete sizes for stack allocation (largest of L1 / L3). */
#define MAYO_BASELINE_PK   ((MAYO_A_INNER_PK_BYTES))
#define MAYO_BASELINE_SK   ((MAYO_A_INNER_SK_BYTES))
#define MAYO_BASELINE_SIG  ((MAYO_A_INNER_SIG_BYTES))

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
    uint8_t pk[MAYO_BASELINE_PK], sk[MAYO_BASELINE_SK];
    static uint8_t sm[MAYO_BASELINE_SIG + 64], m2[64];
    const uint8_t msg[] = "MAYO-x baseline benchmark message -------";

    printf("\n========================================\n");
    printf(" %s baseline benchmark (N=%d trials)\n", MAYO_BASELINE_LABEL, N);
    printf("========================================\n\n");
    printf("Sizes: pk=%u  sk=%u  sig=%u\n\n",
           (unsigned)MAYO_BASELINE_PK,
           (unsigned)MAYO_BASELINE_SK,
           (unsigned)MAYO_BASELINE_SIG);

    for (int i = 0; i < N; i++) {
        double t0;

        t0 = now_ms();
        if (mayo_keypair(MAYO_BASELINE_PARAMS, pk, sk) != MAYO_OK) { printf("KeyGen failed\n"); return 1; }
        t_keygen[i] = now_ms() - t0;

        size_t smlen = 0;
        t0 = now_ms();
        if (mayo_sign(MAYO_BASELINE_PARAMS, sm, &smlen, msg, sizeof(msg), sk) != MAYO_OK) { printf("Sign failed\n"); return 1; }
        t_sign[i] = now_ms() - t0;

        size_t mlen2 = 0;
        t0 = now_ms();
        if (mayo_open(MAYO_BASELINE_PARAMS, m2, &mlen2, sm, smlen, pk) != MAYO_OK) { printf("Open failed\n"); return 1; }
        t_open[i] = now_ms() - t0;
    }

    summarise("KeyGen", t_keygen, N);
    summarise("Sign",   t_sign,   N);
    summarise("Open",   t_open,   N);

    return 0;
}
