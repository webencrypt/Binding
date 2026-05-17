/* KAT generator for QR-UOV-PKB (both -T and -H profiles).
 *
 * Produces two .rsp files, one per profile, with KAT_COUNT deterministic
 * (master_seed, msg, pk, sk, sm) records. Master seeds are SHAKE256-derived
 * from a fixed root, so the KAT is reproducible from this binary alone.
 *
 * Note on internal randomness: qruov_pkb_*_sign uses upstream randombytes()
 * for the three per-signature seeds (seed_y, seed_r, seed_sol). Upstream
 * randombytes is the NIST AES_CTR_DRBG seeded by randombytes_init(), so as
 * long as we initialise the DRBG once at startup with a fixed entropy
 * string, the entire KAT loop is deterministic.
 *
 * Usage:
 *   ./kat_qruov_pkb                       # writes both .rsp files (default names)
 *   ./kat_qruov_pkb out_t.rsp out_h.rsp   # custom paths
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "params_qruov_pkb.h"
#include "qruov_pkb_t.h"
#include "qruov_pkb_h.h"

extern void randombytes_init(unsigned char *entropy_input,
                             unsigned char *personalization_string,
                             int security_strength);

#define KAT_COUNT 100
#define KAT_MSGLEN 33

static void shake256_xof(uint8_t *out, size_t outlen,
                         const uint8_t *in, size_t inlen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) abort();
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) abort();
    if (EVP_DigestUpdate(ctx, in, inlen) != 1) abort();
    if (EVP_DigestFinalXOF(ctx, out, outlen) != 1) abort();
    EVP_MD_CTX_free(ctx);
}

static void hex_print(FILE *fp, const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(fp, "%02X", buf[i]);
}

/* Reseed the upstream AES_CTR_DRBG to a fixed per-profile entropy so each
 * profile's KAT loop is independent and reproducible. */
static void reseed_drbg(const char *tag) {
    unsigned char entropy[48];
    /* Deterministic entropy = SHAKE256("QRUOV-PKB-KAT/v1" || tag)[:48] */
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "QRUOV-PKB-KAT/v1|%s", tag);
    if (n <= 0 || (size_t)n >= sizeof(buf)) abort();
    shake256_xof(entropy, sizeof(entropy), (const uint8_t *)buf, (size_t)n);
    randombytes_init(entropy, NULL, 256);
}

/* Generic KAT runner parameterised by the profile API. */
typedef int (*keypair_fn)(uint8_t *pk, uint8_t *sk);
typedef int (*sign_fn)(uint8_t *sm, unsigned long long *smlen,
                       const uint8_t *m, unsigned long long mlen,
                       const uint8_t *sk);
typedef int (*open_fn)(uint8_t *m, unsigned long long *mlen,
                       const uint8_t *sm, unsigned long long smlen,
                       const uint8_t *pk);

static int run_kat_loop(const char *profile_name,
                        const char *out_path,
                        unsigned sig_overhead,
                        keypair_fn kp, sign_fn sg, open_fn op) {
    reseed_drbg(profile_name);

    FILE *fp = fopen(out_path, "w");
    if (!fp) { perror("open output"); return 1; }

    const unsigned pk_b  = (unsigned)QRUOV_PKB_PK_BYTES;
    const unsigned sk_b  = (unsigned)QRUOV_PKB_SK_BYTES;
    const unsigned sig_b = (unsigned)QRUOV_PKB_INNER_SIG_BYTES + sig_overhead;
    const unsigned sm_b  = sig_b + KAT_MSGLEN;

    fprintf(fp, "# QR-UOV-PKB-%s KAT  (NIST L1 / Ipks-1)\n", profile_name);
    fprintf(fp, "# pk=%u B  sig=%u B (overhead=%u)  sk=%u B  msglen=%d  count=%d\n\n",
            pk_b, sig_b, sig_overhead, sk_b, KAT_MSGLEN, KAT_COUNT);

    const uint8_t kat_root[16] = {
        0x51, 0x52, 0x55, 0x4F, 0x56, 0x2D, 0x50, 0x4B,
        0x42, 0x2D, 0x4B, 0x41, 0x54, 0x21, 0x00, 0x01
    };

    uint8_t *pk = (uint8_t *)malloc(pk_b);
    uint8_t *sm = (uint8_t *)malloc(sm_b);
    uint8_t *m2 = (uint8_t *)malloc(KAT_MSGLEN);
    uint8_t sk[QRUOV_PKB_SK_BYTES];
    if (!pk || !sm || !m2) { free(pk); free(sm); free(m2); fclose(fp); return 1; }

    /* Derive per-row master inputs deterministically. Note: the wrapper
     * exposes only randombytes-driven KeyGen; the determinism therefore
     * relies on the DRBG being reseeded at the top of this loop, with no
     * intervening randombytes consumers. */
    int total_pass = 0;
    for (int i = 0; i < KAT_COUNT; i++) {
        if (kp(pk, sk) != 0) {
            fprintf(stderr, "[%s] KeyGen failed at i=%d\n", profile_name, i);
            free(pk); free(sm); free(m2); fclose(fp); return 2;
        }

        uint8_t row_tag[16 + 4];
        memcpy(row_tag, kat_root, 16);
        row_tag[16] = (uint8_t)(i >> 24);
        row_tag[17] = (uint8_t)(i >> 16);
        row_tag[18] = (uint8_t)(i >>  8);
        row_tag[19] = (uint8_t)i;

        uint8_t msg[KAT_MSGLEN];
        shake256_xof(msg, KAT_MSGLEN, row_tag, sizeof(row_tag));

        unsigned long long smlen = 0;
        if (sg(sm, &smlen, msg, KAT_MSGLEN, sk) != 0) {
            fprintf(stderr, "[%s] Sign failed at i=%d\n", profile_name, i);
            free(pk); free(sm); free(m2); fclose(fp); return 3;
        }
        if (smlen != (unsigned long long)sm_b) {
            fprintf(stderr, "[%s] unexpected smlen at i=%d: %llu vs %u\n",
                    profile_name, i, smlen, sm_b);
            free(pk); free(sm); free(m2); fclose(fp); return 4;
        }

        unsigned long long mlen2 = 0;
        if (op(m2, &mlen2, sm, smlen, pk) != 0) {
            fprintf(stderr, "[%s] Open failed at i=%d\n", profile_name, i);
            free(pk); free(sm); free(m2); fclose(fp); return 5;
        }
        if (mlen2 != KAT_MSGLEN || memcmp(msg, m2, KAT_MSGLEN) != 0) {
            fprintf(stderr, "[%s] Open returned wrong message at i=%d\n",
                    profile_name, i);
            free(pk); free(sm); free(m2); fclose(fp); return 6;
        }

        fprintf(fp, "count = %d\n", i);
        fprintf(fp, "msg = ");  hex_print(fp, msg, KAT_MSGLEN);            fprintf(fp, "\n");
        fprintf(fp, "pk = ");   hex_print(fp, pk, pk_b);                   fprintf(fp, "\n");
        fprintf(fp, "sk = ");   hex_print(fp, sk, sk_b);                   fprintf(fp, "\n");
        fprintf(fp, "sm = ");   hex_print(fp, sm, (size_t)smlen);          fprintf(fp, "\n\n");
        total_pass++;
    }

    fclose(fp);
    free(pk); free(sm); free(m2);
    fprintf(stderr, "[%s] wrote %d/%d KAT vectors -> %s\n",
            profile_name, total_pass, KAT_COUNT, out_path);
    return (total_pass == KAT_COUNT) ? 0 : 7;
}

int main(int argc, char **argv) {
    const char *out_t = (argc > 1) ? argv[1] : "kat_qruov_pkb_t.rsp";
    const char *out_h = (argc > 2) ? argv[2] : "kat_qruov_pkb_h.rsp";

    int rc_t = run_kat_loop("T", out_t, QRUOV_PKB_T_SIG_OVERHEAD,
                            qruov_pkb_t_keypair, qruov_pkb_t_sign, qruov_pkb_t_open);
    int rc_h = run_kat_loop("H", out_h, QRUOV_PKB_H_SIG_OVERHEAD,
                            qruov_pkb_h_keypair, qruov_pkb_h_sign, qruov_pkb_h_open);

    if (rc_t != 0 || rc_h != 0) {
        fprintf(stderr, "FAILURE: rc_t=%d rc_h=%d\n", rc_t, rc_h);
        return 1;
    }
    fprintf(stderr, "OK: KAT generation complete\n");
    return 0;
}
