#ifndef SNOVA_PKB_H
#define SNOVA_PKB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SNOVA-PKB-H: digest-in-target PKB transform on upstream SNOVA(24,5,16,4)
 * (NIST L1 Round-2 reference).
 *
 * The wrapper does not modify upstream SNOVA source.  It computes
 *   d_pk = SHAKE256(canonical_pk_bytes, 32)
 *   synth = "SNOVA-PKB-target/v1" || id || d_pk || u32_LE(|m|) || m
 *   digest = SHAKE256(synth, 64)
 * and feeds (digest, salt) to upstream snova sign/verify.  The signature
 * is byte-identical to upstream SNOVA (248 B). */

#define SNOVA_PKB_PK_BYTES      1016u   /* upstream SNOVA(24,5,16,4) pk size  */
#define SNOVA_PKB_INNER_SK_BYTES  48u   /* upstream SNOVA SEED_LENGTH         */
#define SNOVA_PKB_SK_BYTES        80u   /* 48 inner sk + 32 cached d_pk       */
#define SNOVA_PKB_SIG_BYTES      248u   /* upstream SNOVA signature           */
#define SNOVA_PKB_DPK_BYTES       32u   /* public-key digest length           */

#define SNOVA_PKB_PROFILE_ID_H   0x21u  /* parameter-set identifier byte (PKB-H) */
#define SNOVA_PKB_DST_TARGET     "SNOVA-PKB-target/v1"

/* d_pk = SHAKE256(pk_bytes, dpk_len = SNOVA_PKB_DPK_BYTES). */
void snova_pkb_pkdigest(uint8_t d_pk[SNOVA_PKB_DPK_BYTES],
                        const uint8_t *pk_bytes, size_t pk_bytes_len);

/* Build the synthetic message used by the digest-in-target transform:
 *   synth = "SNOVA-PKB-target/v1" || id || d_pk || u32_LE(|m|) || m
 * Returns the number of bytes written into out, or 0 on error
 * (out_cap too small).  out must hold at least
 *   19 + 1 + 32 + 4 + mlen bytes. */
size_t snova_pkb_build_synth(uint8_t *out, size_t out_cap,
                             uint8_t id,
                             const uint8_t d_pk[SNOVA_PKB_DPK_BYTES],
                             const uint8_t *m, size_t mlen);

/* KeyGen: pk = upstream SNOVA pk (1016 B), sk = 48-B upstream seed_pair
 * concatenated with the 32-byte d_pk cache.  Returns 0 on success. */
int snova_pkb_h_keygen(uint8_t pk[SNOVA_PKB_PK_BYTES], uint8_t sk[SNOVA_PKB_SK_BYTES]);
int snova_pkb_h_keygen_with_seed(uint8_t pk[SNOVA_PKB_PK_BYTES],
                                 uint8_t sk[SNOVA_PKB_SK_BYTES],
                                 const uint8_t seed[48]);

/* Sign: write the upstream SNOVA signature (248 B) into sig.  m/mlen are the
 * raw user message; salt is sampled internally via SNOVA's RNG.
 * Caller must supply pk so the wrapper can also recompute d_pk for cross-check;
 * if pk is NULL the cached d_pk in sk is trusted. */
int snova_pkb_h_sign(uint8_t sig[SNOVA_PKB_SIG_BYTES],
                     const uint8_t sk[SNOVA_PKB_SK_BYTES],
                     const uint8_t *pk_for_check,
                     const uint8_t *m, size_t mlen);

/* Verify: returns 0 if accept, -1 otherwise. */
int snova_pkb_h_verify(const uint8_t pk[SNOVA_PKB_PK_BYTES],
                       const uint8_t sig[SNOVA_PKB_SIG_BYTES],
                       const uint8_t *m, size_t mlen);

#ifdef __cplusplus
}
#endif

#endif /* SNOVA_PKB_H */
