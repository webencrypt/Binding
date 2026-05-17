#pragma once
/*
 * Hand-written NIST API header for QR-UOV-Ipks-1 (Round 2).
 * Mirrors what api_h_gen.c would generate.
 */
#include "qruov.h"

#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 24256
#define CRYPTO_BYTES          200
#define CRYPTO_ALGNAME        "qruov1q127L3v156m54portable64a"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
