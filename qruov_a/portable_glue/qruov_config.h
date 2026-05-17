#pragma once
/*
 * Hand-written configuration for QR-UOV-Ipks-1 (NIST L1, Round 2 spec).
 * Replaces the auto-generated qruov_config.h that the upstream Makefile
 * produces via qruov_config_h_gen.c.
 *
 * Parameters (Round 2 spec, qruov_config.src line for qruov1q127L3v156m54):
 *   q = 127, L = 3, v = 156, m = 54, fc = 1, fe = 1, fc0 = 1
 *   f(x) = x^L - fc * x^fe - fc0 = x^3 - x - 1
 *   Platform: portable64 with AES-CTR PRG (suffix 'a').
 */

#define QRUOV_security_strength_category 1
#define QRUOV_q                          127
#define QRUOV_v                          156
#define QRUOV_m                          54
#define QRUOV_L                          3
#define QRUOV_fc                         1
#define QRUOV_fe                         1
#define QRUOV_fc0                        1
#define QRUOV_PLATFORM                   portable64a
