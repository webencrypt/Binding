#ifndef MAYO_A_RNG_H
#define MAYO_A_RNG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set / clear a preset buffer for the next randombytes() consumer. */
void mayo_a_rng_preset(const uint8_t *buf, size_t len);
void mayo_a_rng_clear(void);

#ifdef __cplusplus
}
#endif

#endif
