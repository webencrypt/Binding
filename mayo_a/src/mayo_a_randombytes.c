/* MAYO-PKB randombytes shim.
 *
 * Provides the `randombytes` and `randombytes_init` symbols that MAYO's
 * source files reference.  Behaviour:
 *   - If a "preset" buffer is set via mayo_a_rng_preset(buf, len),
 *     subsequent randombytes() calls drain bytes from that buffer.
 *     The MAYO-PKB wrapper uses this to feed the inner MAYO KeyGen
 *     deterministically from a SHAKE-derived seed.
 *   - Otherwise, randombytes() reads from /dev/urandom (Linux/macOS) or
 *     uses Win32 RtlGenRandom (Windows).  The fallback path is used
 *     when the caller does NOT preset a buffer (e.g. for sampling the
 *     canonical 32-byte master_seed in mayo_a_keypair()).
 *
 * This file replaces both src/common/randombytes_system.c and
 * src/common/randombytes_ctrdrbg.c at link time when MAYO is built as
 * part of MAYO-PKB.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
#endif

static __thread const uint8_t *g_preset_buf = NULL;
static __thread size_t          g_preset_off = 0;
static __thread size_t          g_preset_len = 0;

void mayo_a_rng_preset(const uint8_t *buf, size_t len) {
    g_preset_buf = buf;
    g_preset_off = 0;
    g_preset_len = len;
}

void mayo_a_rng_clear(void) {
    g_preset_buf = NULL;
    g_preset_off = 0;
    g_preset_len = 0;
}

int randombytes(unsigned char *x, size_t xlen) {
    if (g_preset_buf != NULL) {
        if (g_preset_off + xlen > g_preset_len) {
            return -1;   /* preset buffer exhausted */
        }
        memcpy(x, g_preset_buf + g_preset_off, xlen);
        g_preset_off += xlen;
        return 0;
    }

#if defined(_WIN32)
    HCRYPTPROV provider;
    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT)) return -1;
    if (!CryptGenRandom(provider, (DWORD)xlen, x)) {
        CryptReleaseContext(provider, 0);
        return -1;
    }
    CryptReleaseContext(provider, 0);
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < xlen) {
        ssize_t r = read(fd, x + got, xlen - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
#endif
}

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    /* Only used when caller presets via mayo_a_rng_preset; the official
     * NIST KAT entry path is bypassed in MAYO-PKB.  We provide a stub. */
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
}
