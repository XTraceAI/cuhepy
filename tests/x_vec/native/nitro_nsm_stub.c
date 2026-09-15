/* TEST ONLY: exercise the exact AWS NSM C ABI without a device or real evidence.
 * This source is excluded from the enclave image. It cannot attest anything. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static int mode = 0;
static int closes = 0;

/* Test controls affect only this deliberately synthetic shared library. */
void test_mode(int value) { mode = value; }
int test_closes(void) { return closes; }

/* Model a device descriptor and its idempotent caller-side close handling. */
int nsm_lib_init(void) { return mode == 4 ? -1 : 7; }
void nsm_lib_exit(int fd) { if (fd == 7) ++closes; }

/* Verify that size_t, capacity and destination pointers match the official ABI. */
int nsm_get_random(int fd, uint8_t *out, size_t *length) {
    if (fd != 7 || *length != 32 || mode == 1) return 1;
    for (unsigned i = 0; i < 32; ++i) out[i] = (uint8_t)i;
    if (mode == 2) *length = 31;
    return 0;
}

/* Echo inputs to catch swapped nonce/context/key pointers and uint32_t lengths. */
int nsm_get_attestation_doc(int fd, const uint8_t *user, uint32_t user_len,
    const uint8_t *nonce, uint32_t nonce_len, const uint8_t *key, uint32_t key_len,
    uint8_t *out, uint32_t *length) {
    if (fd != 7 || user_len != 32 || nonce_len != 32 || key_len != 44 ||
        *length != 16384 || mode == 1) return 1;
    if (mode == 3) { *length = 16385; return 0; }
    memcpy(out, user, 32);
    memcpy(out + 32, nonce, 32);
    memcpy(out + 64, key, 44);
    *length = 108;
    return 0;
}
