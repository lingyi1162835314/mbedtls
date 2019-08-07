#include "porting/tls_utils.h"
#include <string.h>

void tls_random(unsigned char *output, size_t output_len)
{
#if defined(CONFIG_TEE_CA)
    csi_tee_rand_generate(output, output_len);
#else
    int i;
    uint32_t random;
    int mod = output_len % 4;
    int count = 0;
    static uint32_t rnd = 0x12345;
    for (i = 0; i < output_len / 4; i++) {
        random = rnd * 0xFFFF777;
        rnd = random;
        output[count++] = (random >> 24) & 0xFF;
        output[count++] = (random >> 16) & 0xFF;
        output[count++] = (random >> 8) & 0xFF;
        output[count++] = (random) & 0xFF;
    }
    random = rnd * 0xFFFF777;
    rnd = random;
    for (i = 0; i < mod; i++) {
        output[i + count] = (random >> 8 * i) & 0xFF;
    }
#endif
}