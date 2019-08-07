#ifndef __TLS_PORTING_H__
#define __TLS_PORTING_H__

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void tls_random(unsigned char *output, size_t output_len);

#ifdef __cplusplus
}
#endif
#endif