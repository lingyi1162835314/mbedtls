#ifndef __TLS_NET_H__
#define __TLS_NET_H__

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif


int yoc_tls_net_set_send_timeout(void *ctx, int timeout_ms);

int yoc_tls_net_send( void *ctx, const unsigned char *buf, size_t len);

int yoc_tls_net_recv( void *ctx, unsigned char *buf, size_t len );

int yoc_tls_net_recv_timeout( void *ctx, unsigned char *buf, size_t len,
                      uint32_t timeout );

int yoc_tls_net_connect( mbedtls_net_context *ctx, const char *host,
                         const char *port, int proto );

void yoc_tls_net_init( mbedtls_net_context *ctx );

void yoc_tls_net_free( mbedtls_net_context *ctx );

#ifdef __cplusplus
}
#endif
#endif