#ifndef TLS_REMOTE_H
#define TLS_REMOTE_H

#include <openssl/ssl.h>

/* the version is like this: 0xMNNFFPPS: major minor fix patch status */
#if OPENSSL_VERSION_NUMBER < 0x00908000L
# error "Need OpenSSL version at least 0.9.8"
#endif

int tls_chainfile(SSL_CTX *ctx, const char *);
int tls_certkey(SSL_CTX *ctx, const char *, const char *, char *);
int tls_conn(SSL *ssl, int sslfd);
int tls_setup(int f, char *, char *);
int tls_checkpeer(SSL *ssl, const char *, int ,int);
int tls_checkcrl(SSL *ssl);
int tls_error(void);
int tls_exit(SSL *ssl);

#endif
