#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include "fmt.h"
#include "ucspitls.h"
#include "stralloc.h"
#include "str.h"
#include "tls_remote.h"
#include "case.h"
#include "strerr.h"

int tls_certkey(SSL_CTX *ctx,const char *cert,const char *key,char *ppwd) 
{
  if (!cert) return 0;

  if (SSL_CTX_use_certificate_chain_file(ctx,cert) != 1)
    return -1;

  if (!key) key = cert;

  if (ppwd) SSL_CTX_set_default_passwd_cb_userdata(ctx,ppwd);

  if (SSL_CTX_use_PrivateKey_file(ctx,key,SSL_FILETYPE_PEM) != 1)
    return -2;

  if (SSL_CTX_check_private_key(ctx) != 1)
    return -3;

  return 0;
}

int tls_conn(SSL *ssl,int smtpfd)
{
  SSL_set_options(ssl,SSL_OP_NO_TLSv1);
  return SSL_set_fd(ssl,smtpfd);
}

int tls_checkpeer(SSL *ssl,const char *hostname,int hlen,int flag)
{
  X509 *cert;
  STACK_OF(GENERAL_NAME) *extensions;
  const GENERAL_NAME *ext;
  char buf[SSL_NAME_LEN];
  char *dnsname;
  int i;
  int num;
  int len;
  int dname = 0;

  if (flag == 1 || flag == 11) return 0;

  cert = SSL_get_peer_certificate(ssl);
  if (!cert) return -1;

  if (flag == 3 || flag == 4 || flag == 13 || flag == 14)
    if (SSL_get_verify_result(ssl) != X509_V_OK) return -2;

  if (flag == 4 || flag == 14 && hostname) {
    extensions = (GENERAL_NAME *)X509_get_ext_d2i(cert,NID_subject_alt_name,0,0);
    num = sk_GENERAL_NAME_num(extensions);      /* num = 0, if no SAN extensions */

    for (i = 0; i < num; ++i) {
      ext = sk_GENERAL_NAME_value(extensions,i);
      if (ext->type == GEN_DNS) {
        if (ASN1_STRING_type(ext->d.ia5) != V_ASN1_IA5STRING) continue;
        dnsname = (char *)ASN1_STRING_data(ext->d.ia5);
        len = ASN1_STRING_length(ext->d.ia5);
        if (len != strlen(dnsname)) continue;
        if (str_diffn(hostname,dnsname,hlen) == 0) return 0;
        dname = 1;
      }
    }

    if (!dname) {
      X509_NAME_get_text_by_NID(X509_get_subject_name(cert),NID_commonName,buf,sizeof buf);
      buf[SSL_NAME_LEN - 1] = 0;
      if (str_diffn(hostname,buf,len) == 0) return 0;
    }
    return -3;
  }

  return 0;
}

int tls_checkcrl(SSL *ssl)
{

  return 0;
}

int tls_exit(SSL *ssl)
{
  if (SSL_shutdown(ssl) == 0)
    SSL_shutdown(ssl);

  return 0;
}
