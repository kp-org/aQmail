#include "ucspissl.h"

int ssl_cca(SSL_CTX *ctx,const char *certfile)
{
  STACK_OF(X509_NAME) *x;

  if (!certfile) return 1;

  x = SSL_load_client_CA_file(certfile);
  if (!x) return 0;

  SSL_CTX_set_client_CA_list(ctx,x);

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);

  return 1;
}

