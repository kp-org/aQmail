#include <sys/types.h>
#include <sys/socket.h>
#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "strsalloc.h"
#include "dns.h"
#include "dnsdoe.h"
#include "ip.h"
#include "ipalloc.h"
#include "exit.h"

strsalloc ssa = {0};
stralloc sa = {0};
ipalloc ia = {0};

int main(int argc,char **argv)
{
  int j;

  if (!argv[1]) _exit(100);

  if (!stralloc_copys(&sa,argv[1]))
    { substdio_putsflush(subfderr,"out of memory\n"); _exit(111); }

  dns_init(1);
  dnsdoe(dns_ip(&ia,&sa));
  if (ia.len <= 0)
    { substdio_putsflush(subfderr,"no IP addresses\n"); _exit(100); }

  switch(ia.ix[0].af) {
    case AF_INET:
      dnsdoe(dns_ptr4(&ssa,&ia.ix[0].addr.ip4)); break;
    case AF_INET6:
      dnsdoe(dns_ptr6(&ssa,&ia.ix[0].addr.ip6)); break;
  }

  for (j = 0;j < ssa.len;++j) {
    substdio_putflush(subfdout,ssa.sa[j].s,ssa.sa[j].len);
    substdio_putsflush(subfdout,"\n");
  }

  _exit(0);
}
