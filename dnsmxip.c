#include <sys/types.h>
#include <sys/socket.h>
#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "fmt.h"
#include "dns.h"
#include "dnsdoe.h"
#include "ip.h"
#include "ipalloc.h"
#include "now.h"
#include "exit.h"

char ipaddr[IPFMT + FMT_ULONG];

stralloc sa = {0};
ipalloc ia = {0};

int main(int argc,char **argv)
{
  int j;
  unsigned long r;

  if (!argv[1]) _exit(100);

  if (!stralloc_copys(&sa,argv[1]))
    { substdio_putsflush(subfderr,"out of memory\n"); _exit(111); }

  r = now() + getpid();
  dns_init(0);
  dnsdoe(dns_mxip(&ia,&sa,r));

  for (j = 0; j < ia.len; ++j) {
    switch(ia.ix[j].af) {
      case AF_INET:
        substdio_put(subfdout,ipaddr,ip4_fmt(ipaddr,&ia.ix[j].addr.ip4));
        break;
      case AF_INET6:
        substdio_put(subfdout,ipaddr,ip6_fmt(ipaddr,&ia.ix[j].addr.ip6));
        break;
      default:
        substdio_puts(subfdout,"Unknown address family = ");
        substdio_put(subfdout,ipaddr,fmt_ulong(ipaddr,ia.ix[j].af));
    }
    substdio_puts(subfdout," ");
    substdio_put(subfdout,ipaddr,fmt_ulong(ipaddr,(unsigned long) ia.ix[j].pref));
    substdio_putsflush(subfdout,"\n");
  }
 _exit(0);
}
