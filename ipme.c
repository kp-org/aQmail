/*
 *  Revision 20171214, Erwin Hoffmann
 *  - changed stralloc ip/ip6 to char ip4[4]/ip6[16]
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#ifndef SIOCGIFCONF /* whatever works */
#include <sys/sockio.h>
#endif
#include "hassalen.h"
#include "byte.h"
#include "ip.h"
#include "ipalloc.h"
#include "stralloc.h"
#include "ipme.h"

/** @file ipme.c
    @brief ipme_is4, ipme_is6, ipme_is, ipme_init
 */

static int ipmeok = 0;
ipalloc ipme = {0};

int ipme_is4(char *ip[4])
{
  int i;

  if (ipme_init() != 1) return -1;

  for (i = 0; i < ipme.len; ++i)
    if (ipme.ix[i].af == AF_INET && byte_equal(&ipme.ix[i].addr,4,ip))
      return 1;
  return 0;
}

int ipme_is6(char *ip[16])
{
  int i;

  if (ipme_init() != 1) return -1;

  for (i = 0; i < ipme.len; ++i)
    if (ipme.ix[i].af == AF_INET6 && byte_equal(&ipme.ix[i].addr,16,ip))
      return 1;
  return 0;
}

int ipme_is(struct ip_mx *mxip)
{
  switch (mxip->af) {
    case AF_INET:  return ipme_is4(&mxip->addr.ip4);
    case AF_INET6: return ipme_is6(&mxip->addr.ip6);
  }
  return 0;
}

/* @brief ipme_init uses now getifaddrs() instead of ioctl calls */

int ipme_init()
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;
  struct ip_mx ix;

  if (ipmeok) return 1;
  if (!ipalloc_readyplus(&ipme,0)) return 0;
  ipme.len = 0;
  ix.pref = 0;

  if (getifaddrs(&ifap)) return 0;

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) 
    if (ifa->ifa_addr) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) ifa->ifa_addr;
        byte_copy(&ix.addr.ip4,4,&sin->sin_addr);
        ix.af = AF_INET;
        if (!ipalloc_append(&ipme,&ix)) return 0; 
      }
      if (ifa->ifa_addr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) ifa->ifa_addr;
        byte_copy(&ix.addr.ip6,16,&sin6->sin6_addr);
        ix.af = AF_INET6;
        if (!ipalloc_append(&ipme,&ix)) return 0; 
       }
    }

  freeifaddrs(ifap);
  ipmeok = 1;

  return 1;
}
