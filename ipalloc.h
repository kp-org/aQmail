/*
 *  Revision 20171214, Erwin Hoffmann
 *  - changed ip to ip4 in struct ip4_address
*/

#ifndef IPALLOC_H
#define IPALLOC_H

#include "ip.h"

struct ip_mx {
  unsigned short af;
  union {
//    struct ip4_address ip4;
//    struct ip6_address ip6;
      char ip4[4];
      char ip6[16];
    } addr;
  int pref;
};

#include "stralloc.h"

GEN_ALLOC_typedef(ipalloc,struct ip_mx,ix,len,a)
int ipalloc_readyplus();
int ipalloc_append();

#endif
