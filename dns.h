#ifndef DNS_H
#define DNS_H

#define DNS_SOFT -1
#define DNS_HARD -2
#define DNS_MEM  -3

#include "ipalloc.h"
#include "strsalloc.h"
#include "dnsresolv.h"

void dns_init(int);
int dns_cname(stralloc *);
int dns_mxip(ipalloc *,stralloc *,unsigned long);
int dns_ip(ipalloc *,stralloc *);
int dns_ptr4(strsalloc *,char *);
int dns_ptr6(strsalloc *,char *);
int dns_txt(strsalloc *,stralloc *);
int dns_txts(strsalloc *,const stralloc *);

// int iaafmt4(char *,char *);
// int iaafmt6(char *,char *);

// int findip4(int);

#endif
