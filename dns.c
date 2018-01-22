#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <resolv.h>
#include <errno.h>
#include "ip.h"
#include "ipalloc.h"
#include "fmt.h"
#include "alloc.h"
#include "str.h"
#include "stralloc.h"
#include "strsalloc.h"
#include "dns.h"
#include "case.h"

/**
 @file dns.c
 @brief DNS functions: resolve, findname, findip4, findip6, findmx, findtxt 
        DNS helpers: dns_init, dns_cname, iaafmt4, dns_ptr4, dns_ptr6,
                     dns_ptr4plus, dns_ptr6plus, iaafmt4, iaafmt6, 
                     dns_ipplus, dns_ip (IPv4+IPv6), dns_mxip
 */

/**
 @brief Includes Christopher K. Davis oversize DNS packet patch
        Includes Jonathan de Boyne Pollard CNAME query patch 
        Additional IPv6 support by fefe and fujiwara 
        Added dns_txts support and multiple field response for TXT from Jana Saout
 */

extern int res_query();
extern int res_search();
extern int errno;
extern int h_errno;

static unsigned short getshort(c) unsigned char *c;
{ unsigned short u; u = c[0]; return (u << 8) + c[1]; }

/* PACKETSZ can be found in /usr/include 
   ./arpa/nameser_compat.h and ./arpa/nameser.h (512 byte)
   MTUSIZE from qlibs (1028 byte) */

// static union { HEADER hdr; unsigned char buf[PACKETSZ]; } response;
static struct { unsigned char *buf; } response;
static int responsebuflen = 0;
static int responselen;
static unsigned char *responseend;
static unsigned char *responsepos;
static u_long saveresoptions;

static int numanswers;
static char name[MAXDNAME];
char ip4[4];
char ip6[16];
unsigned short pref;

static stralloc glue = {0};
static stralloc text = {0};

static int (*lookup)() = res_query;

static int resolve(stralloc *domain,int type)
{
  int n;
  int i;

  errno = 0;
  if (!stralloc_copy(&glue,domain)) return DNS_MEM;
  if (!stralloc_0(&glue)) return DNS_MEM;
  if (!responsebuflen)
   if (response.buf = (unsigned char *)alloc(MTUSIZE+1))
    responsebuflen = MTUSIZE+1;
   else return DNS_MEM;

  responselen = lookup(glue.s,C_IN,type,response.buf,responsebuflen);
  if ((responselen >= responsebuflen) ||
     (responselen > 0 && (((HEADER *)response.buf)->tc))) {
    if (responsebuflen < 65536)
      if (alloc_re(&response.buf,responsebuflen,65536))
        responsebuflen = 65536;
      else return DNS_MEM;
    saveresoptions = _res.options;
    _res.options |= RES_USEVC;
    responselen = lookup(glue.s,C_IN,type,response.buf,responsebuflen);
    _res.options = saveresoptions;
  }
  if (responselen <= 0) {
    if (errno == ECONNREFUSED) return DNS_SOFT;
    if (h_errno == TRY_AGAIN) return DNS_SOFT;
    return DNS_HARD;
  }
  responseend = response.buf + responselen;
  responsepos = response.buf + sizeof(HEADER);
  n = ntohs(((HEADER *)response.buf)->qdcount);

  while (n-- > 0) {
    i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
    if (i < 0) return DNS_SOFT;
    responsepos += i;
    i = responseend - responsepos;
    if (i < QFIXEDSZ) return DNS_SOFT;
    responsepos += QFIXEDSZ;
  }
  numanswers = ntohs(((HEADER *)response.buf)->ancount);
  return 0;
}

static int findname(int wanttype)
{
  unsigned short rrtype;
  unsigned short rrdlen;
  int i;

  if (numanswers <= 0) return 2;
  --numanswers;
  if (responsepos == responseend) return DNS_SOFT;

  i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
  if (i < 0) return DNS_SOFT;
  responsepos += i;

  i = responseend - responsepos;
  if (i < 4 + 3 * 2) return DNS_SOFT;
   
  rrtype = getshort(responsepos);
  rrdlen = getshort(responsepos + 8);
  responsepos += 10;

  if (rrtype == wanttype) {
    if (dn_expand(response.buf,responseend,responsepos,name,MAXDNAME) < 0)
      return DNS_SOFT;
    responsepos += rrdlen;
    return 1;
  }
   
  responsepos += rrdlen;
  return 0;
}

static int findip4(int wanttype)
{
  unsigned short rrtype;
  unsigned short rrdlen;
  int i;

  if (numanswers <= 0) return 2;
  --numanswers;
  if (responsepos == responseend) return DNS_SOFT;

  i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
  if (i < 0) return DNS_SOFT;
  responsepos += i;

  i = responseend - responsepos;
  if (i < 4 + 3 * 2) return DNS_SOFT;
   
  rrtype = getshort(responsepos);
  rrdlen = getshort(responsepos + 8);
  responsepos += 10;

  if (rrtype == wanttype) {
    if (rrdlen < 4)
      return DNS_SOFT;
    byte_copy(&ip4,4,&responsepos[0]);
    responsepos += rrdlen;
    return 1;
  }
   
  responsepos += rrdlen;
  return 0;
}

static int findip6(int wanttype)
{
  unsigned short rrtype;
  unsigned short rrdlen;
  int i;

  if (numanswers <= 0) return 2;
  --numanswers;
  if (responsepos == responseend) return DNS_SOFT;

  i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
  if (i < 0) return DNS_SOFT;
  responsepos += i;

  i = responseend - responsepos;
  if (i < 4 + 3 * 2) return DNS_SOFT;

  rrtype = getshort(responsepos);
  rrdlen = getshort(responsepos + 8);
  responsepos += 10;

  if (rrtype == wanttype) {
    if (rrdlen < 16)
      return DNS_SOFT;
    byte_copy(&ip6,16,&responsepos[0]);
    responsepos += rrdlen;
    return 1;
  }

  responsepos += rrdlen;
  return 0;
}

static int findmx(int wanttype)
{
  unsigned short rrtype;
  unsigned short rrdlen;
  int i;

  if (numanswers <= 0) return 2;
  --numanswers;
  if (responsepos == responseend) return DNS_SOFT;

  i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
  if (i < 0) return DNS_SOFT;
  responsepos += i;

  i = responseend - responsepos;
  if (i < 4 + 3 * 2) return DNS_SOFT;
   
  rrtype = getshort(responsepos);
  rrdlen = getshort(responsepos + 8);
  responsepos += 10;

  if (rrtype == wanttype) {
    if (rrdlen < 3)
      return DNS_SOFT;
    pref = (responsepos[0] << 8) + responsepos[1];
    if (dn_expand(response.buf,responseend,responsepos + 2,name,MAXDNAME) < 0)
      return DNS_SOFT;
    if (str_len(name) == 0 || name == '\0')
      if (pref == 0)
        return DNS_SOFT;			/* RFC 7505 */
    responsepos += rrdlen;
    return 1;
  }
   
  responsepos += rrdlen;
  return 0;
}

static int findtxt(int wanttype)
{
  unsigned short rrtype;
  unsigned short rrdlen;
  int i;

  if (numanswers <= 0) return 2;
  --numanswers;
  if (responsepos == responseend) return DNS_SOFT;

  i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
  if (i < 0) return DNS_SOFT;
  responsepos += i;

  i = responseend - responsepos;
  if (i < 4 + 3 * 2) return DNS_SOFT;

  rrtype = getshort(responsepos);
  rrdlen = getshort(responsepos + 8);
  responsepos += 10;

  if (rrtype == wanttype) {
    unsigned short txtpos;
    unsigned char txtlen;

    text.len = 0;
    for (txtpos = 0; txtpos < rrdlen; txtpos += txtlen) {
      txtlen = responsepos[txtpos++];
      if (txtlen > rrdlen-txtpos) txtlen = rrdlen-txtpos;
      if (!stralloc_catb(&text,&responsepos[txtpos],txtlen)) return DNS_MEM;
    }

    responsepos += rrdlen;
    return 1;
  }

  responsepos += rrdlen;
  return 0;
}

void dns_init(int flagsearch)
{
  res_init();
  if (flagsearch) lookup = res_search;
}

int dns_cname(stralloc *sa)
{
  int r;
  int loop;
  for (loop = 0; loop < 10; ++loop) {
    if (!sa->len) return loop;
    if (sa->s[sa->len - 1] == ']') return loop;
    if (sa->s[sa->len - 1] == '.') { --sa->len; continue; }

    switch (resolve(sa,T_CNAME)) {
      case DNS_MEM: return DNS_MEM;
      case DNS_SOFT: return DNS_SOFT;
      case DNS_HARD: return loop;
      default:
        while ((r = findname(T_CNAME)) != 2) {
          if (r == DNS_SOFT) return DNS_SOFT;
          if (r == 1) {
            if (!stralloc_copys(sa,name)) return DNS_MEM;
            break;
	  }
	}
        if (r == 2) return loop;
    }
  }
  return DNS_HARD; /* alias loop */
}

#define FMT_IAA 40

int iaafmt4(char *s,char ip[4])
{
  unsigned int i;
  unsigned int len;
  len = 0;
  i = fmt_ulong(s,(unsigned long) ip[3]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip[2]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip[1]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip[0]); len += i; if (s) s += i;
  i = fmt_str(s,".in-addr.arpa."); len += i; if (s) s += i;
  return len;
}

static int dns_ptr4plus(strsalloc *ssa,char ip[4])
{
  stralloc sa = {0};
  int r;

  if (!stralloc_ready(&sa,iaafmt4((char *) 0,ip))) return DNS_MEM;
  sa.len = iaafmt4(sa.s,ip);

  r = resolve(&sa,T_PTR);
  alloc_free(sa.s);

  switch(r) {
    case DNS_MEM: return DNS_MEM;
    case DNS_SOFT: return DNS_SOFT;
    case DNS_HARD: return DNS_HARD;
  }

  while ((r = findname(T_PTR)) != 2) {
    if (r == DNS_SOFT) return DNS_SOFT;
    if (r == 1) {
      stralloc sa2 = {0};
      if (!stralloc_copys(&sa2,name)) return DNS_MEM;
      if (!strsalloc_append(ssa,&sa2)) return DNS_MEM;
    }
  }
  if (ssa->len) return 0;

  return DNS_HARD;
}

int dns_ptr4(strsalloc *ssa,char ip[4])
{
  int r;
  int j;

  if (!strsalloc_readyplus(ssa,0)) return DNS_MEM;
  ssa->len = 0;

  r = dns_ptr4plus(ssa,ip);
  if (r < 0) {
    for (j = 0; j < ssa->len; ++j)
      alloc_free(ssa->sa[j].s);

   ssa->len = 0;
  }

  return r;
}

int iaafmt6(char *s,char ip[16])
{
  int j;
  unsigned int len;
  static char data[] = "0123456789abcdef";
  len = 0;

  if (s) {
    for (j = 15; j >= 0; j--) {
      *s++ = data[ip[j] & 0x0f];
      *s++ = '.';
      *s++ = data[(ip[j] >> 4) & 0x0f];
      *s++ = '.';
    }
    strcpy(s,"ip6.arpa");
  }
  return 71;
/* 1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.arpa */
}

static int dns_ptr6plus(strsalloc *ssa,char ip[16])
{
  stralloc sa = {0};
  int r;

  if (!stralloc_ready(&sa,iaafmt6((char *) 0,ip))) return DNS_MEM;
  sa.len = iaafmt6(sa.s,ip);

  r = resolve(&sa,T_PTR);
  alloc_free(sa.s);

  switch(r) {
    case DNS_MEM: return DNS_MEM;
    case DNS_SOFT: return DNS_SOFT;
    case DNS_HARD: return DNS_HARD;
  }

  while ((r = findname(T_PTR)) != 2) {
    if (r == DNS_SOFT) return DNS_SOFT;
    if (r == 1) {
      stralloc sa2 = {0};
      if (!stralloc_copys(&sa2,name)) return DNS_MEM;
      if (!strsalloc_append(ssa,&sa2)) return DNS_MEM;
    }
  }
  if (ssa->len) return 0;

  return DNS_HARD;
}

int dns_ptr6(strsalloc *ssa,char ip[16])
{
  int r;
  int j;

  if (!strsalloc_readyplus(ssa,0)) return DNS_MEM;
  ssa->len = 0;

  r = dns_ptr6plus(ssa,ip);
  if (r < 0) {
    for (j = 0; j < ssa->len; ++j)
      alloc_free(ssa->sa[j].s);

   ssa->len = 0;
  }

  return r;
}

static int dns_ipplus(ipalloc *ia,stralloc *sa,int pref)
{
  int r;
  struct ip_mx ix;
  int err4 = 0;
  int err6 = 0;

  if (!stralloc_copy(&glue,sa)) return DNS_MEM;
  if (!stralloc_0(&glue)) return DNS_MEM;

  if (glue.s[0]) {
    ix.pref = 0;
    ix.af = AF_INET;
    if (!glue.s[ip4_scan(&ix.addr.ip4,glue.s)] ||
        !glue.s[ip4_scanbracket(&ix.addr.ip4,glue.s)]) {
      if (!ipalloc_append(ia,&ix)) return DNS_MEM;
      return 0;
    }
  }

  switch (resolve(sa,T_AAAA)) {
    case DNS_MEM:  err6 = DNS_MEM; break;
    case DNS_SOFT: err6 = DNS_SOFT; break;
    case DNS_HARD: err6 = DNS_HARD; break;
    default:
      while ((r = findip6(T_AAAA)) != 2) {
        ix.af = AF_INET6;
        byte_copy(&ix.addr.ip6,16,&ip6);
        ix.pref = pref;
	if (r == DNS_SOFT) { err6 = DNS_SOFT; break; }
	if (r == 1)
	  if (!ipalloc_append(ia,&ix)) { err6 = DNS_MEM; break; }
      }
      break;
  }

  switch (resolve(sa,T_A)) {
    case DNS_MEM:  err4 = DNS_MEM; break;
    case DNS_SOFT: err4 = DNS_SOFT; break;
    case DNS_HARD: err4 = DNS_HARD; break;
    default:
      while ((r = findip4(T_A)) != 2) {
        ix.af = AF_INET;
        byte_copy(&ix.addr.ip4,4,&ip4);
        ix.pref = pref;
        if (r == DNS_SOFT) { err4 = DNS_SOFT; break; }
        if (r == 1)
	  if (!ipalloc_append(ia,&ix)) { err4 = DNS_MEM; break; }
      }
      break;
  }

  if (err4 != 0 && err6 != 0) {
    return err4;
  }
  return 0;
}

/* FQDN -> (multiple) IPv4/IP6 */

int dns_ip(ipalloc *ia,stralloc *sa)
{
  if (!ipalloc_readyplus(ia,0)) return DNS_MEM;
  ia->len = 0;
  return dns_ipplus(ia,sa,0);
}

int dns_mxip(ipalloc *ia,stralloc *sa,unsigned long random) {
  int r;
  struct mx { stralloc sa; unsigned short p; } *mx;
  struct ip_mx ix;
  int nummx;
  int i;
  int j;
  int flagsoft;

  if (!ipalloc_readyplus(ia,0)) return DNS_MEM;
  ia->len = 0;

  if (!stralloc_copy(&glue,sa)) return DNS_MEM;
  if (!stralloc_0(&glue)) return DNS_MEM;
  if (glue.s[0]) {
    ix.pref = 0;
    if (!glue.s[ip4_scan(&ix.addr.ip4,glue.s)] ||
        !glue.s[ip4_scanbracket(&ix.addr.ip4,glue.s)]) {
      ix.af = AF_INET;
      if (!ipalloc_append(ia,&ix)) return DNS_MEM;
      return 0;
    }
  }

  switch (resolve(sa,T_MX)) {
    case DNS_MEM: return DNS_MEM;
    case DNS_SOFT: return DNS_SOFT;
    case DNS_HARD: return dns_ip(ia,sa);
  }

  mx = (struct mx *) alloc(numanswers * sizeof(struct mx));
  if (!mx) return DNS_MEM;
  nummx = 0;

  while ((r = findmx(T_MX)) != 2) {
    if (r == DNS_SOFT) { alloc_free(mx); return DNS_SOFT; }
    if (r == 1) {
      mx[nummx].p = pref;
      mx[nummx].sa.s = 0;
      if (!stralloc_copys(&mx[nummx].sa,name)) {
        while (nummx > 0) alloc_free(mx[--nummx].sa.s);
        alloc_free(mx); return DNS_MEM;
      }
      ++nummx;
    }
  }

  if (!nummx) return dns_ip(ia,sa); /* e.g., CNAME -> A */

  flagsoft = 0;
  while (nummx > 0) {
    unsigned long numsame;

    i = 0;
    numsame = 1;
    for (j = 1; j < nummx; ++j) { 
      if (mx[j].p < mx[i].p) {
        i = j;
        numsame = 1;
      }
      else if (mx[j].p == mx[i].p) {
        ++numsame;
        random = random * 69069 + 1;
        if ((random / 2) < (2147483647 / numsame))
          i = j;
      }
    }

    switch (dns_ipplus(ia,&mx[i].sa,mx[i].p)) {
      case DNS_MEM: return DNS_MEM;
      case DNS_SOFT: flagsoft = 1; break;
    }

    alloc_free(mx[i].sa.s);
    mx[i] = mx[--nummx];
   }

  alloc_free(mx);
  return flagsoft;
}

static int dns_txtsplus(strsalloc *ssa,const stralloc *sa)
{
  int r;

  switch(resolve(sa,T_TXT)) {
    case DNS_MEM: return DNS_MEM;
    case DNS_SOFT: return DNS_SOFT;
    case DNS_HARD: return DNS_HARD;
  }

  while ((r = findtxt(T_TXT)) != 2) {
    if (r == DNS_SOFT) return DNS_SOFT;
    if (r == 1) {
      stralloc sa = {0};
      if (!stralloc_copy(&sa,&text)) return DNS_MEM;
      if (!strsalloc_append(ssa,&sa)) return DNS_MEM;
    }
  }
 
  if (ssa->len) return 0;
  return DNS_HARD;
}

int dns_txts(strsalloc *ssa,const stralloc *sa)
{
  int r;
  int j;

  if (!strsalloc_readyplus(ssa,0)) return DNS_MEM;
  ssa->len = 0;
 
  r = dns_txtsplus(ssa,sa);
  if (r < 0) {
    for (j = 0; j < ssa->len; ++j)
      alloc_free(ssa->sa[j].s);

    ssa->len = 0;
  }

  return r;
}
