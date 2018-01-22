#ifndef SPF_H
#define SPF_H

#include "qlibs/include/stralloc.h"
#include "ipalloc.h"

/* (Internal) Processing codes */

#define SPF_INIT    -1
#define SPF_EXT     -2  /* x */
#define SPF_ME      -3
#define SPF_EXHAUST -4
#define SPF_LOOP    -5
#define SPF_MULTIRR -6
#define SPF_LOCAL   -7
#define SPF_ERROR   -8
#define SPF_NOMEM   -9
#define SPF_SYNTAX  -10  /* Setup problem */
#define SPF_PREFIX  -11  /* Setup problem */
#define SPF_EXISTS  -99 /* go on */

/* (External) Resulting codes */

#define SPF_OK       0  /* +  Pass */
#define SPF_NONE     1  /* o  None */
#define SPF_UNKNOWN  2  /* u  Unknown method */
#define SPF_NEUTRAL  3  /* ?  Neutral */
#define SPF_SOFTFAIL 4  /* ~  Softfail */
#define SPF_FAIL     5  /* -  Not Permitted */
#define SPF_DNSSOFT  6  /* d  From DNS; not used */

#define LOOKUP_LIMIT 10

/* spfinfo: S=remoteip|O=mailfrom|C=identity/domain|H=helo|M(echanism)=query|D=redirect|I=domain|P=problem|R:result */

#define SPF_DEFEXP   "See http://spf.pobox.com/" \
                     "why.html?sender=%{s}&ip=%{i}&receiver=%{R}"

extern int flagip6;
extern stralloc spfmf;
extern stralloc spfhelo;
extern stralloc spfexplain;
extern stralloc spfinfo;
extern stralloc spfdomain;
extern stralloc dnsname;
extern stralloc spflocalrules;
extern stralloc spfrecord;
extern stralloc expdomain;
extern stralloc spfexplain;
extern stralloc spfexpmsg;

/* this table and macro came from wget more or less */
/* and was in turn stolen by me++ from libspf as is :) */

const static unsigned char urlchr_table[256] =
{
  1,  1,  1,  1,   1,  1,  1,  1,   /* NUL SOH STX ETX  EOT ENQ ACK BEL */
  1,  1,  1,  1,   1,  1,  1,  1,   /* BS  HT  LF  VT   FF  CR  SO  SI  */
  1,  1,  1,  1,   1,  1,  1,  1,   /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
  1,  1,  1,  1,   1,  1,  1,  1,   /* CAN EM  SUB ESC  FS  GS  RS  US  */
  1,  0,  1,  1,   0,  1,  1,  0,   /* SP  !   "   #    $   %   &   '   */
  0,  0,  0,  1,   0,  0,  0,  1,   /* (   )   *   +    ,   -   .   /   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* 0   1   2   3    4   5   6   7   */
  0,  0,  1,  1,   1,  1,  1,  1,   /* 8   9   :   ;    <   =   >   ?   */
  1,  0,  0,  0,   0,  0,  0,  0,   /* @   A   B   C    D   E   F   G   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* H   I   J   K    L   M   N   O   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* P   Q   R   S    T   U   V   W   */
  0,  0,  0,  1,   1,  1,  1,  0,   /* X   Y   Z   [    \   ]   ^   _   */
  1,  0,  0,  0,   0,  0,  0,  0,   /* `   a   b   c    d   e   f   g   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* h   i   j   k    l   m   n   o   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* p   q   r   s    t   u   v   w   */
  0,  0,  0,  1,   1,  1,  1,  1,   /* x   y   z   {    |   }   ~   DEL */

  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,

  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
};

#define WSPACE(x) ((x) == ' ' || (x) == '\t' || (x) == '\r' || (x) == '\n')
#define NXTOK(b, p, a) do { (b) = (p); \
    while((p) < (a)->len && !WSPACE((a)->s[(p)])) ++(p); \
    while((p) < (a)->len && WSPACE((a)->s[(p)])) (a)->s[(p)++] = 0; \
  } while(0)

/* spfdnsip.c */

int match_ip4(char *,int,char *);
int match_ip6(char *,int,char *);
int get_prefix(char *);
int spf_records(stralloc *,stralloc *);
int spf_include(char *,char *);
int spf_a(char *,char *);
int spf_mx(char *,char *);
int spf_ptr(char *,char *);
int spf_ip4(char *,char *);
int spf_ip6(char *,char *);
int spf_exists(char *,char *);

/* spf.c */

int spf_query(char *,char *,char *,char *,int);
int spf_lookup(stralloc *);
int spf_mechanism(char *,char *,char *,char *);
int spf_parse(stralloc *,char *,char *);
int spf_macros(stralloc *,char *,char *);
int spf_info(char *,char *);

#endif

