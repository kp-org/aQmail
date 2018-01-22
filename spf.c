#include "stralloc.h"
#include "strsalloc.h"
#include "alloc.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "now.h"
#include "dns.h"
#include "case.h"
#include "spf.h"

/* long lived SPF variables (output) */

stralloc spfinfo = {0};			/* SPF results - see spf.h */
stralloc spfrecord = {0};	        /* Used for diagnostics */

/* s/qmail control SPF variables (input) */

int localrules;
stralloc spflocalrules;                  /* Local rules provided here */
stralloc spfexplain;                     /* Default SPF_EXPMSG in spf.h */ 

stralloc spfmf = {0};                    /* aka envelopefrom = clientid */
stralloc spfhelo = {0};                  /* helo or domain part for spfmf */
stralloc spfdomain = {0};                /* the last domain in the chain */
stralloc dnsname = {0};                  /* FQDN of client host in DNS */
stralloc spflocal = {0};                 /* Receiving host */

stralloc spfexpmsg = {0};		 /* additional explanation given as 5xx SMTP response */
stralloc expdomain = {0};		 /* the domain, for which explanation is given */

static int recursion;
// struct ip4_address ip4remote;
// struct ip6_address ip6remote; 
int flagip6;
char ip4remote[4];
char ip6remote[16];
// char *prefix = 0;

/* Sample SPF TXT records:
Standard example:   example.net TXT "v=spf1 mx a:pluto.example.net include:aspmx.googlemail.com -all"
Fehcom's example:    fehcom.net TXT "v=spf1 ip4:85.25.149.179/32 ip6:2001:4dd0:ff00:3d4::2/64 -all" 
Include example:    mailing.com TXT "v=spf1 a:smtpout.mailing.com include:spf.nl2go.com ~all"
Exists+Expand:      exisits.com TXT "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all" 
*/

/* Entry point: -------------------------------------- Go for SPF */

/**
 @brief  spf_query
         prepares the SPF TXT record query
 @param  input:  pointer to remoteip, helo, mf, localhost, and flagIP6 
 @return int r = SPF return code
 */

int spf_query(char *remoteip,char *helo,char *mf,char *local,int flagip)
{
  stralloc identity = {0};
  int at;
  int r = SPF_INIT;
  flagip6 = flagip;

  if (!stralloc_copys(&spfinfo," ")) return SPF_NOMEM;
 
  switch (flagip6) {
    case 0:  if (!ip4_scan(&ip4remote,remoteip)) return SPF_SYNTAX; 
             if (ipme_is4(&ip4remote) == 1) {
               if (!spf_info("MLocal=",remoteip)) return SPF_NOMEM; 
               if (!spf_info("R:","+")) return SPF_NOMEM;
               return SPF_ME; 
             } break;
    case 1:  if (!ip6_scan(&ip6remote,remoteip)) return SPF_SYNTAX;
             if (ipme_is6(&ip6remote) == 1) { 
               if (!spf_info("MLocal=",remoteip)) return SPF_NOMEM; 
               if (!spf_info("R:","+")) return SPF_NOMEM;
               return SPF_ME; 
             } break;
  }

  if (helo) {
    if (!stralloc_copys(&spfhelo,helo)) return SPF_NOMEM;
    if (!stralloc_0(&spfhelo)) return SPF_NOMEM;
  } else
    if (!stralloc_copys(&spfhelo,"unknown")) return SPF_NOMEM; 

  if (mf) {
    if (!stralloc_copys(&spfmf,mf)) return SPF_NOMEM;
    if (!stralloc_0(&spfmf)) return SPF_NOMEM;
    at = byte_rchr(spfmf.s,spfmf.len,'@') + 1;
    if (!stralloc_ready(&identity,spfmf.len - at)) return SPF_NOMEM;
    if (at < spfmf.len) {
      if (!stralloc_copys(&identity,spfmf.s + at)) return SPF_NOMEM;
    } else {
      if (!stralloc_copy(&identity,&spfhelo)) return SPF_NOMEM;
    }
    if (!stralloc_0(&identity)) return SPF_NOMEM;
  }

  if (local) {
    if (!stralloc_copys(&spflocal,local)) return SPF_NOMEM; 
    if (!stralloc_0(&spflocal)) return SPF_NOMEM;
  } else
    if (!stralloc_copys(&spflocal,"localhost")) return SPF_NOMEM; 

  if (!spf_info("S=",remoteip)) return SPF_NOMEM;
  if (!spf_info("O=",spfmf.s)) return SPF_NOMEM;
  if (!spf_info("C=",identity.s)) return SPF_NOMEM;
  if (!spf_info("H=",spfhelo.s)) return SPF_NOMEM;

  if (!stralloc_copy(&spfexpmsg,&spfexplain)) return SPF_NOMEM; 
  if (!stralloc_0(&spfexpmsg)) return SPF_NOMEM; 

  recursion = 0;
  dnsname.len = 0;

  if (r == SPF_INIT) r = spf_lookup(&identity);
  if (r == SPF_LOOP) {
    if (!spf_info("P=","Maximum nesting level exceeded; possible loop")) return SPF_NOMEM;
    if (!spf_info("R:","e")) return SPF_NOMEM;
  }
  if (r < 0) r = SPF_UNKNOWN; /* return 2main */

  return r;
}

/* SPF Lookup:  -------------------------------------- Return cases */

static struct spf_aliases {
  char *alias;
  int defrc;
} spf_aliases[] = {
  { "allow",   SPF_OK }
, { "pass",    SPF_OK }
, { "deny",    SPF_FAIL }
, { "softdeny",SPF_SOFTFAIL }
, { "fail",    SPF_FAIL }
, { "softfail",SPF_SOFTFAIL }
, { "unknown", SPF_NEUTRAL }
, { 0,         SPF_UNKNOWN }
};

/**
 @brief  spf_lookup
         calles the actual (recursive) SPF DNS query
 @param  input:  pointer to stralloc domain (fqdn) 
 @input  stralloc spflocalrules (if provided -- for artificial results)
 @output stralloc spfdata with RDATA (+ artificial information)
 @return int r = SPF return code
 */

int spf_lookup(stralloc *domain) 
{
  stralloc spfdata = {0};
  stralloc sa = {0};
  struct spf_aliases *da;
  int first = !recursion;
  int local_pos = -1;
  int q = -1;
  int i, r; 
  int begin, pos;
  int spfrc;
  int done;
  char *p;
   
  localrules = 0;

  /* Fallthrough result */

REDIRECT:
  if (++recursion > LOOKUP_LIMIT) return SPF_EXHAUST; 

  if (!stralloc_0(domain)) return SPF_NOMEM;
  if (!stralloc_copys(&expdomain,domain->s)) return SPF_NOMEM;

  r = spf_records(&spfdata,domain);

  if (first) if (!stralloc_copys(&spfrecord,"")) return SPF_NOMEM;
  if (!stralloc_cats(&spfrecord,"(")) return SPF_NOMEM;
  if (!stralloc_cats(&spfrecord,domain->s)) return SPF_NOMEM;
  if (!stralloc_cats(&spfrecord,")")) return SPF_NOMEM;
  if (!stralloc_cats(&spfrecord," => ")) return SPF_NOMEM;
  if (!stralloc_cat(&spfrecord,&spfdata)) return SPF_NOMEM;
  if (!stralloc_cats(&spfrecord,"\n")) return SPF_NOMEM;

  /* In spite of none-existing SPF data, use local rules as substitude */

  if (r == SPF_NONE) {			/* No SPF records published */
    if (!first) { 
      return r; 
    } else {
      spfdata.len = 0;
    }
    if (localrules) {			/* append local ruleset */
      local_pos = spfdata.len;
      if (!stralloc_cats(&spfdata,spflocalrules.s)) return SPF_NOMEM;
    }
    if (!stralloc_0(&spfdata)) return SPF_NOMEM;

    expdomain.len = 0;
    
  } else if (r == SPF_EXISTS) {		/* SPF records published */
    if (!stralloc_0(&spfdata)) return SPF_NOMEM;
    r = SPF_NEUTRAL;

    if (first && localrules) {	/* try to add local rules before failure of all mechs */
      pos = 0;
      p = (char *) 0;
      while (pos < spfdata.len) {
        NXTOK(begin,pos,&spfdata);
        if (!spfdata.s[begin]) continue;

        if (p && spfdata.s[begin] != *p) p = (char *) 0;
        if (!p && (spfdata.s[begin] == '-' || 
            spfdata.s[begin] == '~' ||
            spfdata.s[begin] == '?')) p = &spfdata.s[begin];

        if (p && p > spfdata.s && str_equal(spfdata.s + begin + 1,"all")) {
          /* ok, we can insert the local rules at p */
          local_pos = p - spfdata.s;

          if (!stralloc_readyplus(&spfdata,spflocalrules.len)) return 0;
          p = spfdata.s + local_pos;
          byte_copyr(p + spflocalrules.len,spfdata.len - local_pos,p);
          byte_copy(p,spflocalrules.len,spflocalrules.s);
          spfdata.len += spflocalrules.len;

          pos += spflocalrules.len;
          break;
        }
      }

      if (pos >= spfdata.len) pos = spfdata.len - 1;
      for (i = 0; i < pos; i++)
        if (!spfdata.s[i]) spfdata.s[i] = ' ';
    }
  
  } else {		/* Any other SPF return code */
    return r;
  }

  /* (artificial) SPF data exist; work thru them */

  pos = 0;
  done = 0;
  while (pos < spfdata.len) {
    NXTOK(begin,pos,&spfdata);
    if (!spfdata.s[begin]) continue;

    if (!done && localrules) {	/* in local ruleset? */
      if (local_pos >= 0 && begin >= local_pos) {
        if (begin < (local_pos + spflocalrules.len)) {
          expdomain.len = 0;
        } else {
          if (!stralloc_copy(&expdomain,domain)) return SPF_NOMEM;
        }
      }
    }

    for (p = spfdata.s + begin; *p; ++p)
      if (*p == ':' || *p == '/' || *p == '=') break;

    if (*p == '=') {
      *p++ = 0;

      if (str_equal(spfdata.s + begin,"redirect")) {	      /* modifiers are simply handled here */
        if (done) continue;
 
        if (!spf_parse(&sa,p,domain->s)) return SPF_NOMEM;
        if (!stralloc_copy(domain,&sa)) return SPF_NOMEM;
        if (!spf_info("D=",p)) return SPF_NOMEM;
        r = SPF_UNKNOWN;

        goto REDIRECT;
      } else if (str_equal(spfdata.s + begin,"default")) {   /* we don't need those anymore */
          if (done) continue;

          for (da = spf_aliases; da->alias; ++da)
            if (str_equal(da->alias,p)) break;

          r = da->defrc;
      } else if (str_equal(spfdata.s + begin,"exp")) {  /* exp= only on top level */
        strsalloc ssa = {0};

        if (!first) continue;
        if (!stralloc_copys(&sa,p)) return SPF_NOMEM;

        switch (dns_txts(&ssa,&sa)) {
          case DNS_MEM:  return SPF_NOMEM;
          case DNS_SOFT: continue; /* FIXME... */
          case DNS_HARD: continue;
        }

        spfexpmsg.len = 0;
        for (i = 0; i < ssa.len; i++) {
          if (!stralloc_cat(&spfexpmsg,&ssa.sa[i])) return SPF_NOMEM;
          if (i < (ssa.len - 1))
            if (!stralloc_append(&spfexpmsg,"\n")) return SPF_NOMEM;
        }
        if (!stralloc_0(&spfexpmsg)) return SPF_NOMEM;
      }   
    } else if (!done) {                             /* and unknown modifiers are ignored */
      if (!stralloc_copys(&sa,spfdata.s + begin)) return SPF_NOMEM;
      if (!stralloc_0(&sa)) return SPF_NOMEM;

      switch (spfdata.s[begin]) {
        case '-': begin++; spfrc = SPF_FAIL; break;
        case '~': begin++; spfrc = SPF_SOFTFAIL; break;
        case '+': begin++; spfrc = SPF_OK; break;
        case '?': begin++; spfrc = SPF_NEUTRAL; break;
        default:  spfrc = SPF_OK;
      }

      if (*p == '/') {
        *p++ = 0;
        q = spf_mechanism(spfdata.s + begin,0,p,domain->s);
      } else {
        if (*p) *p++ = 0;
        i = str_chr(p,'/');
        if (p[i] == '/') {
          p[i++] = 0;
          q = spf_mechanism(spfdata.s + begin,p,p + i,domain->s);
        } else if (i > 0) {
          q = spf_mechanism(spfdata.s + begin,p,0,domain->s);
        } else {
          q = spf_mechanism(spfdata.s + begin,0,0,domain->s);
        }
      }
      if (q == SPF_OK) q = spfrc;

      switch (q) {
        case SPF_OK:       if (!spf_info("R:","+")) return SPF_NOMEM; break;
        case SPF_NEUTRAL:  if (!spf_info("R:","?")) return SPF_NOMEM; break;
        case SPF_SYNTAX:   if (!spf_info("P=","Unknown parse error")) return SPF_NOMEM; 
                           if (!spf_info("R:","e")) return SPF_NOMEM; break;
        case SPF_SOFTFAIL: if (!spf_info("R:","~")) return SPF_NOMEM; break;
        case SPF_FAIL:     if (!spf_info("R:","-")) return SPF_NOMEM; break;
        case SPF_EXT:      if (!spf_info("P=","Unknown SPF mechanism")) return SPF_NOMEM; break;
        case SPF_ERROR:
          if (localrules) if (local_pos >= 0 && begin >= local_pos) break;
          if (!spf_info("R:","o")) return SPF_NOMEM; q = SPF_NONE; break;
        case SPF_NONE: continue;
      }

      r = q;
      done = 1;                                     /* we're done, no more mechanisms */
    }
  }

  /* we fell through, no local rule applied */
  if (!done) 
    if (!stralloc_copy(&expdomain,domain)) return SPF_NOMEM;

  return r;
}

/* Mechanisms:  -------------------------------------- Lookup classes */

static struct mechanisms {
  char *mechanism;
  int (*func)(char *spfspec,char *prefix);
  unsigned int use_spfspec : 1;
  unsigned int use_prefix  : 1;
  unsigned int expands     : 1;
  unsigned int filldomain  : 1;
  int defresult            : 4;
} mechanisms[] = {
  { "all",      0,          0,0,0,0,SPF_OK  }
, { "include",  spf_include,1,0,1,0,0       }
, { "a",        spf_a,      1,1,1,1,0       }
, { "mx",       spf_mx,     1,1,1,1,0       }
, { "ptr",      spf_ptr,    1,0,1,1,0       }
, { "ip4",      spf_ip4,    1,1,0,0,0       }
, { "ip6",      spf_ip6,    1,1,0,0,0       }
, { "exists",   spf_exists, 1,0,1,0,0       }
, { "extension",0,          1,1,0,0,SPF_EXT }
, { 0,          0,          1,1,0,0,SPF_EXT }
};

/**
 @brief  spf_mechanism
         evaluates the provided mechanisms in the SPF record [RFC7208 Sec 5.]
 @param  input:  pointer to mechanism, SPF specification from record, CIDR prefix length, domain
 @input  stralloc spflocalrules (if provided)
 @output pointer to spfspec: data evaluated
 @return int r
 */

int spf_mechanism(char *mechanism,char *spfspec,char *prefix,char *domain)
{
  struct mechanisms *mech;
  stralloc sa = {0};
  int r;
  int pos;

  for (mech = mechanisms; mech->mechanism; mech++)
    if (str_equal(mech->mechanism,mechanism)) break;

  if (mech->use_spfspec && !spfspec && mech->filldomain) spfspec = domain;
  if (!mech->use_spfspec != !spfspec) return SPF_SYNTAX;
  if (!mech->use_prefix && prefix) return SPF_PREFIX;

  if (!mech->func) return mech->defresult;
  if (!stralloc_readyplus(&sa,1)) return SPF_NOMEM;

  if (mech->expands && str_diff(spfspec,domain)) {

    if (!spf_parse(&sa,spfspec,domain)) return SPF_NOMEM;

    for (pos = 0; (sa.len - pos) > 255;) {
      pos += byte_chr(sa.s + pos,sa.len - pos,'.');
      if (pos < sa.len) pos++;
    }
    sa.len -= pos;
    if (pos > 0) byte_copy(sa.s,sa.len,sa.s + pos);
    if (!stralloc_0(&sa)) return SPF_NOMEM;
    spfspec = sa.s;
  }

  r = mech->func(spfspec,prefix);
  return r;
}

/**
 @brief  spf_include
         deals with recursive evaluation of SPF record [RFC7208 Sec. 5.2]
 @param  input:  pointer to included SPF specification; CIDR prefix length
 @return int r = 1 ok; 0 failure
 */

int spf_include(char *spfspec,char *prefix)
{
  stralloc sa = {0};
  int r;

  if (!stralloc_copys(&sa,spfspec)) return SPF_NOMEM;
  if (!stralloc_0(&sa)) return SPF_NOMEM;
  if (!spf_info("I=",sa.s)) return SPF_NOMEM;
  r = spf_lookup(&sa);

  switch(r) {
    case SPF_NONE:     r = SPF_UNKNOWN; break;
    case SPF_SYNTAX:   r = SPF_UNKNOWN; break;
    case SPF_NEUTRAL:
    case SPF_SOFTFAIL:
    case SPF_FAIL:     r = SPF_NONE; break;
  }
  
  return r;
}

/**
 @brief  spf_parse
         parses the substructure of the SPF record and calls spf_macros
 @param  input:  pointer to SPF specification, pointer to domain
         output: stralloc sa 
 @output pointer to spfspec: with found data
 @return int r = 1 ok; 0 failure
 */

int spf_parse(stralloc *sa,char *spfspec,char *domain)
{
  char *p;
  int pos;
  char append;

  if (!stralloc_readyplus(sa,3)) return 0;
  sa->len = 0;
 
  for (p = spfspec; *p; ++p) {
    append = *p;
    if (byte_equal(p,1,"%")) {
      p++;
      switch (*p) {
        case '%': break;
        case '_': append = ' '; break;
        case '-': if (!stralloc_cats(sa,"%20")) return 0; continue;
        case '{':
          pos = str_chr(p,'}');
          if (p[pos] != '}') { p--; break; }
          p[pos] = '\0';  
          if (!spf_macros(sa,p + 1,domain)) return 0;
          p += pos;
          continue;
        default: p--;
      }
    }
    if (!stralloc_readyplus(sa,1)) return 0;
    if (!stralloc_append(sa,&append)) return 0;
  }

  return 1;
}

/**
 @brief  spf_macros
         deals with macros in the SPF specificaton [RFC7208 Sec. 7ff]
 @param  input:  pointer to SPF macro, pointer to domain
         output: pointer to stralloc expand(ed information)
 @return int r = 1 ok; 0 failure
 */

int spf_macros(stralloc *expand,char *macro,char *domain)
{
  static char hextab[] = "0123456789abcdef";
  stralloc sa = {0};
  int reverse = 0;
  int ndigits = -1;
  int urlencode;
  unsigned long u;
  char ch = {0};
  char ascii;
  int pos, i, n; 
  int start = expand->len; 

  /* URL encoding - hidden in RFC 7208 Sec. 7.3 */

  if (*macro == 'x') { urlencode = -1; ++macro; } else urlencode = 0;
  ch = *macro;
  if (!ch) { return 1; }
  if (ch >= 'A' && ch <= 'Z')  { ch += 32; urlencode = 1; }
  if (urlencode == -1) ch -= 32;

  /* No. digits determine number of printed labels */
 
  i = 0;
  while (*macro) {
    i++;
    if (*macro == '}') break;
    if (*macro >= '0' && *macro <= '9') {
      scan_ulong(macro,&u); ndigits = u; 
    } else if (i > 1 && *macro == 'r') { reverse = 1; break; }	/* Reverse representation */
    macro++;
  }

  switch (ch) {							/* see RFC7208 sec. 7.2 */
    case 's': case 'S':
      if (!stralloc_readyplus(&sa,spfmf.len)) return 0;
      if (!stralloc_copys(&sa,spfmf.s)) return 0;
      break;
    case 'l': case 'L':
      i = byte_rchr(spfmf.s,spfmf.len,'@');
      if (i < spfmf.len) {
        if (!stralloc_copyb(&sa,spfmf.s,i)) return 0;
      } else {
        if (!stralloc_copys(&sa,"postmaster")) return 0;
      }
      break;
    case 'o': case 'O':
      i = byte_rchr(spfmf.s,spfmf.len,'@') + 1;
      if (i > spfmf.len) break;
      if (!stralloc_copys(&sa,spfmf.s + i)) return 0;
      break;
    case 'd': case 'D':
      if (!stralloc_readyplus(&sa,str_len(domain))) return 0;
      if (!stralloc_copys(&sa,domain)) return 0;
      break;
    case 'i': case 'c': case 'I': case 'C':
      if (!stralloc_ready(&sa,IPFMT)) return 0;
      if (flagip6) {
        sa.len = ip6_fmt(sa.s,ip6remote);
      } else {
        sa.len = ip4_fmt(sa.s,ip4remote);
      }
      break;
    case 'p': case 'P':
      if (!dnsname.len) spf_ptr(domain,0);
      if (dnsname.len) {
        if (!stralloc_copys(&sa,dnsname.s)) return 0;
      } else {
        if (!stralloc_copys(&sa,"unknown")) return 0; 
      }
      break;
    case 'h': case 'H':
      if (!stralloc_copys(&sa,spfhelo.s)) return 0; /* FIXME: FQDN? */
      break;
    case 't': case 'T':
      if (!stralloc_ready(&sa,FMT_ULONG)) return 0;
      sa.len = fmt_ulong(sa.s,(unsigned long)now());
      break;
    case 'v': case 'V':
      if (flagip6) {
        if (!stralloc_copys(&sa,"ip6")) return 0;
      } else {
        if (!stralloc_copys(&sa,"in-addr")) return 0; 
      }
      break;
    case 'r': case 'R':
      if (!stralloc_readyplus(&sa,spflocal.len)) return 0;
      if (!stralloc_copys(&sa,spflocal.s)) return 0; 
      break;
    default: break;
  }
  if (!stralloc_0(&sa)) return 0;

  if (reverse) {
    n = 0;
    for (i = 1; i <= sa.len; i++) {
      if ((ndigits == -1) || (n < ndigits)) {
        if (!byte_diff(sa.s + sa.len - i - 1,1,".") || (i == sa.len)) {
          n++;
          if (!stralloc_cats(expand,sa.s + sa.len - i)) return 0;
          if (i < sa.len) {
            sa.s[sa.len - i - 1] = 0;
            if (!stralloc_cats(expand,".")) return 0;
          } 
        }
      } 
    }
  } else if (ndigits != -1) {
    n = pos = 0;
    for (i = 1; i <= sa.len; i++) {
      if (n < ndigits) {
        if (!byte_diff(sa.s + i,1,".")) { n++; pos = i; }
      }
    }
    if (!stralloc_catb(expand,sa.s,pos)) return 0;
  } else 
    if (!stralloc_cats(expand,sa.s)) return 0;

  if (urlencode) {
    stralloc_copyb(&sa, expand->s + start, expand->len - start);
    expand->len = start;

    for (i = 0; i < sa.len; ++i) {
      ch = sa.s[i];
      if (urlchr_table[(unsigned char)ch]) {
        if (!stralloc_readyplus(expand,3)) return 0;
        if (!stralloc_append(expand,"%")) return 0;
        ascii = hextab[(unsigned char)ch >> 4];
        if (!stralloc_append(expand,&ascii)) return 0;
        ascii = hextab[(unsigned char)ch & 0x0f];
        if (!stralloc_append(expand,&ascii)) return 0;
      } else {
        if (!stralloc_append(expand,&ch)) return 0;
      }
    }
  } 

  return 1;
}

int spf_info(char *s,char *t)
{
  if (!stralloc_cats(&spfinfo,s)) return 0;
  if (!stralloc_cats(&spfinfo,t)) return 0;
  if (!stralloc_cats(&spfinfo," ")) return 0;

  return 1;
}
