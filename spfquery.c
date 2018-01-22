#include <string.h>
#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "alloc.h"
#include "spf.h"
#include "exit.h"
#include "dns.h"
#include "str.h"
#include "byte.h"

void die(int e,char *s) { substdio_putsflush(subfderr,s); _exit(e); }
void die_usage() { die(100,"fatal: invalid usage\nusage: spfquery <sender-ip> <sender-helo/ehlo> <envelope-from> [<local rules>] [-v(erbose) ] \n"); }
void die_nomem() { die(111,"fatal: out of memory\n"); }

/* extern stralloc spfinfo;
extern stralloc spfmf;
extern stralloc spfhelo;
extern stralloc spfdomain;
extern stralloc spfrecord;
extern stralloc spfexplain; 
extern stralloc expdomain;
extern stralloc spfexpmsg; */

static stralloc heloin = {0};
static stralloc mfin = {0};
static stralloc spflocal = {0};
static stralloc spfbounce = {0};

int main(int argc,char **argv)
{
  stralloc spfip = {0};
  int flag = 0;
  int r;
  int verbose = 0;

  if (argc < 4) die_usage();
  if (argc > 1 && byte_equal(argv[1],2,"-v")) die_usage();
  if (argc > 2 && byte_equal(argv[2],2,"-v")) die_usage();
  if (argc > 3 && byte_equal(argv[3],2,"-v")) die_usage();

  if (!stralloc_copys(&spfip,argv[1])) die_nomem();
  if (!stralloc_0(&spfip)) die_nomem();
  r = byte_chr(spfip.s,spfip.len,':');
  if (r < spfip.len) flag = 1;

  if (!stralloc_copys(&heloin,argv[2])) die_nomem();
  if (!stralloc_0(&heloin)) die_nomem();

  if (!stralloc_copys(&mfin,argv[3])) die_nomem();
  if (!stralloc_0(&mfin)) die_nomem();

  if (argc > 4) {
    if (!byte_diff(argv[4],2,"-v")) verbose = 1;
    else {
      if (!stralloc_copys(&spflocal,argv[4])) die_nomem();
      if (spflocal.len && !stralloc_0(&spflocal)) die_nomem();
    }
  }

  if (argc > 5) {
    if (!byte_diff(argv[5],2,"-v")) verbose = 1;
  }

  if (!stralloc_copys(&spfexplain,SPF_DEFEXP)) die_nomem();
  if (!stralloc_0(&spfexplain)) die_nomem();

  dns_init(0);
  r = spf_query(spfip.s,heloin.s,mfin.s,"localhost",flag);
  if (r == SPF_NOMEM) die_nomem();

  substdio_puts(subfdout,"result=");
  switch (r) {
    case SPF_ME:       substdio_puts(subfdout,"loopback"); break;
    case SPF_OK:       substdio_puts(subfdout,"pass"); break;
    case SPF_NONE:     substdio_puts(subfdout,"none"); break;
    case SPF_UNKNOWN:  substdio_puts(subfdout,"unknown"); break;
    case SPF_NEUTRAL:  substdio_puts(subfdout,"neutral"); break;
    case SPF_SOFTFAIL: substdio_puts(subfdout,"softfail"); break;
    case SPF_FAIL:     substdio_puts(subfdout,"fail"); break;
    case SPF_ERROR:    substdio_puts(subfdout,"error"); break;
    case SPF_SYNTAX:   substdio_puts(subfdout,"IP address syntax error"); break;
    default:           substdio_puts(subfdout,"undefined"); break; 
  }

  substdio_putsflush(subfdout,"\n");
  if (r == SPF_SYNTAX) _exit(1);

  if (verbose) {
    substdio_puts(subfdout,"SPF records read: \n");
    substdio_put(subfdout,spfrecord.s,spfrecord.len);
  }

  substdio_puts(subfdout,"SPF information evaluated: ");
  substdio_put(subfdout,spfinfo.s,spfinfo.len);
  substdio_putsflush(subfdout,"\n");

  if (r == SPF_FAIL) {
    substdio_puts(subfdout,"SPF results returned: ");
    if (!spf_parse(&spfbounce,spfexpmsg.s,expdomain.s)) die_nomem();
    substdio_put(subfdout,spfbounce.s,spfbounce.len);
    substdio_putsflush(subfdout,"\n"); 
  }

  _exit(0);
}
