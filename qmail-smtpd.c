/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
 *  Revision 20171214, Erwin Hoffmann
 *  - changed struct ip/ip6 to char ip4[4]/ip[16]
*/
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "rcpthosts.h"
#include "recipients.h"
#include "mfrules.h"
#include "tls_start.h"
#include "smtpdlog.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "dns.h"
#include "wait.h"
#include "sig.h"
#include "fd.h"
#include "open.h"
#include "base64.h"
#include "spf.h"
#include "cdbread.h"
#include "qmail-spp.h"   // qmail-spp:

#define FDAUTH 3

/** @file qmail-smtpd.c -- authenticating ESMTP/ESMTPS server
    @brief requires sslserver or tcpserver */

#define PAM111421
#define AUTHSLEEP 5
#define PORT_SMTPS "465"

#define MIMETYPE_LEN 9
#define LOADER_LEN 5
#define BASE64MESSAGE "content-transfer-encoding: base64"
#define FDLOG 2

#define BUF_SIZE 1024
#define MAXHOPS 100
unsigned long databytes = 0;
int timeout = 1200;

#define SPP 1   // unset to deactivate qmail-spp
#ifdef SPP
// qmail-spp: (2 lines)
extern void spp_rcpt_accepted();
int spp_val;
#endif

int safewrite(int fd,char *buf,int len)
{
  int r;
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) _exit(1);
  return r;
}

char ssoutbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof(ssoutbuf));

void flush() { substdio_flush(&ssout); }
void out(char *s) { substdio_puts(&ssout,s); }

int saferead(int fd,char *buf,int len)
{
  int r;
  flush();
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == ETIMEDOUT) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[BUF_SIZE];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof(ssinbuf));
char ssinfo[128];
substdio ssrbl = SUBSTDIO_FDBUF(saferead,0,ssinfo,sizeof(ssinfo));

/* this file is too long -------------------------------------- Greeting      */

static stralloc greeting = {0};

void smtp_greet(char *code)
{
  substdio_puts(&ssout,code);
  substdio_put(&ssout,greeting.s,greeting.len);
}
void smtp_help()
{
  out("214 s/qmail home page: http://fehcom.de/sqmail.html\r\n");
}
void smtp_quit()
{
  smtp_greet("221 "); out("\r\n"); flush(); _exit(0);
}

char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *localport;
char *relayclient;
int flagip6 = 1;
int smtputf8 = 0;

stralloc protocol = {0};
stralloc utf8proto = {0};
stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */
stralloc tlsinfo = {0};

char *helocheck;
int flagbadhelo;
int flagdnshelo;
int seenhelo = 0;

char *badmailcond;
char *badhelocond;

void dohelo(char *arg)
{
  if (!stralloc_copys(&helohost,arg)) die_nomem();
  if (!stralloc_0(&helohost)) die_nomem();
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
  if (helocheck) {
    if (str_len(helocheck) == 1) {
      switch (*helocheck) {
        case '=': flagbadhelo = bhelocheck();
                  if (fakehelo) { flagdnshelo = 1; badhelocond = "="; }
                  break;
        case 'A': flagbadhelo = bhelocheck();
                  if (flagbadhelo == 0) { flagdnshelo = dnsq(helohost.s,"A"); badhelocond = "A"; }
                  break;
        case 'M': flagbadhelo = bhelocheck();
                  if (flagbadhelo == 0) { flagdnshelo = dnsq(helohost.s,"M"); badhelocond = "M"; }
                  break;
        case '.': flagbadhelo = bhelocheck();
                  if (!str_len(arg)) flagbadhelo = -2; 
                  break;
        case '!': if (!str_len(arg)) flagbadhelo = -2;  
                  break;
      }
    } else {
       flagbadhelo = bhelocheck();
    }
    if (flagbadhelo == -3) flagbadhelo = 0;
  }
  if (!env_unset("HELOHOST")) die_read();
  if (!env_put("HELOHOST",helohost.s)) die_nomem();
}

int liphostok = 0;
stralloc liphost = {0};

int bmfok = 0;
stralloc bmf = {0};
struct constmap mapbmf;

int brtok= 0;
stralloc brt = {0};
struct constmap mapbrt;

int badhelook = 0;
stralloc badhelo = {0};
struct constmap mapbhlo;

static int fdbmt;
int flagmimetype = 0;   /* 1: white; 2: cdb; 3: white+cdb; 4: !relay+white; 6: !relay+white+cdb; -1: found in cdb; -2: found white */
char *badmimeinit;

static int fdblt;
int flagloadertype = 0;   /* 1: cdb; 2: !relay+cdb; -1: found in cdb */
char *badloaderinit;

static int fdmav;
int flagmav = 0;
int localmf = 0;    /* 1: domainpart->rcpthosts; 2: ->mailformrules; 3: ->remoteinfo; 4: ->DN(Email) */
char *localmfcheck;

char *mfdnscheck;
char *qhpsi;
char *base64;

int maxrcptcount = 0;
int flagerrcpts = 0;
int flagnotorious = 0;

int tarpitcount = 0;
int tarpitdelay = 0;

char *auth;
int smtpauth = 0; /* -1:Cert 0:none 1:login/plain 2:cram 3:login/plain/cram 11:must_login/plain 12:must_2 13:must_3 */
int seenauth = 0; /* 1:ESMTPA 2:~CLIENTDN */
stralloc authmethod = {0};

int starttls = 0; /* -1:TLS 0:none 1:STARTTLS 2:require_STARTTLS 3:relay_if_CLIENTDN 4:require_+_relay_if_CLIENTDN */
int seentls = 0;  /* 1:~STARTTLS 2:~TLS 3:~CLIENTDN */
char *ucspitls;
char *tlsversion;
char *cipher;
char *cipherperm;
char *cipherused;
char *clientdn;
char *clientcn;
char *dnemail;

stralloc mailto = {0};
stralloc deliverto = {0};
char *delivermailto;
stralloc rblinfo = {0};
char *rblsmtpd;

int flagspf = 0;
int localrules = 0;
stralloc spfexplain = {0};
stralloc spflocalrules = {0};
static stralloc spfbounce = {0};

void setup()
{
  char *x;
  unsigned long u;

  if (control_init() == -1) die_control();
  if (control_rldef(&greeting,"etc/smtpgreeting",1,(char *) 0) != 1)
    die_control();
  liphostok = control_rldef(&liphost,"etc/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();
  if (control_readint(&timeout,"etc/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;

  if (rcpthosts_init() == -1) die_control();
// qmail-spp: (1 line)
#ifdef SPP
if (spp_init() == -1) die_control();
#endif
  if (recipients_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"etc/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  brtok = control_readfile(&brt,"etc/badrcptto",0);
  if (brtok == -1) die_control();
  if (brtok)
    if (!constmap_init(&mapbrt,brt.s,brt.len,0)) die_nomem();

  if (control_readint(&databytes,"etc/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;

  if (!stralloc_copys(&protocol,"ESMTP")) die_nomem();   /* RFC 3848 */
  remoteip = env_get("TCP6REMOTEIP");     /* compactified IPv6 */
  if (!remoteip) { remoteip = env_get("TCPREMOTEIP"); flagip6 = 0; }
  if (remoteip && byte_equal(remoteip,7,V4MAPPREFIX))
    { remoteip = remoteip + 7; flagip6 = 0; }
  if (!remoteip) { remoteip = "unknown"; flagip6 = -1; }
  local = env_get("TCP6LOCALHOST");
  if (!local) local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCP6LOCALIP");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
  localport = env_get("TCP6LOCALPORT");
  if (!localport) localport = env_get("TCPLOCALPORT");
  if (!localport) localport = "0";
  remotehost = env_get("TCP6REMOTEHOST");
  if (!remotehost) remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCP6REMOTEINFO");
  if (!remoteinfo) remoteinfo = env_get("TCPREMOTEINFO");
  relayclient = env_get("RELAYCLIENT");

  if (!case_diffs(localport,PORT_SMTPS)) {
    if (!modssl_info()) die_starttls();
    starttls = -1;
  }

  mfdnscheck = env_get("MFDNSCHECK");
  x = env_get("MAXRECIPIENTS");
  if (x) { scan_ulong(x,&u); maxrcptcount = u; };
  if (!(maxrcptcount + 1)) --maxrcptcount;

  helocheck = env_get("HELOCHECK");
  if (helocheck) {
    badhelook = control_readfile(&badhelo,"etc/badhelo",0);
    if (badhelook == -1) die_control();
    if (badhelook)
      if (!constmap_init(&mapbhlo,badhelo.s,badhelo.len,0)) die_nomem();
  }

  x = env_get("TARPITCOUNT");
  if (x) { scan_ulong(x,&u); tarpitcount = u; };
  x = env_get("TARPITDELAY");
  if (x) { scan_ulong(x,&u); tarpitdelay = u; };

  localmfcheck = env_get("LOCALMFCHECK");
  if (localmfcheck) {
    localmf = 1;
    if (str_len(localmfcheck) == 1 && *localmfcheck == '!') {
      localmf = 2;
      fdmav = open_read("etc/mailfromrules.cdb");
      if (fdmav == -1 ) localmf = 1;
    }
    if (str_len(localmfcheck) == 1 && *localmfcheck == '=') {
      localmf = 3;
    }
    if (str_len(localmfcheck) == 1 && *localmfcheck == '?') {
      localmf = 4;
    }
  }

  badmimeinit = env_get("BADMIMETYPE");
  if (badmimeinit) {
    if (str_len(badmimeinit) == 1) {
      if (*badmimeinit == '-')
        flagmimetype = 0;
      else {
        if (*badmimeinit == '!') flagmimetype = 1;
        if (*badmimeinit == '+') flagmimetype = 4;
        fdbmt = open_read("etc/badmimetypes.cdb");
        if (fdbmt != -1 ) flagmimetype = flagmimetype + 2;
      }
    }
  }

  badloaderinit = env_get("BADLOADERTYPE");
  if (badloaderinit) {
    if (str_len(badloaderinit) == 1) {
      if (*badloaderinit == '-')
        flagloadertype = 0;
      else {
        flagloadertype = 1;
        if (*badloaderinit == '+') flagloadertype = 2;
        fdblt = open_read("etc/badloadertypes.cdb");
        if (fdblt == -1 ) flagloadertype = 0;
      }
    }
  }

  base64 = env_get("BASE64");
  qhpsi = env_get("QHPSI");
  auth = env_get("SMTPAUTH");
  if (auth) {
    smtpauth = 1;
    if (!case_diffs(auth,"-")) smtpauth = 0;
    if (!case_diffs(auth,"!")) smtpauth = 11;
    if (case_starts(auth,"cram")) smtpauth = 2;
    if (case_starts(auth,"+cram")) smtpauth = 3;
    if (case_starts(auth,"!cram")) smtpauth = 12;
    if (case_starts(auth,"!+cram")) smtpauth = 13;
  }

  if (!seentls) {
    ucspitls = env_get("UCSPITLS");
    if (ucspitls) {
      starttls = 1;
      if (!case_diffs(ucspitls,"-")) starttls = 0;
      if (!case_diffs(ucspitls,"!")) starttls = 2;
      if (!case_diffs(ucspitls,"?")) starttls = 3;
      if (!case_diffs(ucspitls,"@")) starttls = 4;
    }
  }

  delivermailto = env_get("DELIVERTO");
  if (delivermailto) {
    if (!stralloc_cats(&mailto,delivermailto)) die_nomem();
    if (!stralloc_cats(&mailto," ")) die_nomem();
  }

  rblsmtpd = env_get("RBLSMTPD");
  if (rblsmtpd) {
    if (!stralloc_cats(&rblinfo,rblsmtpd)) die_nomem();
    if (!stralloc_0(&rblinfo)) die_nomem();
  }

  x = env_get("SPF");
  if (x) { scan_ulong(x,&u); flagspf = u; }
  if (flagspf < 0 || flagspf > 6) die_control();
  if (flagspf) {
    localrules = control_readline(&spflocalrules,"etc/spflocalrules");
    if (localrules == -1) die_control();
    if (!stralloc_0(&spflocalrules)) die_nomem();
    if (control_rldef(&spfexplain,"etc/spfexplain",0,SPF_DEFEXP) == -1) die_control();
    if (!stralloc_0(&spfexplain)) die_nomem();
  }

  if (!stralloc_copys(&helohost,"")) die_nomem();    /* helohost is empty */
  if (!stralloc_0(&helohost)) die_nomem();
  fakehelo = 0;
}

void auth_info(char *method)
{
 if (!env_unset("AUTHPROTOCOL")) die_read();
 if (!env_put("AUTHPROTOCOL",method)) die_nomem();

 if (!env_unset("AUTHUSER")) die_read();
 if (!env_put("AUTHUSER",remoteinfo)) die_nomem();

 if (!env_unset("TCPREMOTEINFO")) die_read();
 if (!env_put("TCPREMOTEINFO",remoteinfo)) die_nomem();

 if (!stralloc_append(&protocol,"A")) die_nomem();
}

int modssl_info()
{
  tlsversion = env_get("SSL_PROTOCOL");
  if (!tlsversion) return 0;

  cipher = env_get("SSL_CIPHER");
  if (!cipher) cipher = "unknown";
  cipherperm = env_get("SSL_CIPHER_ALGKEYSIZE");
  if (!cipherperm) cipherperm = "unknown";
  cipherused = env_get("SSL_CIPHER_USEKEYSIZE");
  if (!cipherused) cipherused = "unknown";
  clientdn = env_get("SSL_CLIENT_S_DN");
  if (!clientdn) clientdn = "none";
  else {
    seentls = 3;
    seenauth = 2;
    smtpauth = -1;
    relayclient = "";
  }

  if (!stralloc_copys(&tlsinfo,tlsversion)) die_nomem();
  if (!stralloc_cats(&tlsinfo,": ")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipher)) die_nomem();
  if (!stralloc_cats(&tlsinfo," [")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipherused)) die_nomem();
  if (!stralloc_cats(&tlsinfo,"/")) die_nomem();
  if (!stralloc_cats(&tlsinfo,cipherperm)) die_nomem();
  if (!stralloc_cats(&tlsinfo,"] ")) die_nomem();
  if (!stralloc_cats(&tlsinfo,"DN=")) die_nomem();
  if (!stralloc_cats(&tlsinfo,clientdn)) die_nomem();
  if (!stralloc_0(&tlsinfo)) die_nomem();

  if (!stralloc_append(&protocol,"S")) die_nomem();

  if (seentls == 3 && starttls == 4) {
    clientcn = env_get("SSL_CLIENT_S_DN_CN");
    remoteinfo =  clientcn ? clientcn : clientdn;
    dnemail = env_get("SSL_CLIENT_S_DN_Email");
    if (!dnemail) dnemail = "unknown";
    if (!stralloc_cats(&authmethod,"cert")) die_nomem();
    auth_info(authmethod.s);
  }
  return 1;
}

/* this file is too long --------------------------------- SMTP ADDRESSES */

stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */
stralloc eddr = {0}; /* extended address; used for smart address recognition */
stralloc rddr = {0}; /* test anti-spoofing host name */
stralloc sa = {0};
stralloc mailfrom = {0};
stralloc rcptto = {0};
stralloc user = {0};
stralloc fuser = {0};
stralloc mfparms = {0};

ipalloc ia = {0};

int seenmail = 0;
int flagbarf; /* defined if seenmail */
int flagrcpt;
int flagdnsmf = 0;
int flagsize;
int rcptcount = 0;
// qmail-spp: (2 lines)
#ifdef SPP
int allowed;
int addrparse(char *arg)
#endif
{
  int i;
  char ch;
  char terminator;
  char ip4[4];
  char ip6[16];
  int flagesc;
  int flagquoted;

  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else
    return 0;

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0; (ch = arg[i]); ++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch (ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[') {
        if (byte_rchr(addr.s + i + 2,addr.len - i - 2,':')) {  /* @[IPv6::] */
          if (!addr.s[i + 1 + ip6_scanbracket(ip6,addr.s + i + 1)])
             if (ipme_is6(&ip6)) {
               addr.len = i + 1;
               if (!stralloc_cat(&addr,&liphost)) die_nomem();
               if (!stralloc_0(&addr)) die_nomem();
             }
        } else {  /* @[IPv4] */
          if (!addr.s[i + 1 + ip4_scanbracket(ip4,addr.s + i + 1)])
            if (ipme_is4(&ip4)) {
              addr.len = i + 1;
              if (!stralloc_cat(&addr,&liphost)) die_nomem();
              if (!stralloc_0(&addr)) die_nomem();
            }
        }
      }
  }

  if (addr.len > 900) return 0;
  return 1;
}

int bmfcheck()
{
  int i = 0;
  int j = 0;
  int k = 0;
  int dlen;
  char subvalue;

  if (bmfok) {
    int rlen = str_len(remotehost);
    int at = byte_rchr(mailfrom.s,mailfrom.len,'@');
    if (at >= mailfrom.len) at = 0;

/* '?' enhanced address to skip all other tests including MFDNSCHECK */

    eddr.len = 0;
    if (!stralloc_copys(&eddr,"?")) die_nomem();
    if (!stralloc_cat(&eddr,&mailfrom)) die_nomem();
    case_lowerb(eddr.s,eddr.len);
    if (constmap(&mapbmf,eddr.s,eddr.len - 1)) return -110;

/* '+' extended address for none-RELAYCLIENTS */

    if (at && !relayclient) {
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,mailfrom.s,mailfrom.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"+")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -5;
    }

/* '-' extended address from UNKNOWN */

    if (at && !case_diffs(remotehost,"unknown")) {
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,mailfrom.s,mailfrom.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"-")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -4;
    }

/* '=' extended address for WELLKNOWN senders */

    else if (at && rlen >= mailfrom.len - at - 1) {
      dlen = mailfrom.len - at - 2;
      eddr.len = 0;
      if (!stralloc_copyb(&eddr,mailfrom.s,mailfrom.len - 1)) die_nomem();
      if (!stralloc_append(&eddr,"=")) die_nomem();
      if (!stralloc_0(&eddr)) die_nomem();
      case_lowerb(eddr.s,eddr.len);
      if (str_diffn(remotehost + rlen - dlen,eddr.s + at + 1,dlen))
        if (constmap(&mapbmf,eddr.s + at,eddr.len - at - 1)) return -3;

/* '~' extended address for MISMATCHED Domains */

      if (case_diffrs(remotehost,mailfrom.s + at + 1)) {
        j = 0;
        do {
          eddr.len = 0;
          if (!stralloc_copys(&eddr,"~")) die_nomem();
          if (!stralloc_cats(&eddr,remotehost + j)) die_nomem();
          if (!stralloc_0(&eddr)) die_nomem();
          if (constmap(&mapbmf,eddr.s,eddr.len - 1)) return -2;
          j = byte_chr(remotehost + j,rlen - j,'.') + j + 1;
        }
        while (j > 0 && rlen - j > 0);
      }
    }

/* Standard */

    if (constmap(&mapbmf,mailfrom.s,mailfrom.len - 1)) return -1;
    if (at && at < mailfrom.len)
      if (constmap(&mapbmf,mailfrom.s + at,mailfrom.len - at - 1)) return -1;

/* Wildmating */

    i = k = 0;
    for (j = 0; j < bmf.len; ++j) {
      if (!bmf.s[j]) {
        subvalue = bmf.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(mailfrom.s,bmf.s + i)) k = subvalue;
        i = j + 1;
      }
    }
    return k;
  }

  return 0;
}

int brtcheck()
{
  int i;
  int j;
  int k = 0;
  char subvalue;

  if (brtok) {
    if (constmap(&mapbrt,addr.s,addr.len - 1)) return -2;

    int at = byte_rchr(addr.s,addr.len,'@');
    if (at < addr.len)
      if (constmap(&mapbrt,addr.s + at,addr.len - at - 1)) return -1;

    i = 0;
    for (j = 0; j < brt.len; ++j)
      if (!brt.s[j]) {
        subvalue = brt.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(addr.s,brt.s + i)) k = subvalue;
        i = j + 1;
      }
    return k;
  }
  return 0;
}

int bhelocheck()
{
  int i;
  int j;
  int k = 0;
  char subvalue;

  if (badhelook && helohost.len) {
    eddr.len = 0;             /* helohost! */
    if (!stralloc_copyb(&eddr,helohost.s,helohost.len - 1)) die_nomem();
    if (!stralloc_append(&eddr,"!")) die_nomem();
    if (!stralloc_0(&eddr)) die_nomem();
    if (constmap(&mapbhlo,eddr.s,eddr.len - 1)) return -3;

    if (constmap(&mapbhlo,helohost.s,helohost.len - 1)) return -1;

    i = 0;
    for (j = 0; j < badhelo.len; ++j)
      if (!badhelo.s[j]) {
        subvalue = badhelo.s[i] != '!';
        if (!subvalue) i++;
        if ((k != subvalue) && wildmat(helohost.s,badhelo.s + i)) k = subvalue;
        i = j + 1;
      }
    return k;
  }
  return 0;
}

int dnsq(char *arg,char *type)
{
  unsigned int random;
  int at;
  int i = 0;
  int len;

  len = str_len(arg);
  if (len < 1) return -2;

  sa.len = 0;
  if (arg[len-1] == ' ') len--; /* trailing blank */
  if (len < 1) return -2;

  at = byte_rchr(arg,len,'@');
  if (at < len) {
    if (!stralloc_copyb(&sa,arg + at + 1,len - at - 1)) die_nomem();
  } else
    if (!stralloc_copyb(&sa,arg,len)) die_nomem();

  dns_init(0);
  random = now() + (getpid() << 16);
  switch (*type) {        /* Common for IPv4 and IPv6 */
    case 'A':  i = dns_ip(&ia,&sa); break;
    case 'M':  i = dns_mxip(&ia,&sa,random); break;
  }
  switch (i) {
    case DNS_HARD: return 1;
    case DNS_SOFT: out("451 DNS temporary failure (#4.3.0)\r\n"); return -1;
    case DNS_MEM:  die_nomem();
  }

  return 0;
}

int addrallowed(char *arg)
{
  int r;
  r = rcpthosts(arg,str_len(arg));
  if (r == -1) die_control();
  return r;
}

int rcptallowed()
{
  int r;
  r = recipients(addr.s,str_len(addr.s));
#ifdef PAM111421
  if (r == 111) die_recipients();
#endif
  if (r == -3) die_recipients();
  if (r == -2) die_nomem();
  if (r == -1) die_control();
  return r;
}

int localaddr(char *mf)
{
  int at;
  int mflen;

  mflen = str_len(mf);
  if (mflen < 1 ) return 0;

  if (localmf == 4) {
    if (!case_diffs(dnemail,mf)) return 2;
    return -4;
  }
  if (localmf == 3) {
    if (!case_diffs(remoteinfo,mf)) return 2;
    return -3;
  }
  else  if (localmf == 2)
    return mfrules(fdmav,remoteip,remotehost,remoteinfo,mf);
  else {
    if (str_len(localmfcheck) > 1) {
      case_lowerb(localmfcheck,str_len(localmfcheck));
      at = byte_rchr(mf,mflen,'@');
      if (at < mflen)
        if (!str_diffn(localmfcheck,mf + at + 1,mflen - at - 1)) return 2;
    }
    if (addrallowed(mf)) return 3;
    return -2;
  }
}

int spf_check(int flag)
{
  int r;
  dns_init(0);

  r = spf_query(remoteip,helohost.s,mailfrom.s,local,flag);
  if (r == SPF_NOMEM) die_nomem();
  if (!stralloc_0(&spfinfo)) die_nomem();

  switch (r) {
    case SPF_ME:
    case SPF_OK:   
      env_put("SPFRESULT","pass"); 
      flagspf = 10;
      break;
    case SPF_LOOP:
    case SPF_ERROR: 
    case SPF_SYNTAX:
    case SPF_EXHAUST:
      env_put("SPFRESULT","error");
      if (flagspf < 2) break;
      out("451 SPF lookup failure (#4.3.0)\r\n");
      return -1;
    case SPF_NONE: 
      env_put("SPFRESULT","none");
      flagspf = 0;
    case SPF_UNKNOWN:
      env_put("SPFRESULT","unknown");
      if (flagspf < 6) break;
      else return 4;
    case SPF_NEUTRAL:
      env_put("SPFRESULT","neutral");
      if (flagspf < 5) break;
      else return 3;
    case SPF_SOFTFAIL:
      env_put("SPFRESULT","softfail");
      if (flagspf < 4) break;
      else return 2;
    case SPF_FAIL:
      env_put("SPFRESULT","fail");
      if (flagspf < 3) break;
      if (!spf_parse(&spfbounce,spfexpmsg.s,expdomain.s)) die_nomem();
      if (!stralloc_0(&spfbounce)) die_nomem();
      return 1;
  }

  return 0;
}

int mailfrom_size(char *arg)
{
  long r;
  unsigned long sizebytes = 0;

  scan_ulong(arg,&r);
  sizebytes = r;
  if (databytes) if (sizebytes > databytes) return 1;
  return 0;
}

void mailfrom_auth(char *arg,int len)
{
  if (!stralloc_copys(&fuser,"")) die_nomem();
  if (case_starts(arg,"<>")) {
    if (!stralloc_cats(&fuser,"unknown")) die_nomem();
  } else {
    while (len) {
      if (*arg == '+') {
        if (case_starts(arg,"+3D")) {
          arg = arg + 2; len = len - 2;
          if (!stralloc_cats(&fuser,"=")) die_nomem();
        }
        if (case_starts(arg,"+2B")) {
          arg = arg + 2; len = len - 2;
          if (!stralloc_cats(&fuser,"+")) die_nomem();
        }
      } else {
        if (!stralloc_catb(&fuser,arg,1)) die_nomem();
      }
    arg++; len--;
    }
  }

  if (!stralloc_0(&fuser)) die_nomem();
  if (!remoteinfo) {
    remoteinfo = fuser.s;
    if (!env_unset("TCPREMOTEINFO")) die_read();
    if (!env_put("TCPREMOTEINFO",remoteinfo)) die_nomem();
    if (!env_unset("TCP6REMOTEINFO")) die_read();
    if (!env_put("TCP6REMOTEINFO",remoteinfo)) die_nomem();
  }
}

void mailfrom_parms(char *arg)
{
  int len;

  if (len = str_len(arg)) {
    if (!stralloc_copys(&mfparms,"")) die_nomem();
      while (len) {
        arg++; len--;
        if (*arg == ' ' || *arg == '\0' ) {
          if (case_starts(mfparms.s,"SMTPUTF8")) smtputf8 = 1;
          if (case_starts(mfparms.s,"SIZE=")) if (mailfrom_size(mfparms.s + 5)) { flagsize = 1; return; }
          if (case_starts(mfparms.s,"AUTH=")) mailfrom_auth(mfparms.s + 5,mfparms.len - 5);
          if (!stralloc_copys(&mfparms,"")) die_nomem();
        }
        else
          if (!stralloc_catb(&mfparms,arg,1)) die_nomem();
     }
  }
}

/* this file is too long --------------------------------- SMTP DIALOG */

void smtp_helo(char *arg)
{
// qmail-spp: (1 line)
#ifdef SPP
if(!spp_helo(arg)) return;
#endif
  smtp_greet("250 "); out("\r\n");
  seenmail = 0; rcptcount = 0; seenhelo++; dohelo(arg);
}

void smtp_ehlo(char *arg)
{
// qmail-spp: (1 line)
#ifdef SPP
if(!spp_helo(arg)) return;
#endif
  char size[FMT_ULONG];
  size[fmt_ulong(size,(unsigned long) databytes)] = 0;
  smtp_greet("250-"); out("\r\n");
  out("250-PIPELINING\r\n250-SMTPUTF8\r\n250-8BITMIME\r\n");
  if (starttls > 0 && !seentls) out("250-STARTTLS\r\n");
  if (smtpauth > 0) {
    if (smtpauth == 1 || smtpauth == 11) out("250-AUTH LOGIN PLAIN\r\n");
    if (smtpauth == 2 || smtpauth == 12) out("250-AUTH CRAM-MD5\r\n");
    if (smtpauth == 3 || smtpauth == 13) out("250-AUTH LOGIN PLAIN CRAM-MD5\r\n");
  }
  out("250 SIZE "); out(size); out("\r\n");
  seenhelo++; seenmail = 0; rcptcount = 0; dohelo(arg);
}

void smtp_rset(void)
{
// qmail-spp: (1 line)
#ifdef SPP
spp_rset();
#endif
  seenmail = 0; rcptcount = 0; /* RFC 5321: seenauth + seentls stay */
  mailfrom.len = 0; rcptto.len = 0; ssin.p = 0;
  out("250 flushed\r\n");
}

void smtp_starttls()
{
  if (starttls == 0) { err_unimpl(); return; }
  out("220 Ready to start TLS (#5.7.0)\r\n");
  flush();

  if (!starttls_init()) die_starttls();
  seentls = 2;

  if (!starttls_info()) die_starttls();
  if (!modssl_info()) die_starttls();

/* reset SMTP state */

  seenhelo = 0; seenmail = 0; rcptcount = 0;
  helohost.len = 0; mailfrom.len = 0; rcptto.len = 0; ssin.p = 0;
  if (seenauth == 1) seenauth = 0; /* Otherwise Auth by client Cert */
}


void smtp_mail(char *arg)
{
  if ((starttls > 1) && !seentls) {    
    err_tlsreq("Reject::TLS::missing",protocol.s,remoteip,remotehost,helohost.s);
    return;
  }
  if (smtpauth > 10 && !seenauth) {   
    err_authreq("Reject::AUTH::missing",protocol.s,remoteip,remotehost,helohost.s);
    return;
  }
  if (!addrparse(arg)) { err_syntax(); return; }

// qmail-spp: added additional bracket '{' (second line)
#ifdef SPP
if (!(spp_val = spp_mail())); return;
if (spp_val == 1) {
#endif
  flagsize = 0;
  rcptcount = 0;
  mailfrom_parms(arg);
  seenmail++;
  if (relayclient && localmf) {
    flagmav = localaddr(addr.s);
    if (flagmav > 0) if (!stralloc_append(&protocol,"M")) die_nomem();
  }
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copy(&mailfrom,&addr)) die_nomem();

  if (!env_unset("MAILFROM")) die_read();
  if (!env_put("MAILFROM",mailfrom.s)) die_nomem();

  flagbarf = bmfcheck();
  if (flagbarf != -110) if (mfdnscheck) flagdnsmf = dnsq(mailfrom.s,"M");

  if (smtputf8) {
    if (!stralloc_copys(&utf8proto,"UTF8")) die_nomem();
    if (!stralloc_cat(&utf8proto,&protocol)) die_nomem();
    if (!stralloc_copy(&protocol,&utf8proto)) die_nomem();
  }
  if (!stralloc_0(&protocol)) die_nomem();

  if (!flagdnsmf) out("250 ok\r\n");
// qmail-spp: added bracket (next line)
#ifdef SPP
}
#endif
}

void smtp_rcpt(char *arg)
{
  char *rcptok = 0;
  if (!seenmail) { err_wantmail(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
  rcptcount++;

// qmail-spp: (3 lines)
#ifdef SPP
if (!relayclient) allowed = addrallowed(addr.s);
else allowed = 1;
if (!(spp_val = spp_rcpt(allowed))) return;
#endif

/* this file is too long --------------------------------- Split Horizon envelope checks */

  if (!relayclient) {
    if (!seenhelo && helocheck)       /* Helo rejects */
    if (str_len(helocheck) == 1) {
      err_helo("Reject::SNDR::Bad_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"0");
      return;
    }
    if (flagbadhelo) {
       switch (flagbadhelo) {
         case -2: badhelocond = "!"; break;
         case -1: badhelocond = "."; break;
         default: badhelocond = "*"; break;
       }
       err_helo("Reject::SNDR::Bad_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badhelocond);
       return;
    }
    if (flagdnshelo) {
      err_helo("Reject::SNDR::DNS_Helo",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badhelocond);
      return;
    }
    if (flagdnsmf > 0) {      /* Mail from rejects */
      err_mfdns("Reject::ORIG::DNS_MF",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return;
    }
    if (!addrallowed(addr.s)) {     /* Relaying rejects */
      err_nogateway("Reject::SNDR::Invalid_Relay",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return;
    }

    if (tarpitcount && flagerrcpts >= tarpitcount) {  /* Tarpitting et al. */
      if (tarpitdelay == 999) flagnotorious++;
      err_rcpts("Reject::RCPT::Toomany_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return;
    }
    if (tarpitcount && rcptcount >= tarpitcount)
      if (tarpitdelay > 0 && tarpitdelay < 999) sleep(tarpitdelay);

    flagrcpt = rcptallowed();     /* Rcpt to rejects */
    if (!flagrcpt) {
      err_recipient("Reject::RCPT::Failed_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      flagerrcpts++;
      return;
    }

    if (flagspf)             /* SPF rejects */
      if (spf_check(flagip6) > 0) {
        err_spf("Reject::SPF::Fail",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,spfbounce.s);
        return;
      }
  }

/* this file is too long --------------------------------- Local checks */

  else {
    if (flagmimetype == 4 || flagmimetype == 6) flagmimetype = 0;
    if (flagloadertype == 2) flagloadertype = 0;

    if (flagmav < 0) {
      err_mav("Reject::ORIG::Invalid_Mailfrom",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
      return;
    }
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  }

// qmail-spp: (4 lines)
#ifdef SPP
//else if (spp_val == 1) {   // --> initially we have hade an 'else', but now:
if (spp_val == 1) {
  if (!allowed) { //err_nogateway(); return; }  // err_no´gateway needs now arguments
      err_nogateway("Reject::SNDR::Invalid_Relay",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
  }
}
spp_rcpt_accepted();
#endif

/* this file is too long --------------------------------- Common checks */

  if (flagbarf && flagbarf != -110) {
    switch (flagbarf) {
      case -1: badmailcond = "@"; break;
      case -2: badmailcond = "~"; break;
      case -3: badmailcond = "="; break;
      case -4: badmailcond = "-"; break;
      case -5: badmailcond = "+"; break;
      default: badmailcond = "*"; break;
    }
    err_bmf("Reject::ORIG::Bad_Mailfrom",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badmailcond);
    return;
  }

  if (brtcheck()) {
    err_brt("Reject::RCPT::Bad_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
    return;
  }

  if (flagsize) {
    err_size("Reject::DATA::Invalid_Size",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
    return;
  }

  if (maxrcptcount && rcptcount > maxrcptcount) {
    err_rcpts("Reject::RCPT::Toomany_Rcptto",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
    return;
  }

/* this file is too long --------------------------------- Checks done; mailfrom/recipient accepted */

  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();

  if (!stralloc_cats(&mailto,addr.s)) die_nomem();
  if (!stralloc_cats(&mailto," ")) die_nomem();
  if (!stralloc_copys(&deliverto,mailto.s)) die_nomem();
  if (!stralloc_0(&deliverto)) die_nomem();

  if (!env_unset("RCPTTO")) die_read();
  if (!env_put("RCPTTO",deliverto.s)) die_nomem();

/* this file is too long --------------------------------- Additional logging */

  switch (flagrcpt) {
      case 1:  rcptok = "Recipients_Cdb"; break;
      case 2:  rcptok = "Recipients_Pam"; break;
      case 3:  rcptok = "Recipients_Wild"; break;
      default: rcptok = "Rcpthosts_Rcptto"; break;
  }
  if (seenauth)
    smtp_loga("Accept::AUTH::",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,remoteinfo,authmethod.s);
  else if (flagmav > 0)
    smtp_logg("Accept::ORIG::Local_Sender",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
  else if (relayclient)
    smtp_logg("Accept::SNDR::Relay_Client",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
  else if (flagspf == 10)
    smtp_logr("Accept::SPF::",rcptok,protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s); 
  else
    smtp_logr("Accept::RCPT::",rcptok,protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);

  out("250 ok\r\n");
}

struct qmail qqt;
unsigned long bytestooverflow = 0;

stralloc line = {0};
stralloc base64types = {0};
stralloc badmimetype = {0};
stralloc badloadertype = {0};

unsigned int nolines = 0;
unsigned int flagb64 = 0;       /* lineno with BASE64MESSAGE */
unsigned int flagbase = 0;      /* lineno with actual base64 content */
unsigned int flagblank = 0;

void put(char *ch)
{
//  uint32 dlen;
  struct cdb c;
  int i;

  if (flagmimetype > 0 || flagloadertype > 0 ) {
    if (line.len <= BUF_SIZE)
      if (!stralloc_catb(&line,ch,1)) die_nomem();      /* Reassamble chars to line; prepend with 'L' */

    if (*ch == '\n') {
      nolines++;
      if (line.len == 2) { flagblank = nolines; flagbase = 0; }

      if (*(line.s+1) == 'C' || *(line.s+1) == 'c')
        if (case_startb(line.s+1,line.len-2,BASE64MESSAGE)) flagb64 = nolines;
      if (flagb64 && nolines == flagblank+1 && line.len > MIMETYPE_LEN+2) flagbase = nolines;
      if (*(line.s+1) == '-')  { flagb64 = 0; flagbase = 0; }

      if (flagmimetype > 0 && flagbase == nolines) {                             /* badmimetype */
        if (!stralloc_catb(&base64types,line.s+1,MIMETYPE_LEN)) die_nomem();
        if (!stralloc_0(&base64types)) die_nomem();

        if (flagmimetype == 2 || flagmimetype == 3 || flagmimetype == 6) {
//          if (cdb_seek(fdbmt,line.s+1,MIMETYPE_LEN,&dlen)) {
          cdb_init(&c,fdbmt);
          if (cdb_find(&c,line.s+1,MIMETYPE_LEN)) {
            if (!stralloc_copyb(&badmimetype,line.s+1,MIMETYPE_LEN)) die_nomem();
            if (!stralloc_0(&badmimetype)) die_nomem();
            if (!stralloc_cats(&rcptto,"M")) die_nomem();
            if (!stralloc_0(&rcptto)) die_nomem();
            qmail_fail(&qqt);
            flagmimetype = -1;
          }
          cdb_free(&c);
        }
      }

      if (flagbase && line.len > LOADER_LEN + 2) {
        if (flagloadertype >= 1 || flagmimetype >= 1) {
          for (i = 0; i < line.len - LOADER_LEN; ++i) {
            if (flagloadertype == 1 && *(line.s+i) == *badloaderinit) {          /* badloadertype */
//              if (cdb_seek(fdblt,line.s+i,LOADER_LEN,&dlen)) {
              cdb_init(&c,fdblt);
              if (cdb_find(&c,line.s+i,LOADER_LEN)) {
                if (!stralloc_copyb(&badloadertype,line.s+i,LOADER_LEN)) die_nomem();
                if (!stralloc_0(&badloadertype)) die_nomem();
                if (!stralloc_cats(&rcptto,"L")) die_nomem();
                if (!stralloc_0(&rcptto)) die_nomem();
                qmail_fail(&qqt);
                flagloadertype = -1;
              }
              cdb_free(&c);
            }
            if (flagmimetype == 1 || flagmimetype == 3 || flagmimetype == 4) {
              if (*(line.s+i) == ' ' || *(line.s+i) == '\t') {                   /* white spaces */
                if (!stralloc_copyb(&badmimetype,line.s+i-2,MIMETYPE_LEN)) die_nomem();
                if (!stralloc_0(&badmimetype)) die_nomem();
                if (!stralloc_cats(&rcptto,"M")) die_nomem();
                if (!stralloc_0(&rcptto)) die_nomem();
                qmail_fail(&qqt);
                flagmimetype = -2;
              }
            }
          }
        }
      }
      line.len = 0;
      if (!stralloc_copys(&line,"L")) die_nomem();
    }
  }

  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
}

void blast(int *hops)
{
  char ch;
  int state;
  int seencr;
  int flaginheader;
  int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */

  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; seencr = 0;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (ch == '\n')
      {
       if (seencr == 0)
         { substdio_seek(&ssin,-1); ch = '\r'; }
      }
    if (ch == '\r') seencr = 1; else seencr = 0;
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
        ++pos;
      }
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    switch (state) {
      case 0:
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 4; continue; }
        break;
      case 1: /* \r\n */
        if (ch == '\n') straynewline();
        if (ch == '.') { state = 2; continue; }
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 2: /* \r\n + . */
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 3; continue; }
        state = 0;
        break;
      case 3: /* \r\n + .\r */
        if (ch == '\n') return;
        put(".");
        put("\r");
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 4: /* + \r */
        if (ch == '\n') { state = 1; break; }
        if (ch != '\r') { put("\r"); state = 0; }
    }
    put(&ch);
  }
}

char accept_buf[FMT_ULONG];

void acceptmessage(unsigned long qp)
{
  datetime_sec when;
  when = now();
  out("250 ok ");
  accept_buf[fmt_ulong(accept_buf,(unsigned long) when)] = 0;
  out(accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out("\r\n");
}

void smtp_data()
{
  int hops;
  unsigned long qp;
  char *qqx;

  if (!seenmail) { err_wantmail(); return; }
  if (!rcptto.len) { err_wantrcpt(); return; }
  if (flagnotorious) { err_notorious(); }
// qmail-spp: (1 line)
#ifdef SPP
if (!spp_data()) return;
#endif
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;

  if (!stralloc_copys(&addr,"")) die_nomem();
  if (!stralloc_cats(&addr,rcptto.s+1)) die_nomem();
  if (!stralloc_0(&addr)) die_nomem();

  if (qmail_open(&qqt) == -1) { err_qqt(); return; }
  qp = qmail_qp(&qqt);
  out("354 go ahead\r\n");

  if (smtputf8) {
    if (!stralloc_copys(&utf8proto,"UTF8")) die_nomem();
    if (!stralloc_cat(&utf8proto,&protocol)) die_nomem();
    if (!stralloc_copy(&protocol,&utf8proto)) die_nomem();
  }

  if (flagspf && !relayclient) spfheader(&qqt,spfinfo.s,local,remoteip,fakehelo,mailfrom.s);
  received(&qqt,protocol.s,local,remoteip,remotehost,remoteinfo,fakehelo,tlsinfo.s,rblinfo.s);
// qmail-spp: (2 lines)
#ifdef SPP
qmail_put(&qqt,sppheaders.s,sppheaders.len);  /* set in qmail-spp.c */
spp_rset();
#endif
  blast(&hops);
  hops = (hops >= MAXHOPS);
  if (hops) qmail_fail(&qqt);
  if (base64 && base64types.len == 0) {
    if (!stralloc_cats(&rcptto,"Q")) die_nomem();
    if (!stralloc_0(&rcptto)) die_nomem();
  }
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);

  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) { out("554 too many hops, this message is looping (#5.4.6)\r\n"); return; }
  if (databytes)
    if (!bytestooverflow) {
       err_size("Reject::DATA::Invalid_Size",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s);
       return;
    }
  if (flagmimetype < 0) {
    err_data("Reject::DATA::Bad_MIME",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badmimetype.s);
    return;
  }
  if (flagloadertype < 0) {
    err_data("Reject::DATA::Bad_Loader",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,badloadertype.s);
    return;
  }
  if (*qqx == 'S') {
    err_data("Reject::DATA::Spam_Message",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"spam");
    return;
  }
  if (*qqx == 'A') {
    err_data("Reject::DATA::MIME_Attach",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"MIME");
    return;
  }
  if (*qqx == 'V') {
    if (qhpsi)
      err_data("Reject::DATA::Virus_Infected",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,qhpsi);
    else
      err_data("Reject::DATA::Virus_Infected",protocol.s,remoteip,remotehost,helohost.s,mailfrom.s,addr.s,"AV scanner");
    return;
  }
  if (*qqx == 'D') out("554 "); else out("451 ");
  out(qqx + 1);
  out("\r\n");
}

/* this file is too long --------------------------------- SMTP AUTH */

char unique[FMT_ULONG + FMT_ULONG + 3];
static stralloc authin = {0};   /* input from SMTP client */
static stralloc pass = {0};     /* plain passwd or digest */
static stralloc resp = {0};     /* b64 response */
static stralloc chal = {0};     /* CRAM-MD5 plain challenge */
static stralloc slop = {0};     /* CRAM-MD5 b64 challenge */

char **childargs;
char ssauthbuf[512];
substdio ssauth = SUBSTDIO_FDBUF(safewrite,FDAUTH,ssauthbuf,sizeof(ssauthbuf));

int authgetl(void)
{
  int i;

  if (!stralloc_copys(&authin,"")) die_nomem();
  for (;;) {
    if (!stralloc_readyplus(&authin,1)) die_nomem(); /* XXX */
    i = substdio_get(&ssin,authin.s + authin.len,1);
    if (i != 1) die_read();
    if (authin.s[authin.len] == '\n') break;
    ++authin.len;
  }

  if (authin.len > 0) if (authin.s[authin.len - 1] == '\r') --authin.len;
  authin.s[authin.len] = 0;
  if (*authin.s == '*' && *(authin.s + 1) == 0) return err_authabort();
  if (authin.len == 0)  return err_authinput();
  return authin.len;
}

int authenticate(void)
{
  int child;
  int wstat;
  int pi[2];

  if (!stralloc_0(&user)) die_nomem();
  if (!stralloc_0(&pass)) die_nomem();
  if (!stralloc_0(&chal)) die_nomem();
  if (!env_put("AUTHUSER",user.s)) die_nomem();

  if (pipe(pi) == -1) return err_pipe();
  switch (child = fork()) {
    case -1:
      return err_fork();
    case 0:
      close(pi[1]);
      if (fd_copy(FDAUTH,pi[0]) == -1) return err_pipe();
      sig_pipedefault();
      execvp(*childargs, childargs);
      _exit(1);
  }
  close(pi[0]);

  substdio_fdbuf(&ssauth,write,pi[1],ssauthbuf,sizeof(ssauthbuf));
  if (substdio_put(&ssauth,user.s,user.len) == -1) return err_write();
  if (substdio_put(&ssauth,pass.s,pass.len) == -1) return err_write();
  if (smtpauth == 2 || smtpauth == 3 || smtpauth == 12 || smtpauth == 13)
    if (substdio_put(&ssauth,chal.s,chal.len) == -1) return err_write();
  if (substdio_flush(&ssauth) == -1) return err_write();

  close(pi[1]);
  if (!stralloc_copys(&chal,"")) die_nomem();
  if (!stralloc_copys(&slop,"")) die_nomem();
  byte_zero(ssauthbuf,sizeof(ssauthbuf));
  if (wait_pid(&wstat,child) == -1) return err_child();
  if (wait_crashed(wstat)) return err_child();
  if (wait_exitcode(wstat)) { sleep(AUTHSLEEP); return 1; } /* no */
  return 0; /* yes */
}

int auth_login(char *arg)
{
  int r;

  if (*arg) {
    if ((r = b64decode((unsigned char *)arg,str_len(arg),&user)) == 1) return err_authinput();
  }
  else {
    out("334 VXNlcm5hbWU6\r\n"); flush();       /* Username: */
    if (authgetl() < 0) return -1;
    if ((r = b64decode((unsigned char *)authin.s,authin.len,&user)) == 1) return err_authinput();
  }
  if (r == -1) die_nomem();

  out("334 UGFzc3dvcmQ6\r\n"); flush();         /* Password: */

  if (authgetl() < 0) return -1;
  if ((r = b64decode((unsigned char *)authin.s,authin.len,&pass)) == 1) return err_authinput();
  if (r == -1) die_nomem();

  if (!user.len || !pass.len) return err_authinput();
  return authenticate();
}

int auth_plain(char *arg)
{
  int r, id = 0;

  if (*arg) {
    if ((r = b64decode((unsigned char *)arg,str_len(arg),&resp)) == 1) return err_authinput();
  }
  else {
    out("334 \r\n"); flush();
    if (authgetl() < 0) return -1;
    if ((r = b64decode((unsigned char *)authin.s,authin.len,&resp)) == 1) return err_authinput();
  }
  if (r == -1 || !stralloc_0(&resp)) die_nomem();
  while (resp.s[id]) id++;                       /* "authorize-id\0userid\0passwd\0" */

  if (resp.len > id + 1)
    if (!stralloc_copys(&user,resp.s + id + 1)) die_nomem();
  if (resp.len > id + user.len + 2)
    if (!stralloc_copys(&pass,resp.s + id + user.len + 2)) die_nomem();

  if (!user.len || !pass.len) return err_authinput();
  return authenticate();
}

int auth_cram()
{
  int i, r;
  char *s;

  s = unique;           /* generate challenge */
  s += fmt_uint(s,getpid());
  *s++ = '.';
  s += fmt_ulong(s,(unsigned long) now());
  *s++ = '@';
  *s++ = 0;
  if (!stralloc_copys(&chal,"<")) die_nomem();
  if (!stralloc_cats(&chal,unique)) die_nomem();
  if (!stralloc_cats(&chal,local)) die_nomem();
  if (!stralloc_cats(&chal,">")) die_nomem();
  if (b64encode(&chal,&slop) < 0) die_nomem();
  if (!stralloc_0(&slop)) die_nomem();

  out("334 ");                                          /* "334 base64_challenge \r\n" */
  out(slop.s);
  out("\r\n");
  flush();

  if (authgetl() < 0) return -1;                        /* got response */
  if ((r = b64decode((unsigned char *)authin.s,authin.len,&resp)) == 1) return err_authinput();
  if (r == -1 || !stralloc_0(&resp)) die_nomem();

  i = str_rchr(resp.s,' ');
  s = resp.s + i;
  while (*s == ' ') ++s;
  resp.s[i] = 0;
  if (!stralloc_copys(&user,resp.s)) die_nomem();       /* userid */
  if (!stralloc_copys(&pass,s)) die_nomem();      /* digest */

  if (!user.len || !pass.len) return err_authinput();
  return authenticate();
}

struct authcmd {
  char *text;
  int (*fun)();
} authcmds[] = {
  { "login", auth_login }
, { "plain", auth_plain }
, { "cram-md5", auth_cram }
, { 0, err_noauth }
};

void smtp_auth(char *arg)
{
  int i;
  char *cmd = arg;

  if (!smtpauth || !*childargs) { out("503 auth not available (#5.3.3)\r\n"); return; }
  if (seenauth) { err_authd(); return; }
  if (seenmail) { err_authmail(); return; }

  if (!stralloc_copys(&user,"")) die_nomem();
  if (!stralloc_copys(&pass,"")) die_nomem();
  if (!stralloc_copys(&resp,"")) die_nomem();
  if (!stralloc_copys(&chal,"")) die_nomem();   /* only needed for CRAM-MD5 */

  i = str_chr(cmd,' ');         /* get AUTH type */
  arg = cmd + i;
  while (*arg == ' ') ++arg;
  cmd[i] = 0;

  for (i = 0; authcmds[i].text; ++i)
    if (case_equals(authcmds[i].text,cmd)) break;
  if (!stralloc_copys(&authmethod,authcmds[i].text)) die_nomem();
  if (!stralloc_0(&authmethod)) die_nomem();

  if ((smtpauth == 2 || smtpauth == 12) && i < 2) {
    if (!stralloc_append(&protocol,"A")) die_nomem();
    if (!stralloc_0(&protocol)) die_nomem();
    err_authfail("Reject::AUTH::",protocol.s,remoteip,remotehost,helohost.s,"none","Auth_Meth");
    return;
  }

  switch (authcmds[i].fun(arg)) {
    case 0:
// qmail-spp: (1 line)
#ifdef SPP
if (!spp_auth(authcmds[i].text, user.s)) return;
#endif
      seenauth = 1;
      relayclient = "";
      remoteinfo = user.s;
      auth_info(authmethod.s);
      out("235 ok, go ahead (#2.0.0)\r\n");
      break;
    case 1:
      if (!stralloc_append(&protocol,"A")) die_nomem();
      if (!stralloc_0(&protocol)) die_nomem();
      err_authfail("Reject::AUTH::",protocol.s,remoteip,remotehost,helohost.s,user.s,authmethod.s);
      return;
  }
}

/* this file is too long --------------------------------- GO ON */

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "auth", smtp_auth, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { "starttls", smtp_starttls, flush }
, { 0, err_unimpl, flush }
} ;

int main(int argc, char **argv)
{
  childargs = argv + 1;
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  smtpdlog_init();
  if (ipme_init() != 1) die_ipme();
#ifdef SPP
  if (spp_connect()) {
#endif
  smtp_greet("220 ");
  out(" ESMTP\r\n");
#ifdef SPP
  }
#endif
  if (commands(&ssin,&smtpcommands) == 0) die_read();
  die_nomem();

  return 0;
}
