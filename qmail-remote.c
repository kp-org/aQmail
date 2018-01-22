/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
 *  Revision 20171214, Erwin Hoffmann
 *  - changed struct domainip4/domainip6 to char domainip4[4]/domainip6[16]
*/
#ifdef IDN2
#include <idn2.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "scan.h"
#include "case.h"
#include "byte.h"
#include "error.h"
#include "auto_qmail.h"
#include "control.h"
#include "dns.h"
#include "alloc.h"
#include "quote.h"
#include "fmt.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "base64.h"
#include "socket_if.h"
#include "ucspitls.h" 
#include "tls_remote.h"
#include "tls_errors.h"
#include "tls_timeoutio.h"

#define MAX_SIZE 200000000
#define HUGESMTPTEXT 5000
#define PORT_SMTP 25  /* silly rabbit, /etc/services is for users */
#define PORT_QMTP 209 
#define PORT_SMTPS 465
#define PORT_QMTPS 6209
#define VERIFYDEPTH 1

unsigned long port = PORT_SMTP;

/** @file qmail-remote.c -- versatile SMTP(S)/QMTP(S) client */

int flagauth = 0;       /* 1 = login; 2 = plain; 3 = crammd5 */
int flagtlsdomain = 0;  /* 0 = no; 1 = yes; 2 = cert */
int flagtls = 0;        /* -2 = rejected; -1 = not; 0 = no, default; 
                            > 0 see tls_remote.c
                          +10 = SMTPS; +20 = QMTPS; 100 = active TLS connection */
int flagverify = 0;	/* 1 = verify Cert against CA; 2 = verify against Dir; -1 = Cert pinning */ 
int flagutf8 = 0;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc eaihost = {0};
stralloc host = {0};
stralloc idnhost = {0};
stralloc sender = {0};
stralloc canonhost = {0};
stralloc canonbox = {0};
stralloc senddomain = {0};
stralloc sendip = {0};

stralloc domainips = {0};
struct constmap mapdomainips;
//struct ip_address domainip4;
//struct ip6_address domainip6;
unsigned long scope_id;

stralloc smtproutes = {0};
struct constmap mapsmtproutes;
stralloc qmtproutes = {0};
struct constmap mapqmtproutes;

saa reciplist = {0};

struct ip_mx partner;

char domainip4[4];
char domainip6[16];

SSL *ssl;
SSL_CTX *ctx; 

void out(char *s) { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie() {
  zero();
  substdio_flush(subfdoutsmall);
  if (ssl) tls_exit(ssl);
  _exit(0);
}

void outsafe(stralloc *sa) 
{ 
  int i; 
  char ch;
  for (i = 0; i < sa->len; ++i) {
    ch = sa->s[i]; 
    if (ch < 33) ch = '?'; 
    if (ch > 126) ch = '?';
    if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); 
  } 
}

void temp_noip() 
{ 
  out("ZInvalid ipaddr in etc/domainips (#4.3.0)\n"); 
  zerodie(); 
}
void temp_nomem() 
{ 
  out("ZOut of memory. (#4.3.0)\n"); 
  zerodie(); 
}
void temp_oserr() 
{ 
  out("ZSystem resources temporarily unavailable. (#4.3.0)\n"); 
  zerodie(); 
}
void temp_osip() 
{ 
  out("ZCan't bind to local ip address: "); 
  outsafe(&sendip); 
  out(". (#4.3.0)\n");
  zerodie(); 
}
void temp_noconn() 
{ 
  out("ZSorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); 
  zerodie(); 
}
void temp_qmtpnoc() 
{ 
  out("ZSorry, I wasn't able to establish an QMTP connection. (#4.4.1)\n"); 
  zerodie(); 
}
void temp_read() 
{ 
  out("ZUnable to read message. (#4.3.0)\n"); 
  zerodie(); 
}
void temp_dnscanon() 
{ 
  out("ZCNAME lookup failed temporarily for: "); 
  outsafe(&canonhost); 
  out(". (#4.4.3)\n");
  zerodie(); 
}
void temp_dns() 
{  
  out("ZSorry, I couldn't find any host named: "); 
  outsafe(&host); 
  out(". (#4.1.2)\n"); 
  zerodie(); 
}
void temp_chdir() 
{ 
  out("ZUnable to switch to home directory. (#4.3.0)\n"); 
  zerodie(); 
}
void temp_control() 
{ 
  out("ZUnable to read control files. (#4.3.0)\n"); 
  zerodie(); 
}
void perm_partialline() 
{ 
  out("DSMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); 
  zerodie(); 
}
void temp_proto() 
{ 
  out("ZRecipient did not talk proper QMTP (#4.3.0)\n"); 
  zerodie(); 
}
void perm_usage() 
{ 
  out("Dqmail-remote was invoked improperly. (#5.3.5)\n"); 
  zerodie(); 
}
void perm_dns() 
{ 
  out("DSorry, I couldn't find any host named "); 
  outsafe(&host); 
  out(". (#5.1.2)\n"); 
  zerodie(); 
}
void perm_nomx() 
{ 
  out("DSorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n"); 
  zerodie(); 
}
void perm_ambigmx() 
{ 
  out("DSorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my etc/locals file, so I don't treat it as local. (#5.4.6)\n");
  zerodie(); 
}
void err_authprot() 
{
  out("KNo supported AUTH method found, continuing without authentication.\n");
  zero();
  substdio_flush(subfdoutsmall);
}

void outhost()
{
  char ipaddr[IPFMT];
  int len;

  switch(partner.af) {
    case AF_INET:
      len = ip4_fmt(ipaddr,&partner.addr.ip4); break;
    case AF_INET6:
      len = ip6_fmt(ipaddr,&partner.addr.ip6); break;
  } 
  if (substdio_put(subfdoutsmall,ipaddr,len) == -1) _exit(0);
}

int flagcritical = 0;

void dropped() 
{
  out("ZConnected to ");
  outhost();
  out(" but connection died. ");
  if (flagcritical) out("Possible duplicate! ");
  out("(#4.4.2)\n");
  zerodie();
}

int timeoutconnect = 60;
int smtpfd;
int timeout = 1200;

int saferead(int fd,char *buf,int len)
{
  int r;
  if (ssl) {
    r = tls_timeoutread(timeout,smtpfd,smtpfd,ssl,buf,len);
    if (r < 0) temp_tlserr();
  } else {
    r = timeoutread(timeout,smtpfd,buf,len);
  }
  if (r <= 0) dropped();
  return r;
}

int safewrite(int fd,char *buf,int len)
{
  int r;
  if (ssl) {
    r = tls_timeoutwrite(timeout,smtpfd,smtpfd,ssl,buf,len);
    if (r < 0) temp_tlserr();
  } else {
    r = timeoutwrite(timeout,smtpfd,buf,len);
  }
  if (r <= 0) dropped();
  return r;
}

char inbuf[1450];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof(inbuf));
char smtptobuf[1450];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof(smtptobuf));
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof(smtpfrombuf));

stralloc smtptext = {0};
#ifdef SMTPUTF8
stralloc header = {0};
#endif
 
void get(char *ch)
{
  substdio_get(&smtpfrom,ch,1);
  if (*ch != '\r')
    if (smtptext.len < HUGESMTPTEXT)
     if (!stralloc_append(&smtptext,ch)) temp_nomem();
}

unsigned long smtpcode()
{
  unsigned char ch;
  unsigned long code;

  if (!stralloc_copys(&smtptext,"")) temp_nomem();

  get(&ch); code = ch - '0';
  get(&ch); code = code * 10 + (ch - '0');
  get(&ch); code = code * 10 + (ch - '0');
  for (;;) {
    get(&ch);
    if (ch != '-') break;
    while (ch != '\n') get(&ch);
    get(&ch);
    get(&ch);
    get(&ch);
  }
  while (ch != '\n') get(&ch);

  return code;
}

void outsmtptext()
{
  int i; 
  if (smtptext.s) if (smtptext.len) {
    out("Remote host said: ");
    for (i = 0; i < smtptext.len; ++i)
      if (!smtptext.s[i]) smtptext.s[i] = '?';
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(0);
    smtptext.len = 0;
  }
}

void quit(char *prepend,char *append)
{
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
  outsmtptext();
  zerodie();
}

void blast()
{
  int r;
  int i;
  int o;
  char in[4096];
  char out[4096*2+1];
  int sol;

#ifdef SMTPUTF8
  substdio_put(&smtpto,header.s,header.len);
#endif

  for (sol = 1;;) {
    r = substdio_get(&ssin,in,sizeof(in));
    if (r == 0) break;
    if (r == -1) temp_read();

    for (i = o = 0; i < r; ) {
      if (sol && in[i] == '.') {
	out[o++] = '.';
	out[o++] = in[i++];
      }
      sol = 0;
      while (i < r) {
	if (in[i] == '\n') {
	  sol = 1;
	  ++i;
	  out[o++] = '\r';
	  out[o++] = '\n';
	  break;
	}
	out[o++] = in[i++];
      }
    }
    substdio_put(&smtpto,out,o);
  }
 
  if (!sol) perm_partialline();
  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

stralloc recip = {0};

void mailfrom()
{
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">\r\n");
#ifdef SMTPUTF8
  if (flagutf8)
    substdio_puts(&smtpto," SMTPUTF8");
  else if (utf8received())
    substdio_puts(&smtpto," SMTPUTF8");
#endif   
  substdio_flush(&smtpto);
}

/* this file is too long -------------------------------------- client TLS */

stralloc cafile = {0};
stralloc cadir = {0};
stralloc certfile = {0};
stralloc keyfile = {0};
stralloc keypwd = {0};
stralloc ciphers = {0};

char *tlsdestinfo = 0;
char *tlsdomaininfo = 0;

stralloc domaincerts = {0};
struct constmap mapdomaincerts;
stralloc tlsdestinations = {0};
struct constmap maptlsdestinations;
unsigned long verifydepth = VERIFYDEPTH;

void tls_init()
{
  ctx = ssl_client();
  ssl_errstr();
  if (!ctx) temp_tlsctx();

/* Fetch CA infos for dest */

  if (flagverify > 0) 
    if (cafile.len || cadir.len) 
      if (!ssl_ca(ctx,cafile.s,cadir.s,(int) verifydepth)) temp_tlsca();

  if (ciphers.len)
    if (!ssl_ciphers(ctx,ciphers.s)) temp_tlscipher();

/* Prepare for Certificate Request */

  if (flagtlsdomain == 2) 
    switch (tls_certkey(ctx,certfile.s,keyfile.s,keypwd.s)) {
      case  0: break;
      case -1: temp_tlscert();
      case -2: temp_tlskey();
      case -3: temp_tlschk();
    }

/* Set SSL Context */

  ssl = ssl_new(ctx,smtpfd);
  if (!ssl) temp_tlsctx();

/* Setup SSL FDs */
 
  if (!tls_conn(ssl,smtpfd)) temp_tlscon(); 

/* Go on in none-blocking mode */

  if (tls_timeoutconn(timeout,smtpfd,smtpfd,ssl) <= 0)
    temp_tlserr();
}

int starttls_peer()
{
  int i = 0;

  for (i = 0; i < smtptext.len-8; ++i) 
    if (case_startb(smtptext.s+i,8,"STARTTLS")) return 1;

  return 0;
}

void tls_peercheck()
{
  if (flagverify < 0) {
    if (cafile.len) case_lowerb(cafile.s,cafile.len);
    switch(tls_fingerprint(ssl,cafile.s+1,cafile.len-2)) {
      case -1: temp_tlspeercert();
      case -2: temp_tlsdigest();
      case -3: temp_invaliddigest();
      case  1: temp_tlscertfp();
    }
  } else {
    if (!stralloc_0(&host)) temp_nomem();
    switch (tls_checkpeer(ssl,host.s,host.len,flagtls,flagverify)) {
      case -1: temp_tlspeercert();
      case -2: temp_tlspeerverify();
      case -3: temp_tlspeervalid();
    }
  }
  flagtls = 100;
}
  
/* this file is too long -------------------------------------- client auth */

stralloc authsenders = {0};
struct constmap mapauthsenders;

stralloc user = {0};
stralloc pass = {0};
stralloc auth = {0};
stralloc chal = {0};
stralloc slop = {0};
stralloc plain = {0};
stralloc xuser = {0};

char *authsender;

int xtext(stralloc *sa,char *s,int len)
{
  int i;

  if (!stralloc_copys(sa,"")) temp_nomem();

  for (i = 0; i < len; i++) {
    if (s[i] == '=') {
      if (!stralloc_cats(sa,"+3D")) temp_nomem();
    } else if (s[i] == '+') {
        if (!stralloc_cats(sa,"+2B")) temp_nomem();
    } else if ((int) s[i] < 33 || (int) s[i] > 126) {
        if (!stralloc_cats(sa,"+3F")) temp_nomem(); /* ok. not correct */
    } else if (!stralloc_catb(sa,s+i,1)) {
        temp_nomem();
    }
  }

  return sa->len;
}

void mailfrom_xtext()
{
  if (!xtext(&xuser,user.s,user.len)) temp_nomem();
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,"> AUTH=");
  substdio_put(&smtpto,xuser.s,xuser.len);
#ifdef SMTPUTF8
  if (flagutf8)
    substdio_puts(&smtpto," SMTPUTF8");
  else if (utf8received())
    substdio_puts(&smtpto," SMTPUTF8");
#endif
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
}
  
int mailfrom_plain()
{
  substdio_puts(&smtpto,"AUTH PLAIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (AUTH PLAIN)");

  if (!stralloc_cat(&plain,&sender)) temp_nomem(); /* Mail From: <authorize-id> */
  if (!stralloc_0(&plain)) temp_nomem();
  if (!stralloc_cat(&plain,&user)) temp_nomem(); /* user-id */
  if (!stralloc_0(&plain)) temp_nomem();
  if (!stralloc_cat(&plain,&pass)) temp_nomem(); /* password */
  if (b64encode(&plain,&auth)) quit("ZConnected to "," but unable to base64encode (plain)");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  switch (smtpcode()) {
    case 235: mailfrom_xtext(); break;
    case 432: quit("DConnected to "," but password expired"); 
    case 534: quit("ZConnected to "," but authentication mechamism too weak (plain)"); 
    default: quit("ZConnected to "," but authentication was rejected (plain)"); 
  }
  return 0;
}

int mailfrom_login()
{
  substdio_puts(&smtpto,"AUTH LOGIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (AUTH LOGIN)");

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&user,&auth)) quit("ZConnected to "," but unable to base64encode user");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (username)");

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&pass,&auth)) quit("ZConnected to "," but unable to base64encode pass");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  switch (smtpcode()) {
    case 235: mailfrom_xtext(); break;
    case 432: quit("DConnected to "," but password expired"); 
    case 534: quit("ZConnected to "," but authentication mechamism too weak (login)"); 
    default: quit("ZConnected to "," but authentication was rejected (login)"); 
  }
  return 0;
}

int mailfrom_cram()
{
  int j;
  unsigned char digest[16];
  unsigned char digascii[33];
  static char hextab[]="0123456789abcdef";

  substdio_puts(&smtpto,"AUTH CRAM-MD5\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to"," but authentication was rejected (AUTH CRAM-MD5)");

  if (str_chr(smtptext.s+4,' ')) {                      /* Challenge */
    if (!stralloc_copys(&slop,"")) temp_nomem();
    if (!stralloc_copyb(&slop,smtptext.s+4,smtptext.len-5)) temp_nomem();
    if (b64decode(slop.s,slop.len,&chal)) quit("ZConnected to"," but unable to base64decode challenge");
  }

  hmac_md5(chal.s,chal.len,pass.s,pass.len,digest);

  for (j = 0; j < 16; j++) {                             /* HEX => ASCII */
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0x0f];
  }
  digascii[32]=0;

  slop.len = 0;
  if (!stralloc_copys(&slop,"")) temp_nomem();
  if (!stralloc_cat(&slop,&user)) temp_nomem();          /* user-id */
  if (!stralloc_cats(&slop," ")) temp_nomem();
  if (!stralloc_catb(&slop,digascii,32)) temp_nomem();   /* digest */

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&slop,&auth)) quit("ZConnected to"," but unable to base64encode username+digest");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  switch (smtpcode()) {
    case 235: mailfrom_xtext(); break;
    case 432: quit("DConnected to "," but password expired"); 
    case 534: quit("ZConnected to "," but authentication mechamism too weak (cram)"); 
    default: quit("ZConnected to "," but authentication was rejected (cram)"); 
  }
  return 0;
}

void smtp_auth()
{
  int i;

  for (i = 4; i < smtptext.len-5; ++i) {
    if (case_startb(smtptext.s+i,4,"CRAM"))
      if (mailfrom_cram() >= 0) return;
    if (case_startb(smtptext.s+i,5,"LOGIN"))
      if (mailfrom_login() >= 0) return;
    if (case_startb(smtptext.s+i,5,"PLAIN"))
      if (mailfrom_plain() >= 0) return;
  }
  err_authprot();
  mailfrom();
}

/* this file is too long -------------------------------------- smtp client */

unsigned long code;

void smtp_greeting()
{
  substdio_puts(&smtpto,"EHLO ");
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);

  if (smtpcode() != 250) {
    substdio_puts(&smtpto,"HELO ");
    substdio_put(&smtpto,helohost.s,helohost.len);
    substdio_puts(&smtpto,"\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    authsender = 0;
    if (code >= 500) quit("DConnected to"," but my name was rejected");
    if (code != 250) quit("ZConnected to"," but my name was rejected");
  }
}

void smtp_starttls()
{
  substdio_puts(&smtpto,"STARTTLS\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 220) {
    tls_init();
    tls_peercheck();
    smtp_greeting();
  }
  else {
    flagtls = -2;
    quit("ZConnected to"," but STARTTLS was rejected");
  }
}

#ifdef SMTPUTF8
/* this file is too long --------------------------------------- smtp UTF8 */

int utf8string(unsigned char *ch,int len)
{
  int i = 0;
  while (i < len)
    if (ch[i++] > 127) return 1;
  return 0;
}

int utf8received()
{
  int r;
  int i;
  int received = 0;
  char ch;
  stralloc receivedline = {0};

  for (;;) {		 			/* we consider only our own last written header */
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();

    if (ch == '\n') {
      if (!stralloc_append(&header,"\r")) temp_nomem();			/* received.c does not add '\r' */
      if (!stralloc_append(&header,"\n")) temp_nomem();
      if (case_startb(receivedline.s,5,"Date:")) return 0;		/* header to quit asap */
      if (case_startb(receivedline.s,14,"Received: from")) received++;	/* found Received header */
      if (received) {
        if (case_startb(receivedline.s,5,"  by ")) {
          for (i = 6; i < receivedline.len-6; ++i) 
            if (*(receivedline.s+i) == ' ')
              if (case_startb(receivedline.s+i+1,9,"with UTF8")) return 1;
          return 0;
        } 
      }
      if (!stralloc_copys(&receivedline,"")) temp_nomem();
      receivedline.len = 0;
    } else {
      if (!stralloc_append(&header,&ch)) temp_nomem();
      if (!stralloc_catb(&receivedline,&ch,1)) temp_nomem();
    }
  }
  return 0;
}
#endif

/* this file is too long ------------------------------------------- GO ON */

void smtp()
{
  int flagbother;
  int i;

  if (flagtls > 10 && flagtls < 20) {          /* SMTPS */
    tls_init();
    tls_peercheck(); 
  }

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code == 421 || code == 450) quit("ZConnected to "," but greylisted"); /* RFC 6647 */
  if (code >= 400) return;                      /* try next MX */
  if (code != 220) quit("ZConnected to "," but greeting failed");

  smtp_greeting();

  if (flagtls > 0 && flagtls < 10) {             /* STARTTLS */
    if (starttls_peer()) 
       smtp_starttls();
    else if (flagtls > 2)
       temp_tlshost();
  }

  if (user.len && pass.len)			/* AUTH */
    smtp_auth();
  else 
    mailfrom();

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was greylisted");
 
  flagbother = 0;
  for (i = 0; i < reciplist.len; ++i) {
    substdio_puts(&smtpto,"RCPT TO:<");
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_puts(&smtpto,">\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    if (code >= 500) {
      out("h"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else if (code == 421 || code == 450) {
      out("s"); outhost(); out(" probably greylisting.\n");
      outsmtptext(); zero();
    }
    else if (code >= 400) {
      out("s"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else {
      out("r"); zero();
      flagbother = 1;
    }
  }
  if (!flagbother) quit("DGiving up on ","");
 
  substdio_putsflush(&smtpto,"DATA\r\n");
  code = smtpcode();
  if (code >= 500) quit("D"," failed on DATA command");
  if (code == 451) quit("Z"," message was greylisted");
  if (code >= 400) quit("Z"," failed on DATA command");
 
  blast();
  code = smtpcode();
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
  if (flagtls == 100) quit("K"," TLS transmitted message accepted");
  else quit("K"," accepted message");
}

/* this file is too long -------------------------------------- qmtp client */

int qmtpsend = 0;

void qmtp()
{
  struct stat st;
  unsigned long len;
  char *x;
  int i;
  int n;
  unsigned char ch;
  char num[FMT_ULONG];
  int flagallok;

  if (qmtpsend == 2) {          /* QMTPS */
    tls_init();
    tls_peercheck();
  }

  if (fstat(0,&st) == -1) quit("Z", " unable to fstat stdin");
  len = st.st_size;

/* the following code was substantially taken from serialmail's serialqmtp.c */

  substdio_put(&smtpto,num,fmt_ulong(num,len+1));
  substdio_put(&smtpto,":\n",2);
  while (len > 0) {
    n = substdio_feed(&ssin);
    if (n <= 0) _exit(32); /* wise guy again */
    x = substdio_PEEK(&ssin);
    substdio_put(&smtpto,x,n);
    substdio_SEEK(&ssin,n);
    len -= n;
  }
  substdio_put(&smtpto,",",1);

  len = sender.len;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_put(&smtpto,",",1);

  len = 0;
  for (i = 0; i < reciplist.len; ++i)
    len += fmt_ulong(num,reciplist.sa[i].len)+1+reciplist.sa[i].len+1;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  for (i = 0; i < reciplist.len; ++i) {
    substdio_put(&smtpto,num,fmt_ulong(num,reciplist.sa[i].len));
    substdio_put(&smtpto,":",1);
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_put(&smtpto,",",1);
  }
  substdio_put(&smtpto,",",1);
  substdio_flush(&smtpto);

  flagallok = 1;

  for (i = 0; i < reciplist.len; ++i) {
    len = 0;
    for (;;) {
      get(&ch);
      if (ch == ':') break;
      if (len > 200000000) temp_proto();
      if (ch - '0' > 9) temp_proto();
      len = 10 * len + (ch - '0');
    }
    if (!len) temp_proto();
    get(&ch); --len;
    if ((ch != 'Z') && (ch != 'D') && (ch != 'K')) temp_proto();

    if (!stralloc_copyb(&smtptext,&ch,1)) temp_proto();
    if (flagtls == 100) {
      if (!stralloc_cats(&smtptext,"qmtps:")) temp_nomem();
    } else {
      if (!stralloc_cats(&smtptext,"qmtp:")) temp_nomem();
    }

    while (len > 0) {
      get(&ch);
      --len;
    }

    for (len = 0; len < smtptext.len; ++len) {
      ch = smtptext.s[len];
      if ((ch < 32) || (ch > 126)) smtptext.s[len] = '?';
    }
    get(&ch);
    if (ch != ',') temp_proto();
    smtptext.s[smtptext.len-1] = '\n';

    if (smtptext.s[0] == 'K') out("r");
    else if (smtptext.s[0] == 'D') {
      out("h");
      flagallok = 0;
    }
    else { /* if (smtptext.s[0] == 'Z') */
      out("s");
      flagallok = 0;
    }
    if (substdio_put(subfdoutsmall,smtptext.s+1,smtptext.len-1) == -1) temp_qmtpnoc();
    zero();
  }
  if (!flagallok) {
    out("DGiving up on "); outhost(); out("\n");
  } else {
    out("KAll received okay by "); outhost(); out("\n");
  }
  zerodie();
}

/* this file is too long -------------------------------------- common */

void addrmangle(stralloc *saout,char *address,int *flagalias,int flagcname) 	/* host has to be canonical, box has to be quoted */
{
  int at;

  *flagalias = flagcname;
#ifdef SMTPUTF8
  flagutf8 = utf8string(address,str_len(address));
#endif

  at = str_rchr(address,'@');
  if (!address[at]) {
    if (!stralloc_copys(saout,address)) temp_nomem();
    return;
  }

  if (!stralloc_copys(&canonbox,address)) temp_nomem();
  canonbox.len = at;
  if (!quote(saout,&canonbox)) temp_nomem();
  if (!stralloc_cats(saout,"@")) temp_nomem();

  if (!stralloc_copys(&canonhost,address+at+1)) temp_nomem();
  if (flagcname)
    switch(dns_cname(&canonhost)) {
      case 0: *flagalias = 0; break;
      case DNS_MEM: temp_nomem();
      case DNS_SOFT: temp_dnscanon();
      case DNS_HARD: ; /* alias loop, not our problem */
    }

  if (!stralloc_cat(saout,&canonhost)) temp_nomem();
}

void getcontrols()
{
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"etc/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"etc/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"etc/helohost",1,(char *) 0) != 1)
    temp_control();
  switch(control_readfile(&smtproutes,"etc/smtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapsmtproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapsmtproutes,smtproutes.s,smtproutes.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&domainips,"etc/domainips",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapdomainips,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapdomainips,domainips.s,domainips.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&authsenders,"etc/authsenders",0)) {
    case -1:
       temp_control();
    case 0:
      if (!constmap_init(&mapauthsenders,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapauthsenders,authsenders.s,authsenders.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&qmtproutes,"etc/qmtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapqmtproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapqmtproutes,qmtproutes.s,qmtproutes.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&domaincerts,"etc/domaincerts",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapdomaincerts,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapdomaincerts,domaincerts.s,domaincerts.len,1)) temp_nomem(); break;
  }
  switch(control_readfile(&tlsdestinations,"etc/tlsdestinations",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maptlsdestinations,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maptlsdestinations,tlsdestinations.s,tlsdestinations.len,1)) temp_nomem(); break;
  }
}

int main(int argc,char **argv)
{
  static ipalloc ip = {0};
  stralloc netif = {0};
  int i, j, k; 
  int p; /* reserverd for port */
  unsigned long random;
  char **recips;
  unsigned long prefme;
  int flagallaliases;
  int flagalias;
  char *relayhost;
  char *asciihost = 0;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
  char *localip;
  int flaglocalip6 = 0;

  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();

  authsender = 0;
  relayhost = 0;

  addrmangle(&sender,argv[2],&flagalias,0);

  if (sender.len > 1) {
    i = str_chr(sender.s,'@'); 
    if (sender.s[i] == '@')
      if (!stralloc_copyb(&senddomain,sender.s+i+1,sender.len-i-1)) temp_nomem();
  }

/* this file is too long -------------------------------------- set domain ip + helohost  */

  localip = 0;
     
  for (i = 0; i <= senddomain.len; ++i)
    if ((i == 0) || (i == senddomain.len) || (senddomain.s[i] == '.')) 
      if (localip = constmap(&mapdomainips,senddomain.s+i,senddomain.len-i)) 
        break;

  if (!localip)
    localip = constmap(&mapdomainips,"*",1);                    /* one for all */

  if (localip) {
    j = str_chr(localip,'%'); 
    if (localip[j] != '%') j = 0;
    k = str_chr(localip+j,'|'); 
    if (localip[j+k] != '|') k = 0;
    if (k) {                                                    /* helohost */
      if (!stralloc_copys(&helohost,localip+j+k+1)) temp_nomem();
      if (!stralloc_0(&helohost)) temp_nomem();
      localip[j+k] = 0;
    }
    if (j) {                                                    /* if index */
      localip[j] = 0;
      if (!stralloc_copys(&netif,localip+j+1)) temp_nomem();
      if (!stralloc_0(&netif)) temp_nomem();
    }
  }

/* this file is too long -------------------------------------- authsender routes */

  for (i = 0; i <= sender.len; ++i)
    if ((i == 0) || (i == sender.len) || (sender.s[i] == '.') || (sender.s[i] == '@'))
      if (authsender = constmap(&mapauthsenders,sender.s+i,sender.len-i))
        break;

  if (authsender && !*authsender) authsender = 0;

  if (authsender) {
    i = str_chr(authsender,'|');
    if (authsender[i] == '|') {
      j = str_chr(authsender+i+1,'|');
      if (authsender[i+j+1] == '|') {
        authsender[i] = 0;
        authsender[i+j+1] = 0;
        if (!stralloc_copys(&user,"")) temp_nomem();
        if (!stralloc_copys(&user,authsender+i+1)) temp_nomem();
        if (!stralloc_copys(&pass,"")) temp_nomem();
        if (!stralloc_copys(&pass,authsender+i+j+2)) temp_nomem();
      }
    }
    p = str_chr(authsender,';');
    if (authsender[p] == ';') {
      scan_ulong(authsender+p+1,&port);
      authsender[p] = 0;
    }
    if (!stralloc_copys(&relayhost,authsender)) temp_nomem();
    if (!stralloc_copys(&host,authsender)) temp_nomem();
  }

/* this file is too long -------------------------------------- standard routes */

  if (!authsender) {
    if (sender.len == 0) {                       		 /* bounce routes */
      if (relayhost = constmap(&mapqmtproutes,"!@",2)) {
         qmtpsend = 1; port = PORT_QMTP;
      } else
         relayhost = constmap(&mapsmtproutes,"!@",2);
    }

    if (relayhost && !*relayhost) relayhost = 0;

    if (!relayhost) {
      for (i = 0; i <= host.len; ++i) {				/* qmtproutes */
        if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
          if (relayhost = constmap(&mapqmtproutes,host.s+i,host.len-i)) {
            qmtpsend = 1; port = PORT_QMTP;
            break;
          }							/* default smtproutes */
          else if (relayhost = constmap(&mapsmtproutes,host.s+i,host.len-i))
            break;
      }
    }

    if (relayhost && !*relayhost) relayhost = 0;

    if (relayhost) {				/* default smtproutes -- authenticated */
      i = str_chr(relayhost,'|');
      if (relayhost[i]) {
        j = str_chr(relayhost+i+1,'|');
        if (relayhost[j]) {
          relayhost[i] = 0;
          relayhost[i+j+1] = 0;
          if (!stralloc_copys(&user,"")) temp_nomem();
          if (!stralloc_copys(&user,relayhost+i+1)) temp_nomem();
          if (!stralloc_copys(&pass,"")) temp_nomem();
          if (!stralloc_copys(&pass,relayhost+i+j+2)) temp_nomem();
        }
      }
      p = str_chr(relayhost,';');
      if (relayhost[p]) {
        scan_ulong(relayhost+p+1,&port);
        if (qmtpsend && port == PORT_QMTPS) qmtpsend = 2;
        relayhost[p] = 0;
      }
      if (!stralloc_copys(&host,relayhost)) temp_nomem();
#ifdef IDN2
    } else {
      if (!stralloc_0(&host)) temp_nomem();
      switch (idn2_lookup_u8(host.s,(uint8_t**)&asciihost,IDN2_NFC_INPUT)) {
        case IDN2_OK:     break;
        case IDN2_MALLOC: temp_nomem();
        default:          perm_dns();
      }
      if (!stralloc_copys(&idnhost,asciihost)) temp_nomem();
      if (!stralloc_0(&idnhost)) temp_nomem();
#endif
    }
  }

/* this file is too long -------------------------------------- TLS destinations */

  flagtls = tls_destination(host.s,host.len);

  if (flagtls > 0) {
    if (tlsdestinfo) { 
      i = str_chr(tlsdestinfo,'|');	         /* ca file or cert fingerprint */
      if (tlsdestinfo[i] == '|') {
        tlsdestinfo[i] = 0;
        j = str_chr(tlsdestinfo+i+1,'|');        /* cipher */
        if (tlsdestinfo[i+j+1] == '|') {
          tlsdestinfo[i+j+1] = 0; 
          k = str_chr(tlsdestinfo+i+j+2,'|');	 /* cone domain */
          if (tlsdestinfo[i+j+k+2] == '|') {
            tlsdestinfo[i+j+k+2] = 0; 
            if (str_diffn(tlsdestinfo[i+j+k+3],canonhost.s,canonhost.len)) flagtls = 0;
          }
          p = str_chr(tlsdestinfo+i+j+2,';');	 /* verifydepth;port */
          if (tlsdestinfo[i+j+p+2] == ';') {
            tlsdestinfo[i+j+p+2] = 0;
            if (p > 0) scan_ulong(tlsdestinfo+i+j+2,&verifydepth);
            scan_ulong(tlsdestinfo+i+j+p+3,&port);
          }
        }
        if (!stralloc_copys(&ciphers,tlsdestinfo+i+1)) temp_nomem();
      } 
      if (!stralloc_copys(&cafile,tlsdestinfo)) temp_nomem();
    }

/*  cafile starts with '=' => it is a fingerprint
    cafile ends with '/'  => consider it as cadir */

    if (cafile.len) {
      flagverify = 1;
      if (cafile.s[cafile.len] == '/') {
        cafile.len = 0;
        flagverify = 2;
        if (!stralloc_copys(&cadir,tlsdestinfo)) temp_nomem();
        if (!stralloc_0(&cadir)) temp_nomem();
      } else {
        if (cafile.s[0] == '=') flagverify = -1;
        if (!stralloc_0(&cafile)) temp_nomem(); 
      }
    } else 
      cafile.len = cadir.len = ciphers.len = p = 0;

/* Fetch port if not already done and check for SMTPS */

    if (i == 0) {
      cafile.len = 0;
      p = str_rchr(tlsdestinfo,';');
      if (tlsdestinfo[p] == ';') 
        scan_ulong(tlsdestinfo+p+1,&port);
    }

    if (port == PORT_SMTPS) flagtls = flagtls + 10;
    if (port == PORT_QMTPS) flagtls = flagtls + 20;
  }

  if (!flagtls && qmtpsend == 2) flagtls = 20;	/* QMTPS */

/* this file is too long -------------------------------------- Our Certs - per senddomain */

  if (flagtls > 0) {
    flagtlsdomain = tls_domaincerts(senddomain.s,senddomain.len);

    if (flagtlsdomain) {
      i = str_chr(tlsdomaininfo,'|');
      if (tlsdomaininfo[i]) {
        tlsdomaininfo[i] = 0;
        j = str_chr(tlsdomaininfo + i + 1,'|');
        if (tlsdomaininfo[i + j + 1]) {
          tlsdomaininfo[i + j + 1] = 0;
          if (!stralloc_copys(&keypwd,"")) temp_nomem();
          if (!stralloc_copys(&keypwd,tlsdomaininfo+i+j+2)) temp_nomem();
          if (!stralloc_0(&keypwd)) temp_nomem();
        }
        if (!stralloc_copys(&keyfile,tlsdomaininfo+i+1)) temp_nomem();
        if (!stralloc_0(&keyfile)) temp_nomem();
      }
      if (!stralloc_copys(&certfile,tlsdomaininfo)) temp_nomem();
      if (!stralloc_0(&certfile)) temp_nomem();
      flagtlsdomain = 2;
    }
  }

/* this file is too long -------------------------------------- work thru reciplist */

  if (!saa_readyplus(&reciplist,0)) temp_nomem();
  if (ipme_init() != 1) temp_oserr();
 
  flagallaliases = 1;
  recips = argv + 3;

  while (*recips) {
    if (!saa_readyplus(&reciplist,1)) temp_nomem();
    reciplist.sa[reciplist.len] = sauninit;
    addrmangle(reciplist.sa + reciplist.len,*recips,&flagalias,!relayhost);
    ++reciplist.len;
    ++recips;
  }

  random = now() + (getpid() << 16);
#ifdef IDN2
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&idnhost,random)) {
#else
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&host,random)) {
#endif
    case DNS_MEM: temp_nomem();
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }
 
  if (ip.len <= 0) perm_nomx();
 
  prefme = 100000;
  for (i = 0; i < ip.len; ++i)
    if (ipme_is(&ip.ix[i]))
      if (ip.ix[i].pref < prefme)
        prefme = ip.ix[i].pref;
 
  if (relayhost) prefme = 300000;
  if (flagallaliases) prefme = 500000;
 
  for (i = 0; i < ip.len; ++i)
    if (ip.ix[i].pref < prefme)
      break;
 
  if (i >= ip.len)
    perm_ambigmx();
  
  for (i = 0; i < ip.len; ++i) {
    if (ip.ix[i].pref < prefme) {
      if (tcpto(&ip.ix[i])) continue;
 
      smtpfd = socket(ip.ix[i].af,SOCK_STREAM,0);
      if (smtpfd == -1) temp_oserr();

      if (localip) {							/* set domain ip */
        if (!stralloc_copyb(&sendip,localip,str_len(localip))) temp_nomem();
         j = str_chr(localip,':');
         if (j && localip[j] == ':') flaglocalip6 = 1;

         if (flaglocalip6 && ip.ix[i].af == AF_INET6) {
           if (!ip6_scan(domainip6,localip)) temp_noip();		/* IPv6 */

           byte_zero((char *)&s6,sizeof(s6));
           s6.sin6_family = AF_INET6;
           s6.sin6_port = 0;
           if (netif.len > 1) 						 /* required for LLU address */
             s6.sin6_scope_id = socket_getifidx(netif.s);

           byte_copy((char *)&s6.sin6_addr,16,(char *)&domainip6);
           if (bind(smtpfd,(struct sockaddr *)&s6,sizeof(s6)) < 0) temp_osip();
         }
         if (!flaglocalip6 && ip.ix[i].af == AF_INET) {
           if (!ip4_scan(domainip4,localip)) temp_noip();		/* IPv4 */
   
           byte_zero((char *)&s4,sizeof(s4));
           s4.sin_family = AF_INET;
           s4.sin_port = 0;

           byte_copy((char *)&s4.sin_addr,4,(char *)&domainip4);
           if (bind(smtpfd,(struct sockaddr *)&s4,sizeof(s4)) < 0) temp_osip();
         }
      } 

      if (timeoutconn(smtpfd,&ip.ix[i],(unsigned int) port,timeoutconnect) == 0) { 
        tcpto_err(&ip.ix[i],0);
        partner = ip.ix[i];
        if (qmtpsend) 
          qmtp(); 
        else  
          smtp(); /* read qmail/THOUGHTS; section 6 */
      }
      tcpto_err(&ip.ix[i],errno == ETIMEDOUT || errno == ECONNREFUSED);
      close(smtpfd);
    }
  }
  temp_noconn();
}
