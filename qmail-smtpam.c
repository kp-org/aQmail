/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
 *  Revision 20171214, Erwin Hoffmann
 *  - changed struct domainip4/domainip6 to char domainip4[4]/domainip[16]
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "socket_if.h"
#include "ucspitls.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "tls_remote.h"
#include "tls_errors.h"
#include "tls_timeoutio.h"

#define MAX_SIZE 200000000
#define HUGESMTPTEXT 5000
#define PORT_SMTP 25 /* silly rabbit, /etc/services is for users */
#define PORT_SMTPS 465
#define VERIFYDEPTH 1

/** @file qmail-smtpam.c -- TLS enabled SMTP PAM to check mailbox at remote MX
  */

int flagauth = 0;       /* 1 = login; 2 = plain; 3 =crammd5 */
int flagtls = 0;        /* -2 = rejected; -1 = not; 0 = no, default; 
                            > 0 see tls_remote.c
                          +10 = SMTPS; +20 = QMTPS; 100 = active TLS connection */
int flagverify = 0;     /* 1 = verify Cert against CA ; -1 = Cert pinning */
int flagutf8mail = 0;

unsigned long port = PORT_SMTP;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)


stralloc helohost = {0};
stralloc host = {0};
stralloc sender = {0};
stralloc canonhost = {0};
stralloc canonbox = {0};
stralloc senddomain = {0};
stralloc sendip = {0};
stralloc recipient = {0};

stralloc domainips = {0};
struct constmap mapdomainips;
//struct ip_address domainip4;
//struct ip6_address domainip6;
unsigned long scope_id;

stralloc routes = {0};
struct constmap maproutes;

struct ip_mx partner;

char domainip4[4];
char domainip6[16];

SSL *ssl;
SSL_CTX *ctx;

void out(char *s) { if (substdio_puts(subfdoutsmall,s) == -1) _exit(111); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(111); }
void zerodie() { zero(); substdio_flush(subfdoutsmall); _exit(111); }
void outsafe(stralloc *sa) 
{ 
  int i; 
  char ch;
  for (i = 0; i < sa->len; ++i) {
    ch = sa->s[i]; 
    if (ch < 33) ch = '?'; 
    if (ch > 126) ch = '?';
    if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(111); 
  } 
}

void temp_noip() 
{
  out("Zinvalid ipaddr in etc/domainips (#4.3.0)\n");
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
void perm_usage() 
{
  out("Dqmail-smtpam was invoked improperly. (#5.3.5)\n");
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
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

int safewrite(int fd,char *buf,int len)
{
  int r;
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

char inbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof(inbuf));
char smtptobuf[1024];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof(smtptobuf));
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof(smtpfrombuf));

stralloc smtptext = {0};

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
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(111);
    smtptext.len = 0;
  }
}

void quit(char *prepend,char *append)
{
  substdio_putsflush(&smtpto,"QUIT\r\n");
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
  outsmtptext();
  zerodie();
}

stralloc recip = {0};

/* this file is too long -------------------------------------- client TLS */

stralloc cafile = {0};
stralloc cadir = {0};
stralloc certfile = {0};
stralloc keyfile = {0};
stralloc keypwd = {0};
stralloc ciphers = {0};
stralloc tlsdest = {0};

char *tlsdestinfo = 0;
char *tlsdomaininfo = 0;

stralloc domaincerts = {0};
struct constmap mapdomaincerts;
stralloc tlsdestinations = {0};
struct constmap maptlsdestinations;
unsigned long verifydepth = VERIFYDEPTH;

void tls_init()
{
/* Client CTX */

  ctx = ssl_client();
  ssl_errstr();
  if (!ctx) temp_tlsctx();

/* Fetch CA infos for dest */

  if (flagverify > 0)
    if (cafile.len || cadir.len)
      if (!ssl_ca(ctx,cafile.s,cadir.s,(int) verifydepth)) temp_tlsca();

  if (ciphers.len)
    if (!ssl_ciphers(ctx,ciphers.s)) temp_tlscipher();

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

  while ( (i += str_chr(smtptext.s+i,'\n') + 1) &&
          (i+8 < smtptext.len) ) {
          if (!str_diffn(smtptext.s+i+4,"STARTTLS",8)) return 1; }

  return 0;
}

void tls_peercheck()
{
  if (flagverify < 0) {
    if (cafile.len) case_lowerb(cafile.s,cafile.len);
    switch(tls_fingerprint(ssl,cafile.s+1,cafile.len-1)) {
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

#ifdef SMTPUTF8
int utf8flag(unsigned char *ch,int len)
{
  int i = 0;
  while (i < len)
    if (ch[i++] > 127) return 1;
  return 0;
}
#endif 

/* this file is too long -------------------------------------- SMTP connection */

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
  } else {
    flagtls = -2;
    quit("ZConnected to"," but STARTTLS was rejected");
  }
}

void smtp()
{

  if (flagtls > 10 && flagtls < 20) {          /* SMTPS */
    tls_init();
    tls_peercheck();
  }

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was greylisted");

  smtp_greeting();

#ifdef SMTPUTF8
  if (flagutf8mail) substdio_puts(&smtpto," SMTPUTF8");
#endif

  if (flagtls > 0 && flagtls < 10)              /* STARTTLS */
    if (starttls_peer()) {
       smtp_starttls();
    } else if (flagtls > 2) {
       temp_tlshost();
    }

  substdio_puts(&smtpto,"MAIL FROM:<>");
#ifdef SMTPUTF8
  if (flagutf8mail)
    substdio_puts(&smtpto," SMTPUTF8");
#endif
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");
 
  substdio_puts(&smtpto,"RCPT TO:<");
  substdio_put(&smtpto,recipient.s,recipient.len);
  substdio_puts(&smtpto,">\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  close(smtpfd);
  if (code == 250) _exit(0);
  _exit(1);
}

void getcontrols()
{
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"etc/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"etc/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"etc/helohost",1,(char *) 0) != 1)
    temp_control();
  switch (control_readfile(&domainips,"etc/domainips",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&mapdomainips,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapdomainips,domainips.s,domainips.len,1)) temp_nomem(); break;
  }
}

char up[513];
int uplen;

int main(int argc,char **argv)
{
  static ipalloc ip = {0};
  stralloc netif = {0};
  int i, j, k;
  int r; /* reserved for return code */
  int p; /* reserved for port */
  unsigned long prefme;
  char *localip;
  struct sockaddr_in6 s6;
  struct sockaddr_in s4;
  char *tlsdestinfo = 0;
 
  sig_pipeignore();
  if (argc < 2) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();
  if (argv[2])
    scan_ulong(argv[2],&port);

  if (ipme_init() != 1) temp_oserr();

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
    
    if (k)  {                                                   /* helohost */
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


/* this file is too long -------------------------------------- TLS destinations */

  flagtls = tls_destination(host.s,host.len);

  if (flagtls > 0) {
    if (tlsdestinfo) {
      i = str_chr(tlsdestinfo,'|');              /* ca file or cert fingerprint */
      if (tlsdestinfo[i] == '|') {
        tlsdestinfo[i] = 0;
        j = str_chr(tlsdestinfo+i+1,'|');        /* cipher */
        if (tlsdestinfo[i+j+1] == '|') {
          tlsdestinfo[i+j+1] = 0;
          k = str_chr(tlsdestinfo+i+j+2,'|');    /* cone domain */
          if (tlsdestinfo[i+j+k+2] == '|') {
            tlsdestinfo[i+j+k+2] = 0;
            if (str_diffn(tlsdestinfo[i+j+k+3],canonhost.s,canonhost.len)) flagtls = 0;
          }
          p = str_chr(tlsdestinfo+i+j+2,';');     /* verifydepth;port */
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

/* cafile starts with '=' => it is a fingerprint
   cafile ends with '/'  => consider it as cadir */

   if (cafile.len) {
      flagverify = 1;
      if (cafile.s[cafile.len] == '/') {
        cafile.len = 0;
        flagverify = 2;
        if (!stralloc_copys(&cadir,tlsdestinfo)) temp_nomem();
        if (!stralloc_0(&cadir)) temp_nomem();
      } else {
        if (cafile.s[0] == '%') flagverify = -1;
        if (!stralloc_0(&cafile)) temp_nomem();
      }
    } else {
      cafile.len = cadir.len = ciphers.len = p = 0;
    }

/* Fetch port if not already done and check for SMTPS */

    if (i == 0) {
      cafile.len = 0;
      p = str_rchr(tlsdestinfo,';');
      if (tlsdestinfo[p] == ';')
        scan_ulong(tlsdestinfo+p+1,&port);
    }

    if (port == PORT_SMTPS) flagtls = flagtls + 10;
  }

/* this file is too long -------------------------------------- Setup connection */

  if (ipme_init() != 1) temp_oserr();

  uplen = 0;
  for (;;) {
    do
      r = read(3,up + uplen,sizeof(up) - uplen);
    while ((r == -1) && (errno == EINTR));
    if (r == -1) _exit(111);
    if (r == 0) break;
    uplen += r;
    if (uplen >= sizeof(up)) _exit(111);
  }
  close(3);

  if (!stralloc_copys(&recipient,up)) temp_nomem();
  if (!stralloc_0(&recipient)) temp_nomem(); 
#ifdef SMTPUTF8
  flagutf8mail = utf8flag(recipient.s,recipient.len);
#endif

  switch (dns_ip(&ip,&host)) {
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

  for (i = 0; i < ip.len; ++i)
    if (ip.ix[i].pref < prefme)
      break;

  if (i >= ip.len)
    perm_ambigmx();

  smtpfd = socket(ip.ix[i].af,SOCK_STREAM,0);
  if (smtpfd == -1) temp_oserr();
   
  if (localip) {                                                  /* set domain ip */
    if (!stralloc_copyb(&sendip,localip,str_len(localip))) temp_nomem();
      j = str_chr(localip,':');

      if (j && localip[j] == ':') {                               /* IPv6 */
        if (!ip6_scan(&domainip6,localip)) temp_noip();

        byte_zero((char *)&s6,sizeof(s6));
        s6.sin6_family = AF_INET6;
        s6.sin6_port = 0;
        if (netif.len > 1) 
          s6.sin6_scope_id = socket_getifidx(netif.s);		 /* required for LLU address */

        byte_copy((char *)&s6.sin6_addr,16,(char *)&domainip6);
        if (bind(smtpfd,(struct sockaddr *)&s6,sizeof(s6)) < 0) temp_osip();
      } else {                                                   /* IPv4 */
        if (!ip4_scan(&domainip4,localip)) temp_noip();

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
    smtp(); /* does not return */
  }
  tcpto_err(&ip.ix[i],errno == ETIMEDOUT);
  close(smtpfd);
  
  temp_noconn();
}
