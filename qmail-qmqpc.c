/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
 *  Revision 20171214, Erwin Hoffmann
 *  - changed stralloc ip4/ip6 to char ip4[4]/ip[16]
 *  - changed netif to scope_id
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "substdio.h"
#include "getln.h"
#include "readwrite.h"
#include "exit.h"
#include "stralloc.h"
#include "readclose.h"
#include "error.h"
#include "str.h"
#include "sig.h"
#include "ip.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "auto_qmail.h"
#include "control.h"
#include "fmt.h"

#define PORT_QMQP 628

void die_success() { _exit(0); }
void die_perm() { _exit(31); }
void nomem() { _exit(51); }
void die_read() { if (errno == ENOMEM) nomem(); _exit(54); }
void die_control() { _exit(55); }
void die_socket() { _exit(56); }
void die_home() { _exit(61); }
void die_temp() { _exit(71); }
void die_conn() { _exit(74); }
void die_format() { _exit(91); }

int lasterror = 55;
int qmqpfd;

int saferead(int fd,char *buf,int len)
{
  int r;
  r = timeoutread(60,qmqpfd,buf,len);
  if (r <= 0) die_conn();
  return r;
}

int safewrite(int fd,char *buf,int len)
{
  int r;
  r = timeoutwrite(60,qmqpfd,buf,len);
  if (r <= 0) die_conn();
  return r;
}

char buf[1024];
substdio to = SUBSTDIO_FDBUF(safewrite,-1,buf,sizeof(buf));
substdio from = SUBSTDIO_FDBUF(saferead,-1,buf,sizeof(buf));
substdio envelope = SUBSTDIO_FDBUF(read,1,buf,sizeof(buf));
/* WARNING: can use only one of these at a time! */

stralloc beforemessage = {0};
stralloc message = {0};
stralloc aftermessage = {0};

char strnum[FMT_ULONG];
stralloc line = {0};

void getmess()
{
  int match;

  if (slurpclose(0,&message,1024) == -1) die_read();

  strnum[fmt_ulong(strnum,(unsigned long) message.len)] = 0;
  if (!stralloc_copys(&beforemessage,strnum)) nomem();
  if (!stralloc_cats(&beforemessage,":")) nomem();
  if (!stralloc_copys(&aftermessage,",")) nomem();

  if (getln(&envelope,&line,&match,'\0') == -1) die_read();
  if (!match) die_format();
  if (line.len < 2) die_format();
  if (line.s[0] != 'F') die_format();

  strnum[fmt_ulong(strnum,(unsigned long) line.len - 2)] = 0;
  if (!stralloc_cats(&aftermessage,strnum)) nomem();
  if (!stralloc_cats(&aftermessage,":")) nomem();
  if (!stralloc_catb(&aftermessage,line.s + 1,line.len - 2)) nomem();
  if (!stralloc_cats(&aftermessage,",")) nomem();

  for (;;) {
    if (getln(&envelope,&line,&match,'\0') == -1) die_read();
    if (!match) die_format();
    if (line.len < 2) break;
    if (line.s[0] != 'T') die_format();

    strnum[fmt_ulong(strnum,(unsigned long) line.len - 2)] = 0;
    if (!stralloc_cats(&aftermessage,strnum)) nomem();
    if (!stralloc_cats(&aftermessage,":")) nomem();
    if (!stralloc_catb(&aftermessage,line.s + 1,line.len - 2)) nomem();
    if (!stralloc_cats(&aftermessage,",")) nomem();
  }
}

void doit(char *server)
{
  char ip4[4];
  char ip6[16];
//  struct ip_address ip4;
//  struct ip6_address ip6;
  char *scope_id = 0;
  char ch;
  int i, j, r;

  i = str_chr(server,':');
  if (i && server[i]) {
    j = str_chr(server,'%');                                   /* if index */
    if (j > 0 && server[j]) {
      server[j] = 0;
      scope_id = &server[j+1];
    } 
    if (!ip6_scan(ip6,server)) return;
    qmqpfd = socket(AF_INET6,SOCK_STREAM,0);
    if (qmqpfd == -1) die_socket();
    r = timeoutconn6(qmqpfd,&ip6,PORT_QMQP,10,scope_id);
  } else {
    if (!ip4_scan(ip4,server)) return;
    qmqpfd = socket(AF_INET,SOCK_STREAM,0);
    if (qmqpfd == -1) die_socket();
    r = timeoutconn(qmqpfd,&ip4,PORT_QMQP,10);
  }
  if (r != 0) {
    lasterror = 73;
    if (errno == ETIMEDOUT) lasterror = 72;
    close(qmqpfd);
    return;
  }

  strnum[fmt_ulong(strnum,(unsigned long) (beforemessage.len + message.len + aftermessage.len))] = 0;
  substdio_puts(&to,strnum);
  substdio_puts(&to,":");
  substdio_put(&to,beforemessage.s,beforemessage.len);
  substdio_put(&to,message.s,message.len);
  substdio_put(&to,aftermessage.s,aftermessage.len);
  substdio_puts(&to,",");
  substdio_flush(&to);

  for (;;) {
    substdio_get(&from,&ch,1);
    if (ch == 'K') die_success();
    if (ch == 'Z') die_temp();
    if (ch == 'D') die_perm();
  }
}

stralloc servers = {0};

int main()
{
  int i;
  int j;

  sig_pipeignore();

  if (chdir(auto_qmail) == -1) die_home();
  if (control_init() == -1) die_control();
  if (control_readfile(&servers,"etc/qmqpservers",0) != 1) die_control();

  getmess();

  i = 0;
  for (j = 0;j < servers.len;++j)
    if (!servers.s[j]) {
      doit(servers.s + i);
      i = j + 1;
    }

  _exit(lasterror);
}
