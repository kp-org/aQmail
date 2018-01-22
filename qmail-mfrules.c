/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
*/
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "getln.h"
#include "error.h"
#include "exit.h"
#include "readwrite.h"
#include "open.h"
#include "auto_qmail.h"
#include "cdbmake.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"

#define MFFATAL "qmail-mfrules: fatal: "

stralloc address = {0};
stralloc data = {0};
stralloc key = {0};
stralloc line = {0};

char inbuf[1024];
substdio ssin;

int fd;
int fdtemp;
int match = 1;

//struct cdbmss cdbmss;
struct cdb_make c;

void die_nomem()
{
  strerr_die2x(112,MFFATAL,"out of memory");
}
void die_parse()
{
  if (!stralloc_0(&line)) die_nomem();
  strerr_die3x(100,MFFATAL,"unable to parse this line: ",line.s);
}
void die_read()
{
  strerr_die2sys(111,MFFATAL,"unable to read etc/mailfromrules: ");
}
void die_write()
{
  strerr_die2sys(111,MFFATAL,"unable to write to etc/mailfromrules.tmp: ");
}

char strnum[FMT_ULONG];
stralloc sanum = {0};

void getnum(char *buf,int len,unsigned long *u)
{
  if (!stralloc_copyb(&sanum,buf,len)) die_nomem();
  if (!stralloc_0(&sanum)) die_nomem();
  if (sanum.s[scan_ulong(sanum.s,u)]) die_parse();
}

void doaddressdata()
{
  int i;
  int left;
  int right;
  unsigned long bot;
  unsigned long top;

  if (byte_chr(address.s,address.len,'=') == address.len)
    if (byte_chr(address.s,address.len,'@') == address.len) {
      i = byte_chr(address.s,address.len,'-');
      if (i < address.len) {
        left = byte_rchr(address.s,i,'.');
        if (left == i) left = 0; else ++left;

        ++i;
        right = i + byte_chr(address.s + i,address.len - i,'.');

        getnum(address.s + left,i - 1 - left,&bot);
        getnum(address.s + i,right - i,&top);
        if (top > 255) top = 255;

        while (bot <= top) {
      if (!stralloc_copyb(&key,address.s,left)) die_nomem();
      if (!stralloc_catb(&key,strnum,fmt_ulong(strnum,bot))) die_nomem();
      if (!stralloc_catb(&key,address.s + right,address.len - right)) die_nomem();
          case_lowerb(key.s,key.len);
//          if (cdbmss_add(&cdbmss,key.s,key.len,data.s,data.len) == -1) die_write();
          if (cdb_make_add(&c,key.s,key.len,data.s,data.len) == -1) die_write();
      ++bot;
        }

        return;
      }
    }

  case_lowerb(address.s,address.len);
  case_lowerb(data.s,data.len);
//  if (cdbmss_add(&cdbmss,address.s,address.len,data.s,data.len) == -1) die_write();
  if (cdb_make_add(&c,address.s,address.len,data.s,data.len) == -1) die_write();
}

int main()
{
  int amper;
  int colon;
  int dot;
  int i;
  int len;
  char *x;
  char ch;

  umask(033);
  if (chdir(auto_qmail) == -1)
    strerr_die4sys(111,MFFATAL,"unable to chdir to ",auto_qmail,": ");

  fd = open_read("etc/mailfromrules");
  if (fd == -1) die_read();

  substdio_fdbuf(&ssin,read,fd,inbuf,sizeof(inbuf));

  fdtemp = open_trunc("etc/mailfromrules.tmp");
  if (fdtemp == -1) die_write();

//  if (cdbmss_start(&cdbmss,fdtemp) == -1) die_write();
  if (cdb_make_start(&c,fdtemp) == -1) die_write();

  while (match) {
    if (getln(&ssin,&line,&match,'\n') != 0) die_read();

    x = line.s; len = line.len;

    if (!len) break;
    if (x[0] == '#') continue;
    if (x[0] == '\n') continue;

    while (len) {
      ch = x[len - 1];
      if (ch != '\n') if (ch != ' ') if (ch != '\t') break;
      --len;
    }
    line.len = len; /* for die_parse() */

    amper = byte_chr(x,len,'&');
    if (!amper) die_parse();
    if (amper) if (amper == len || amper <  2) die_parse();

    if (!stralloc_copyb(&address,x,amper)) die_nomem();
    if (!stralloc_copys(&data,"")) die_nomem();

    x = line.s + amper + 1; len = line.len - amper - 1;

    while (len) {
      if (len < 3) die_parse();					/* input checks */
      if ( *x == ',' || *x == ' ' || *x == '\t') die_parse();
      i = byte_chr(x,len,',');					/* &addr1,addr2,.. */
      if (i > 0 && i < len) {
        if (!stralloc_catb(&data,"+",1)) die_nomem();
        if (!stralloc_catb(&data,x,i)) die_nomem(); 
        x += i + 1; len -= i + 1; }
      else {
        if (!stralloc_catb(&data,"+",1)) die_nomem();
        if (!stralloc_catb(&data,x,len)) die_nomem(); 
        len = 0; }
    }
    doaddressdata();
  }

//  if (cdbmss_finish(&cdbmss) == -1) die_write();
  if (cdb_make_finish(&c) == -1) die_write();
  if (fsync(fdtemp) == -1) die_write();
  if (close(fdtemp) == -1) die_write(); /* NFS stupidity */
  if (rename("etc/mailfromrules.tmp","etc/mailfromrules.cdb") == -1)
    strerr_die2sys(111,MFFATAL,"unable to move etc/mailfromrules.tmp to etc/mailfromrules.cdb");

  _exit(0);
}
