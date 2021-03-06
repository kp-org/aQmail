#include "substdio.h"
#include "strerr.h"
#include "stralloc.h"
#include "getln.h"
#include "open.h"
#include "readwrite.h"
#include "token822.h"
#include "control.h"
#include "auto_qmail.h"
#include "case.h"
#include "cdbmss.h"

#define FATAL "newaliases: fatal: "

void nomem()
{
  strerr_die2x(111,FATAL,"out of memory");
}
void nulbyte()
{
  strerr_die2x(100,FATAL,"NUL bytes are not permitted");
}
void longaddress()
{
  strerr_die2x(100,FATAL,"addresses over 800 bytes are not permitted");
}
void writeerr()
{
  strerr_die2sys(111,FATAL,"unable to write to /etc/aliases.tmp: ");
}
void readerr()
{
  strerr_die2sys(111,FATAL,"unable to read /etc/aliases: ");
}
void die_control()
{
  strerr_die2sys(111,FATAL,"unable to read controls: ");
}

stralloc me = {0};
stralloc defaulthost = {0};
stralloc defaultdomain = {0};
stralloc plusdomain = {0};

void readcontrols()
{
  int r;
  int fddir;

  fddir = open_read(".");
  if (fddir == -1)
    strerr_die2sys(111,FATAL,"unable to open current directory: ");

  if (chdir(auto_qmail) == -1)
    strerr_die4sys(111,FATAL,"unable to chdir to ",auto_qmail,": ");

  r = control_readline(&me,"control/me");
  if (r == -1) die_control();
  if (!r) if (!stralloc_copys(&me,"me")) nomem();

  r = control_readline(&defaultdomain,"control/defaultdomain");
  if (r == -1) die_control();
  if (!r) if (!stralloc_copy(&defaultdomain,&me)) nomem();

  r = control_readline(&defaulthost,"control/defaulthost");
  if (r == -1) die_control();
  if (!r) if (!stralloc_copy(&defaulthost,&me)) nomem();

  r = control_readline(&plusdomain,"control/plusdomain");
  if (r == -1) die_control();
  if (!r) if (!stralloc_copy(&plusdomain,&me)) nomem();

  if (fchdir(fddir) == -1)
    strerr_die2sys(111,FATAL,"unable to set current directory: ");
}

stralloc target = {0};
stralloc fulltarget = {0};
stralloc instr = {0};

stralloc cbuf = {0};
token822_alloc toks = {0};
token822_alloc tokaddr = {0};
stralloc address = {0};

void gotincl()
{
  token822_reverse(&tokaddr);
  if (token822_unquote(&address,&tokaddr) != 1) nomem();
  tokaddr.len = 0;

  if (!address.len)
    strerr_die2x(111,FATAL,"empty :include: filenames not permitted");
  if (byte_chr(address.s,address.len,'\0') < address.len)
    strerr_die2x(111,FATAL,"NUL not permitted in :include: filenames");

  if ((address.s[0] != '.') && (address.s[0] != '/'))
    if (!stralloc_cats(&instr,"./")) nomem();
  if (!stralloc_cat(&instr,&address)) nomem();
  if (!stralloc_cats(&instr,".bin")) nomem();
  if (!stralloc_0(&instr)) nomem();
}

void gotaddr()
{
  int i;
  int j;
  int flaghasat;
 
  token822_reverse(&tokaddr);
  if (token822_unquote(&address,&tokaddr) != 1) nomem();

  if (!address.len)
    strerr_die2x(111,FATAL,"empty recipient addresses not permitted");
 
  flaghasat = 0;
  for (i = 0;i < tokaddr.len;++i)
    if (tokaddr.t[i].type == TOKEN822_AT)
      flaghasat = 1;
 
  tokaddr.len = 0;

  if (!address.len) return;

  if (!flaghasat)
    if (address.s[0] == '/') {
      if (!stralloc_0(&address)) nomem();
      strerr_die4x(111,FATAL,"file delivery ",address.s," not supported");
    }
  if (!flaghasat)
    if (address.s[0] == '|') {
      if (byte_chr(address.s,address.len,'\0') < address.len)
        strerr_die2x(111,FATAL,"NUL not permitted in program names");
      if (!stralloc_cats(&instr,"!")) nomem();
      if (!stralloc_catb(&instr,address.s + 1,address.len - 1)) nomem();
      if (!stralloc_0(&instr)) nomem();
      return;
    }


  if (target.len) {
    if (!stralloc_cats(&instr,"&")) nomem();
    if (!stralloc_cat(&instr,&fulltarget)) nomem();
    if (!stralloc_0(&instr)) nomem();
  }

  if (!flaghasat)
    if (!stralloc_cats(&address,"@")) nomem();

  if (!stralloc_copy(&target,&address)) nomem();
  if (!stralloc_copy(&fulltarget,&address)) nomem();

  if (fulltarget.s[fulltarget.len - 1] == '@')
     if (!stralloc_cat(&fulltarget,&defaulthost)) nomem();
  if (fulltarget.s[fulltarget.len - 1] == '+') {
    fulltarget.s[fulltarget.len - 1] = '.';
    if (!stralloc_cat(&fulltarget,&plusdomain)) nomem();
  }

  j = 0;
  for (i = 0;i < fulltarget.len;++i) if (fulltarget.s[i] == '@') j = i;
  for (i = j;i < fulltarget.len;++i) if (fulltarget.s[i] == '.') break;
  if (i == fulltarget.len) {
    if (!stralloc_cats(&fulltarget,".")) nomem();
    if (!stralloc_cat(&fulltarget,&defaultdomain)) nomem();
  }

  if (fulltarget.len > 800) longaddress();
  if (byte_chr(fulltarget.s,fulltarget.len,'\0') < fulltarget.len)
    strerr_die2x(111,FATAL,"NUL not permitted in recipient addresses");
}

stralloc line = {0};
stralloc newline = {0};
int match;

void parseerr()
{
  if (!stralloc_0(&line)) nomem();
  strerr_die3x(111,FATAL,"unable to parse this line: ",line.s);
}

void parseline()
{
  int wordok;
  struct token822 *t;
  struct token822 *beginning;
 
  switch(token822_parse(&toks,&line,&cbuf)) {
    case -1: nomem();
    case 0: parseerr();
  }

  beginning = toks.t;
  t = toks.t + toks.len;
  wordok = 1;
 
  if (!token822_readyplus(&tokaddr,1)) nomem();
  tokaddr.len = 0;
 
  while (t > beginning)
    switch((--t)->type) {
      case TOKEN822_SEMI:
        break; /*XXX*/
      case TOKEN822_COLON:
        if (t >= beginning + 2)
          if (t[-2].type == TOKEN822_COLON)
            if (t[-1].type == TOKEN822_ATOM)
              if (t[-1].slen == 7)
                if (!byte_diff(t[-1].s,7,"include")) {
                  gotincl();
                  t -= 2;
                }
        break; /*XXX*/
      case TOKEN822_RIGHT:
        if (tokaddr.len) gotaddr();
        while ((t > beginning) && (t[-1].type != TOKEN822_LEFT))
          if (!token822_append(&tokaddr,--t)) nomem();
        gotaddr();
        if (t <= beginning) parseerr();
        --t;
        while ((t > beginning) && ((t[-1].type == TOKEN822_COMMENT) || (t[-1].type == TOKEN822_ATOM) || (t[-1].type == TOKEN822_QUOTE) || (t[-1].type == TOKEN822_AT) || (t[-1].type == TOKEN822_DOT)))
          --t;
        wordok = 0;
        continue;
      case TOKEN822_ATOM: case TOKEN822_QUOTE: case TOKEN822_LITERAL:
        if (!wordok) if (tokaddr.len) gotaddr();
        wordok = 0;
        if (!token822_append(&tokaddr,t)) nomem();
        continue;
      case TOKEN822_COMMENT:
        /* comment is lexically a space; shouldn't affect wordok */
        break;
      case TOKEN822_COMMA:
        if (tokaddr.len) gotaddr();
        wordok = 1;
        break;
      default:
        wordok = 1;
        if (!token822_append(&tokaddr,t)) nomem();
        continue;
    }
  if (tokaddr.len) gotaddr();
}

char inbuf[1024];
substdio ssin;
struct cdbmss cdbmss;
stralloc key = {0};

void doit()
{
  if (!instr.len) {
    if (target.len) parseerr();
    return;
  }

  if (!target.len) parseerr();

  if (stralloc_starts(&target,"owner-")) {
    if (!stralloc_copys(&key,"?")) nomem();
    if (!stralloc_catb(&key,target.s + 6,target.len - 6)) nomem();
    case_lowerb(key.s,key.len);
    if (cdbmss_add(&cdbmss,key.s,key.len,fulltarget.s,fulltarget.len) == -1) writeerr();
  }

  if (!stralloc_copys(&key,":")) nomem();
  if (!stralloc_cat(&key,&target)) nomem();
  case_lowerb(key.s,key.len);
  if (cdbmss_add(&cdbmss,key.s,key.len,instr.s,instr.len) == -1) writeerr();
}

int main()
{
  int fd;

  umask(033);
  readcontrols();

  fd = open_read("/etc/aliases");
  if (fd == -1) readerr();
  substdio_fdbuf(&ssin,read,fd,inbuf,sizeof(inbuf));

  fd = open_trunc("/etc/aliases.tmp");
  if (fd == -1) strerr_die2sys(111,FATAL,"unable to create /etc/aliases.tmp: ");
  if (cdbmss_start(&cdbmss,fd) == -1) writeerr();

  if (!stralloc_copys(&line,"")) nomem();

  for (;;) {
    if (getln(&ssin,&newline,&match,'\n') != 0) readerr();

    if (match && (newline.s[0] == '\n')) continue;

    if (match && ((newline.s[0] == ' ') || (newline.s[0] == '\t'))) {
      if (!stralloc_cat(&line,&newline)) nomem();
      continue;
    }

    if (line.len)
      if (line.s[0] != '#') {
        if (!stralloc_copys(&target,"")) nomem();
        if (!stralloc_copys(&fulltarget,"")) nomem();
        if (!stralloc_copys(&instr,"")) nomem();
        parseline();
	doit();
      }

    if (!match) break;
    if (!stralloc_copy(&line,&newline)) nomem();
  }

  if (cdbmss_finish(&cdbmss) == -1) writeerr();
  if (fsync(fd) == -1) writeerr();
  if (close(fd) == -1) writeerr(); /* NFS stupidity */

  if (rename("/etc/aliases.tmp","/etc/aliases.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move /etc/aliases.tmp to /etc/aliases.cdb: ");
  
  _exit(0);
}
