/*
 *  Revision 20170926, Kai Peter
 *  - changed 'control' directory name to 'etc'
*/
#include <sys/types.h>
#include <sys/stat.h>
#include "global.h"
#include "readwrite.h"
#include "auto_qmail.h"
#include "stralloc.h"
#include "substdio.h"
#include "case.h"
#include "control.h"
#include "constmap.h"
#include "direntry.h"
#include "error.h"
#include "str.h"
#include "fmt.h"
//#include "cdb.h"
#include "fd.h"
#include "open.h"
#include "byte.h"
#include "scan.h"
#include "str.h"
#include "readwrite.h"

#define FDAUTH 3
#define RESPECT_CASE "-C"
#define BUF_SIZE 129

/** @file qmail-vmailuser.c
    @return 0: virtual user exists 
            1: virtual user dir not accessible
            2: qmail-vmailuser is misused
            111: temporary problem
*/

char inputbuf[BUF_SIZE];
struct constmap mapvdoms;
stralloc vdoms = {0};
stralloc vdomdir = {0};
stralloc vuser = {0};
stralloc vuserdir = {0};

void pam_exit(int fail)
{
  int i;

  close(FDAUTH);
  for (i = 0; i < sizeof(inputbuf); ++i) inputbuf[i] = 0;
  _exit(fail);
}

int main(int argc,char **argv)
{
  DIR *dir;
  char *vdomuser; 
  char *domain = 0;
  int buflen = 0;
  int domlen = 0;
  int flagrespect = 0;
  int i, r;
  char ch;
  char *homedir = "/home";

  if (argv[1])
    if (!case_diffs(argv[1],RESPECT_CASE)) flagrespect = 1;
    else {
      homedir = argv[1];
      dir = opendir(homedir);
      if (!dir) pam_exit(2);
    }

  if (argv[2])
    if (!case_diffs(argv[2],RESPECT_CASE)) flagrespect = 1;


  switch (control_readfile(&vdoms,"etc/virtualdomains",0)) {
    case -1: pam_exit(111);
    case  0: if (!constmap_init(&mapvdoms,"",0,1)) pam_exit(111);
    case  1: if (!constmap_init(&mapvdoms,vdoms.s,vdoms.len,1)) pam_exit(111);
  }

  for (;;) {						/* read input */
    do
      r = read(FDAUTH,inputbuf + buflen,sizeof(inputbuf) - buflen);
    while ((r == -1) && (errno == EINTR));
    if (r == -1) pam_exit(111);
    if (r == 0) break;
    buflen += r;
    if (buflen >= sizeof(inputbuf)) pam_exit(2);
  }
  close(FDAUTH);

  if (r = byte_rchr(inputbuf,buflen,'@'))			/* @domain */
    if (r < buflen && inputbuf[r] == '@') {
      domain = inputbuf + r + 1;
      domlen = str_len(domain);
      if (!flagrespect)
        case_lowerb(inputbuf,buflen);
      else
        case_lowerb(domain,domlen);
    }
  vdomuser = constmap(&mapvdoms,domain,domlen);
  if (!vdomuser) pam_exit(1);

  if (!stralloc_copys(&vuser,"")) pam_exit(111);		/* user */
  for (i = 0; i < r; ++i) {
    ch = inputbuf[i];
    if (ch == '.') ch = ':';
    if (!stralloc_append(&vuser,&ch)) pam_exit(111);
  }
  if (!stralloc_0(&vuser)) pam_exit(111); 

  if (!stralloc_copys(&vdomdir,homedir)) pam_exit(111);  	/* common */
  if (!stralloc_cats(&vdomdir,"/")) pam_exit(111);  
  if (!stralloc_copy(&vuserdir,&vdomdir)) pam_exit(111);  

  if (!stralloc_cats(&vuserdir,vdomuser)) pam_exit(111);  	/* vmailmgr */
  if (!stralloc_cats(&vuserdir,"/users")) pam_exit(111);  
  if (!stralloc_copy(&vdomdir,&vuserdir)) pam_exit(111);  
  if (!stralloc_0(&vdomdir)) pam_exit(111); 

  dir = opendir(vdomdir.s);
  if (dir) {
    if (!stralloc_cats(&vuserdir,"/")) pam_exit(111);  
    if (!stralloc_cat(&vuserdir,&vuser)) pam_exit(111);  
    if (!stralloc_0(&vuserdir)) pam_exit(111); 

    dir = opendir(vuserdir.s);
    if (dir) pam_exit(0);
  }
   
  if (!stralloc_cats(&vuserdir,"vpopmail")) pam_exit(111);	/* vpopmail */
  if (!stralloc_cats(&vuserdir,"/domains/")) pam_exit(111);
  if (!stralloc_cats(&vuserdir,vdomuser)) pam_exit(111);  
  if (!stralloc_copy(&vdomdir,&vuserdir)) pam_exit(111);  
  if (!stralloc_0(&vdomdir)) pam_exit(111); 

  dir = opendir(vdomdir.s);
  if (dir) {
    if (!stralloc_cats(&vuserdir,"/")) pam_exit(111);  
    if (!stralloc_cat(&vuserdir,&vuser)) pam_exit(111);  
    if (!stralloc_0(&vuserdir)) pam_exit(111); 

    dir = opendir(vuserdir.s);
    if (dir) pam_exit(0);
  }

  pam_exit(1);
}
