/*
 *  Revision 20170926, Kai Peter
 *  - moved directory 'users' to 'var/users'
*/
#include "global.h"
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "auto_qmail.h"
#include "case.h"
#include "control.h"
#include "constmap.h"
#include "error.h"
#include "str.h"
#include "fmt.h"
#include "fd.h"
#include "open.h"
#include "byte.h"
#include "scan.h"
#include "md5.h"
#include "hmac_md5.h"
#include "sha1.h"
#include "sha256.h"
#include "pathexec.h"
#include "prot.h"
#include "wait.h"
#include "sig.h"
#include "readwrite.h"
#define FDAUTH 3
#define FDGOSSIP 1
#define SOCKET_CALL "-s"

extern char *crypt();
#include <pwd.h>
static struct passwd *pw;

#include "hasspnam.h"
#ifdef HASGETSPNAM
#include <shadow.h>
static struct spwd *spw;
#endif

#include "hasuserpw.h"
#ifdef HASUSERPW
#include <userpw.h>
static struct userpw *upw;
#endif

/** @file qmail-authuser.c
@return 0: ok
    1: credentials failure
    2: qmail-authuser is misused
    111: temporary problem checking the password
*/

#define BUF_SIZE 513
char authbuf[BUF_SIZE];
substdio ssauth = SUBSTDIO_FDBUF(write,FDAUTH,authbuf,sizeof(authbuf));
static char hextab[]="0123456789abcdef";

struct constmap mapauthuser;
stralloc authfile = {0};
stralloc disabled = {0};
stralloc userauth = {0};

/** @brief Supported storage methods: 
	 (1) authuser:[=]plainpasswd, 
	 (2) authuser:%hashpasswd, 
	 (3) authuser:?, authuser:!, *:?, *:! (! -> +environment)
	 (4) x:+ -> checkvpw; x = { user@domain, @domain, @ } vmailmgr
	 (5) x:& -> vchkpw; x = { user@domain, @domain, @ } vpopmail
	 (6) x:= -> qmail-client; x = { user@domain, @domain, @ } dovecot
   Supported auth methods: 
	 user/login/plain: (1,2,3,4,5,6), 
	 cram-md5: (1,5 partially) 
*/

void auth_exit(int fail)
{
  int i;

  close(FDAUTH);
  for (i = 0; i < sizeof(authbuf); ++i) authbuf[i] = 0; 
  _exit(fail);
}

int auth_sha1(char *pwdhash,char *response)
{
  unsigned char digest[20];
  unsigned char digascii[41];
  int j;

  SHA1(digest,response,str_len(response));

  for (j = 0; j < 20; j++) {                                /* HEX => ASCII */
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0x0f];
  }
  digascii[40] = '\0';

  return str_diffn(digascii,pwdhash,40);
} 

int auth_sha256(char *pwdhash,char *response)
{
  unsigned char digest[32];
  unsigned char digascii[65];
  int j;

  sha256_hash(response,str_len(response),digest);

  for (j = 0; j < 32; j++) {                                /* HEX => ASCII */
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0x0f];
  }
  digascii[64] = '\0';

  return str_diffn(digascii,pwdhash,64);
} 

int auth_md5(char *pwdhash,char *response)
{ 
  MD5_CTX ctx;
  unsigned char digest[16];
  unsigned char digascii[33];
  int j;

  MD5Init(&ctx);
  MD5Update(&ctx,response,str_len(response));
  MD5Final(digest,&ctx);

  for (j = 0; j < 16; j++) {                                /* HEX => ASCII */
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0x0f];
  }
  digascii[32] = '\0';

  return str_diffn(digascii,pwdhash,32);
}

int auth_hash(char *password,char *response)
{
  switch (str_len(password)) {
  case 32: return auth_md5(password,response); 
  case 40: return auth_sha1(password,response);
  case 64: return auth_sha256(password,response);
  default: return -1;
  }
}

void user_env(int flag)
{
  if (flag) return;

  if (prot_gid((int) pw->pw_gid) == -1) auth_exit(1);
  if (prot_uid((int) pw->pw_uid) == -1) auth_exit(1);
  if (chdir(pw->pw_dir) == -1) auth_exit(111);

  if (!pathexec_env("USER",pw->pw_name)) auth_exit(111);
  if (!pathexec_env("HOME",pw->pw_dir)) auth_exit(111);
  if (!pathexec_env("SHELL",pw->pw_shell)) auth_exit(111); 
}

int auth_unix(char *user,char* response)
{
  char *encrypted = 0;
  char *stored = 0;

  pw = getpwnam(user);
  if (pw)
    stored = pw->pw_passwd;
  else {
    if (errno == ETXTBSY) auth_exit(111);
    auth_exit(1);
  }

#ifdef HASUSERPW
  upw = getuserpw(user);
  if (upw)
    stored = upw->upw_passwd;
  else
    if (errno == ETXTBSY) auth_exit(111);
#endif
#ifdef HASGETSPNAM
  spw = getspnam(user);
  if (spw)
    stored = spw->sp_pwdp;
  else
    if (errno == ETXTBSY) auth_exit(111);
#endif
  if (!stored || !*stored) auth_exit(111);
  encrypted = crypt(response,stored);

  return str_diff(encrypted,stored);
}

int auth_cram(unsigned char *password,unsigned char *response,unsigned char *challenge)
{
  unsigned char digest[16];
  unsigned char digascii[33];
  int j;

  hmac_md5(challenge,str_len(challenge),password,str_len(password),digest);

  for (j = 0; j < 16; j++) {
    digascii[2*j] = hextab[digest[j] >> 4];
    digascii[2*j+1] = hextab[digest[j] & 0x0f];
  }   
  digascii[32] = 0;

  return (str_diff(digascii,response) && str_diff(password,response));
}

int auth_dovecot(char *user,char *response,char *socket) 
{
  int wstat;
  int child;
  char *wrapper[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  close(FDGOSSIP); close(FDAUTH); 	/* gossiping doveadm */

  switch(child = fork()) {
    case -1:
      auth_exit(111);
    case 0:
      wrapper[0] = "doveadm";
      wrapper[1] = "auth";
      wrapper[2] = "test";
      wrapper[3] = "-a";
      wrapper[4] = socket;
      wrapper[5] = user;
      wrapper[6] = response;  
      wrapper[7] = 0;

      execvp(wrapper[0],wrapper);
      auth_exit(111);
  }

  if (wait_pid(&wstat,child) == -1) auth_exit(111);
  if (wait_crashed(wstat)) auth_exit(111);
  return wait_exitcode(wstat);  
}

int auth_wrapper(char *pam,char *arg1,char *arg2,char *auth,int len)
{
  int wstat;
  int child;
  int pi[2];
  char *wrapper[4] = {0, 0, 0, 0};
  
  close(FDAUTH);
  if (pipe(pi) == -1) auth_exit(111);
  if (pi[0] != FDAUTH) auth_exit(111);

  switch(child = fork()) {
    case -1:
      auth_exit(111);
    case 0: 
      close(pi[1]);
      if (fd_copy(FDAUTH,pi[0]) == -1) auth_exit(111);
      wrapper[0] = pam;
      wrapper[1] = arg1;
      wrapper[2] = arg2;
      wrapper[3] = 0;
      sig_pipedefault();

      execvp(wrapper[0],wrapper);
      auth_exit(111);
  }
  close(pi[0]);

  substdio_fdbuf(&ssauth,write,pi[1],authbuf,sizeof(authbuf));
  if (substdio_put(&ssauth,auth,len) == -1) auth_exit(111);
  if (substdio_flush(&ssauth) == -1) auth_exit(111);
  close(pi[1]);

  if (wait_pid(&wstat,child) == -1) auth_exit(111);
  if (wait_crashed(wstat)) auth_exit(111);
  return wait_exitcode(wstat);
}

int main(int argc,char **argv)
{
  char *authuser;
  char *authpass;
  char *response = 0;
  char *challenge = 0;
  char *domain = 0;
  char *authsocket = 0;
  int result = -1; /* initialise: -1; ok: 0; !ok: > 0 */
  int authlen = 0;
  int buflen = 0;
  int domlen = 0;
  int i = 0;
  int r;

  if (!argv[1]) 
    auth_exit(2);
  else if (argv[2])
    if (!case_diffs(argv[1],SOCKET_CALL)) {
      if (!argv[3]) auth_exit(2);
      authsocket = argv[2];
    }
  
  switch (control_readfile(&authfile,"var/users/authuser",0)) {
    case -1: auth_exit(111);
    case  0: if (!constmap_init(&mapauthuser,"",0,1)) auth_exit(111); 
    case  1: if (!constmap_init(&mapauthuser,authfile.s,authfile.len,1)) auth_exit(111);
  }

  for (;;) {						/* read input */
    do
      r = read(FDAUTH,authbuf + buflen,sizeof(authbuf) - buflen);
    while ((r == -1) && (errno == EINTR));
    if (r == -1) auth_exit(111);
    if (r == 0) break;
    buflen += r;
    if (buflen >= sizeof(authbuf)) auth_exit(2);
  }
  close(FDAUTH);

  authuser = authbuf + i;				/* username */
  if (i == buflen) auth_exit(2);
  while (authbuf[i++]) 					/* response */
    if (i == buflen) auth_exit(2);
  response = authbuf + i;
  if (i == buflen) auth_exit(2);
  while (authbuf[i++]) 					/* challenge */
    if (i == buflen) auth_exit(2);
  challenge = authbuf + i;
  
  authlen = str_len(authuser); 
  if (!stralloc_copyb(&userauth,authuser,authlen)) auth_exit(111);

  if (i = byte_rchr(authuser,authlen,'@')) 		/* @domain */
    if (i < authlen && authuser[i] == '@') {
      domain = authuser + i;
      domlen = str_len(domain);
      case_lowerb(domain,domlen);
      userauth.len = 0;
      if (!stralloc_copyb(&userauth,authuser,i)) auth_exit(111);
    }
  if (!stralloc_0(&userauth)) auth_exit(111);

  /* Check for disabled authuser/domains */

  if (!stralloc_copys(&disabled,"!")) auth_exit(111); 
  if (!stralloc_catb(&disabled,authuser,authlen)) auth_exit(111);
  if (constmap(&mapauthuser,disabled.s,disabled.len)) auth_exit(1);

  if (domlen) {
    disabled.len = 0;
    if (!stralloc_copys(&disabled,"!")) auth_exit(111);
    if (!stralloc_catb(&disabled,domain,domlen)) auth_exit(111);
    if (constmap(&mapauthuser,disabled.s,disabled.len)) auth_exit(1);
  }

  /* Virtual and system user accounts */

  authpass = constmap(&mapauthuser,authuser,authlen);
  if (!authpass && domlen) 
    authpass = constmap(&mapauthuser,domain,domlen);
  if (!authpass) 
    authpass = constmap(&mapauthuser,"@",1);
  if (!authpass)
    authpass = constmap(&mapauthuser,"*",1);

  if (!authpass) auth_exit(1);

  if (str_len(authpass) == 1) {
    switch (authpass[0]) {
      case '?': result = auth_unix(userauth.s,response); break;
      case '!': result = auth_unix(userauth.s,response); user_env(result); break;
      case '+': result = auth_wrapper("checkvpw","true","Maildir",authbuf,buflen); break;
      case '&': result = auth_wrapper("vchkpw",0,0,authbuf,buflen); break;
      case '=': result = auth_dovecot(authuser,response,authsocket); break;
      default:  result = 2; break;
    }
  } else 
    switch (authpass[0]) {
      case '%': result = auth_hash(authpass+1,response); 
      default:  if (result) result = auth_cram(authpass,response,challenge); break;
    } 

  if (result) auth_exit(result);

  for (i = 0; i < sizeof(authbuf); ++i) authbuf[i] = 0; 

  if (authsocket) pathexec(argv + 3);
  else pathexec(argv + 1);
  auth_exit(111);
}
