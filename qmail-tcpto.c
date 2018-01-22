/* XXX: this program knows quite a bit about tcpto's internals */
/* feh, changed struct ipX_address to char; 20171231 */

#include <sys/socket.h>
#include "substdio.h"
#include "subfd.h"
#include "auto_qmail.h"
#include "fmt.h"
#include "ip.h"
#include "lock.h"
#include "error.h"
#include "exit.h"
#include "datetime.h"
#include "now.h"
#include "stralloc.h"

void die(n) int n; { substdio_flush(subfdout); _exit(n); }

void warn(s) char *s;
{
 char *x;
 x = error_str(errno);
 substdio_puts(subfdout,s);
 substdio_puts(subfdout,": ");
 substdio_puts(subfdout,x);
 substdio_puts(subfdout,"\n");
}

void die_chdir() { warn("fatal: unable to chdir"); die(111); }
void die_open() { warn("fatal: unable to open tcpto"); die(111); }
void die_lock() { warn("fatal: unable to lock tcpto"); die(111); }
void die_read() { warn("fatal: unable to read tcpto"); die(111); }

char tcpto_buf[1024];

char tmp[FMT_ULONG + IPFMT];

int main(void)
{
 int fdlock;
 int fd;
 int r;
 int i;
 char *record;
// struct ip_address ip;
// struct ip6_address ip6;
 char ip4[4];
 char ip6[16];
 datetime_sec when;
 datetime_sec start;

 if (chdir(auto_qmail) == -1) die_chdir();
 if (chdir("queue/lock") == -1) die_chdir();

 fdlock = open_write("tcpto");
 if (fdlock == -1) die_open();
 fd = open_read("tcpto");
 if (fd == -1) die_open();
 if (lock_ex(fdlock) == -1) die_lock();
 r = read(fd,tcpto_buf,sizeof(tcpto_buf));
 close(fd);
 close(fdlock);

 if (r == -1) die_read();
 r >>= 5;                   /* 32 bit read */

 start = now();
 record = tcpto_buf;

 for (i = 0; i < r; ++i) {
   if (record[4] >= 1) {
     when = (unsigned long) (unsigned char) record[11];
     when = (when << 8) + (unsigned long) (unsigned char) record[10];
     when = (when << 8) + (unsigned long) (unsigned char) record[9];
     when = (when << 8) + (unsigned long) (unsigned char) record[8];

     if (record[0] == AF_INET) {
       byte_copy(ip4,4,record+16);
       substdio_put(subfdout,tmp,ip4_fmt(tmp,ip4));
     } else {
       byte_copy(ip6,16,record+16);
       substdio_put(subfdout,tmp,ip6_fmt(tmp,ip6));
     }
     substdio_puts(subfdout," timed out ");
     substdio_put(subfdout,tmp,fmt_ulong(tmp,(unsigned long) (start - when)));
     substdio_puts(subfdout," seconds ago; # recent timeouts: ");
     substdio_put(subfdout,tmp,fmt_ulong(tmp,(unsigned long) (unsigned char) record[4]));
     substdio_puts(subfdout,"\n");
    }
   record += 32;
  }

 die(0);
}
