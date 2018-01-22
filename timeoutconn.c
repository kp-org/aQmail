#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"
#include "ip.h"
#include "ipalloc.h"
#include "byte.h"
#include "timeoutconn.h"
#include "socket_if.h"

int timeoutconn4(int s,struct ip_address *ip,unsigned int port,int timeout)
{
  char ch;
  struct sockaddr_in sin;
  char *x;
  fd_set wfds;
  struct timeval tv;
 
  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,ip);
  x = (char *) &sin.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  sin.sin_family = AF_INET;
 
  if (ndelay_on(s) == -1) return -1;
 
  /* XXX: could bind s */
 
  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK)) return -1;
 
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;
 
  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }
 
  errno = ETIMEDOUT; /* note that connect attempt is continuing */
  return -1;
}

int timeoutconn6(int s,struct ip6_address *ip,unsigned int port,int timeout,char *ifname)
{
  char ch;
  struct sockaddr_in6 sin;
  fd_set wfds;
  struct timeval tv;

  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin6_addr,16,ip);
  sin.sin6_port = htons(port);
  sin.sin6_family = AF_INET6;
  if (ifname) sin.sin6_scope_id = socket_getifidx(ifname); 

  if (ndelay_on(s) == -1) return -1;

  /* XXX: could bind s */

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK)) return -1;

  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }

  errno = ETIMEDOUT; /* note that connect attempt is continuing */
  return -1;
}

int timeoutconn(int fd,struct ip_mx *ix,int port,int timeout)
{

  switch(ix->af) {
    case AF_INET6: return timeoutconn6(fd,&ix->addr.ip6,port,timeout,0); 
    case AF_INET:  return timeoutconn4(fd,&ix->addr.ip4,port,timeout); 
  }
}
