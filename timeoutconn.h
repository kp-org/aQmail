#ifndef TIMEOUTCONN_H
#define TIMEOUTCONN_H

int timeoutconn4(int,struct ip_address *,unsigned int,int);
int timeoutconn6(int,struct ip6_address *,unsigned int,int,char *);
int timeoutconn(int,struct ip_mx *,int,int);

#endif
