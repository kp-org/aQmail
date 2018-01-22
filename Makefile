# Don't edit Makefile! Use ../conf-* for configuration.

SHELL=/bin/sh

COMPILE=./compile
MAKELIB=./makelib
LOAD=./load

default: conf libs \
it-base it-dns it-control \
it-mbox it-queue \
it-clients it-user it-dns it-server it-log

clean:
	rm -f *.a *.o *.lib *.tmp `cat TARGETS`
	cd ucspissl ; make clean
	cd qlibs ; make clean

conf:
	./configure

libs:
	cd qlibs ; make
	cd qlibs ; make install
	cd ucspissl ; make
	cp ucspissl/ucspissl.a ucspissl.a
#	cp ucspissl/ssl.lib ssl.lib
	cd ..


auto_break.o:
	$(COMPILE) auto_break.c

auto_patrn.o:
	$(COMPILE) auto_patrn.c

auto_qmail.o:
	./compile auto_home.c
	./compile auto_qmail.c

auto_spawn.o:
	$(COMPILE) auto_spawn.c

auto_split.o:
	$(COMPILE) auto_split.c

auto_uids.o:
	./compile auto_uids.c

auto_usera.o:
	./compile auto_usera.c


md5c.o : \
compile md5c.c md5.h
	./compile md5c.c

hmac_md5.o : \
compile hmac_md5.c hmac_md5.h global.h
	./compile hmac_md5.c

bouncesaying:
	$(COMPILE) bouncesaying.c
	$(LOAD) bouncesaying strerr.a error.a substdio.a wait.a \
	qlibs/buffer.a qlibs/errmsg.a qlibs/byte.o str.a

commands.o:
	$(COMPILE) commands.c

compile:
#make-compile warn-auto.sh systype
#	( cat warn-auto.sh; ./make-compile "`cat systype`" ) > \
#	compile
#	chmod 755 compile

condredirect: qmail.o auto_qmail.o
	$(COMPILE) condredirect.c
	./load condredirect qmail.o buffer.a strerr.a fd.a sig.a wait.a \
	seek.a env.a error.a str.a fs.a auto_qmail.o buffer.a errmsg.a

#config: \
#warn-auto.sh config.sh
#	cat warn-auto.sh config.sh \
#	| sed s}HOME}"`head -1 conf-home`"}g \
#	| sed s}BREAK}"`head -1 conf-break`"}g \
#	| sed s}SPLIT}"`head -1 conf-split`"}g \
#	> config
#	chmod 755 config

#config-fast:
#warn-auto.sh config-fast.sh
## ../conf-home ../conf-break ../conf-split
#	cat warn-auto.sh config-fast.sh \
#	| sed s}HOME}"`head -1 conf-home`"}g \
#	| sed s}BREAK}"`head -1 conf-break`"}g \
#	| sed s}SPLIT}"`head -1 conf-split`"}g \
#	> config-fast
#	chmod 755 config-fast

constmap.o:
	$(COMPILE) constmap.c

control.o:
	$(COMPILE) control.c

date822fmt.o:
	$(COMPILE) date822fmt.c

datemail: \
warn-auto.sh datemail.sh
	cat warn-auto.sh datemail.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> datemail
	chmod 755 datemail

datetime.o:
	./compile datetime.c

ddist: \
warn-auto.sh ddist.sh
	cat warn-auto.sh ddist.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> ddist
	chmod 755 ddist

deferrals: \
warn-auto.sh deferrals.sh 
	cat warn-auto.sh deferrals.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> deferrals
	chmod 755 deferrals

dns.o:
#compile dns.c
# ip.h ipalloc.h \
#strsalloc.h gen_alloc.h dns.h
	./compile dns.c

dnscname: \
dnscname.o dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnscname dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	`cat dns.lib` `cat socket.lib`

dnscname.o:
#compile dnscname.c
# substdio.h subfd.h strsalloc.h \
#gen_alloc.h dns.h dnsdoe.h readwrite.h exit.h
	./compile dnscname.c

dnsdoe.o:
#compile dnsdoe.c
# substdio.h subfd.h exit.h dns.h dnsdoe.h
	./compile dnsdoe.c

dnsfq: \
dnsfq.o dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsfq dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	`cat dns.lib` `cat socket.lib`

dnsfq.o:
#compile dnsfq.c
# substdio.h subfd.h strsalloc.h gen_alloc.h \
#dns.h dnsdoe.h ip.h ipalloc.h gen_alloc.h exit.h
	./compile dnsfq.c

dnsip: \
dnsip.o dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsip dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	`cat dns.lib` `cat socket.lib`

dnsip.o:
#compile dnsip.c
# substdio.h subfd.h strsalloc.h gen_alloc.h \
#dns.h dnsdoe.h ip.h ipalloc.h gen_alloc.h exit.h
	./compile dnsip.c

dnsmxip: \
dnsmxip.o dns.o dnsdoe.o ip.a ipalloc.o now.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsmxip dns.o dnsdoe.o ip.a ipalloc.o now.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a  `cat \
	dns.lib` `cat socket.lib`

dnsmxip.o:
#compile dnsmxip.c
# substdio.h subfd.h strsalloc.h \
#gen_alloc.h dns.h dnsdoe.h ip.h ipalloc.h \
#now.h datetime.h exit.h
	./compile dnsmxip.c

dnsptr: \
dnsptr.o dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsptr dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	`cat dns.lib` `cat socket.lib`

dnsptr.o:
#compile dnsptr.c
# substdio.h subfd.h strsalloc.h gen_alloc.h \
#scan.h dns.h dnsdoe.h ip.h exit.h
	./compile dnsptr.c

dnstxt: \
dnstxt.o dns.o dnsdoe.o ip.a ipalloc.o strsalloc.o \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnstxt dns.o dnsdoe.o ip.a  ipalloc.o strsalloc.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	`cat dns.lib` `cat socket.lib`

dnstxt.o:
	$(COMPILE) dnstxt.c

except:
	$(COMPILE) except.c
	./load except strerr.a error.a wait.a \
	buffer.a errmsg.a str.a

fifo.o: \
compile fifo.c hasmkffo.h fifo.h
	./compile fifo.c

fmtqfn.o:
	$(COMPILE) fmtqfn.c

forward: qmail.o auto_qmail.o
	$(COMPILE) forward.c
	./load forward qmail.o strerr.a alloc.a fd.a wait.a sig.a \
	env.a substdio.a error.a str.a fs.a auto_qmail.o   qlibs/buffer.a qlibs/errmsg.a

gfrom.o: \
compile gfrom.c gfrom.h
	./compile gfrom.c

hasmkffo.h: \
trymkffo.c compile load
	( ( ./compile trymkffo.c && ./load trymkffo ) >/dev/null \
	2>&1 \
	&& echo \#define HASMKFIFO 1 || exit 0 ) > hasmkffo.h
	rm -f trymkffo.o trymkffo

hasspnam.h: \
tryspnam.c compile load
	( ( ./compile tryspnam.c && ./load tryspnam ) >/dev/null \
	2>&1 \
	&& echo \#define HASGETSPNAM 1 || exit 0 ) > hasspnam.h
	rm -f tryspnam.o tryspnam

hasuserpw.h: \
tryuserpw.c s.lib compile load
	( ( ./compile tryuserpw.c \
	&& ./load tryuserpw `cat s.lib` ) >/dev/null 2>&1 \
	&& echo \#define HASGETUSERPW 1 || exit 0 ) > hasuserpw.h
	rm -f tryuserpw.o tryuserpw

#trynpbg1.c compile load open.h open.a fifo.h fifo.o select.h

hasnpbg1.h: \
trynpbg1.c compile load open.h open.a fifo.h fifo.o
	( ( ./compile trynpbg1.c \
	&& ./load trynpbg1 fifo.o open.a && ./trynpbg1 ) \
	>/dev/null 2>&1 \
	&& echo \#define HASNAMEDPIPEBUG1 1 || exit 0 ) > \
	hasnpbg1.h
	rm -f trynpbg1.o trynpbg1

hassalen.h: \
trysalen.c compile
	( ./compile trysalen.c >/dev/null 2>&1 \
	&& echo \#define HASSALEN 1 || exit 0 ) > hassalen.h

hassgact.h: \
trysgact.c compile load
	( ( ./compile trysgact.c && ./load trysgact ) >/dev/null \
	2>&1 \
	&& echo \#define HASSIGACTION 1 || exit 0 ) > hassgact.h
	rm -f trysgact.o trysgact

hassgprm.h: \
trysgprm.c compile load
	( ( ./compile trysgprm.c && ./load trysgprm ) >/dev/null \
	2>&1 \
	&& echo \#define HASSIGPROCMASK 1 || exit 0 ) > hassgprm.h
	rm -f trysgprm.o trysgprm

headerbody.o:
	$(COMPILE) headerbody.c

hfield.o:
	$(COMPILE) hfield.c

hier.o: \
compile hier.c
# auto_qmail.h auto_split.h auto_uids.h fmt.h fifo.h
	./compile hier.c

hostname: \
load hostname.o substdio.a error.a str.a dns.lib socket.lib
	./load hostname substdio.a error.a str.a `cat dns.lib` \
	`cat socket.lib`

hostname.o: \
compile hostname.c
# substdio.h subfd.h readwrite.h exit.h
	./compile hostname.c

idn2.lib: \
tryidn2.c compile load
	( (./compile tryidn2.c && \
	./load tryidn2 `head -1 conf.tmp/conf-idn2` -lidn2 ) >/dev/null 2>&1 \
	&& echo "`head -1 conf.tmp/conf-idn2` -lidn2" || exit 0 ) > idn2.lib
	rm -f tryind2.o tryidn2


# install: \
#load install.o fifo.o hier.o auto_qmail.o auto_split.o auto_uids.o \
#strerr.a substdio.a open.a error.a str.a fs.a
#	./load install fifo.o hier.o auto_qmail.o auto_split.o \
#	auto_uids.o strerr.a substdio.a open.a error.a str.a fs.a \
#	qlibs/buffer.a qlibs/errmsg.a

#install.o: \
#compile install.c
# substdio.h strerr.h error.h open.h readwrite.h exit.h
#	./compile install.c

#instcheck: \
#load instcheck.o fifo.o hier.o auto_qmail.o auto_split.o auto_uids.o \
#strerr.a substdio.a error.a str.a fs.a
#	./load instcheck fifo.o hier.o auto_qmail.o auto_split.o \
#	auto_uids.o strerr.a substdio.a error.a str.a fs.a \
#	qlibs/buffer.a  qlibs/errmsg.a qlibs/byte.o qlibs/qstring.a

#instcheck.o: \
#compile instcheck.c
#	./compile instcheck.c

#ip.o:
#	$(COMPILE) ip.c

ipalloc.o:
	$(COMPILE) ipalloc.c

ipme.o: compile ipme.c hassalen.h
	./compile ipme.c

ipmeprint: \
load ipmeprint.o ipme.o ip.a ipalloc.o auto_qmail.o open.a \
getln.a stralloc.a alloc.a substdio.a \
error.a str.a fs.a socket.lib
	./load ipmeprint ipme.o ip.a auto_qmail.o ipalloc.o \
	open.a getln.a stralloc.a alloc.a \
	substdio.a error.a str.a fs.a  `cat socket.lib`

ipmeprint.o: \
compile ipmeprint.c
	./compile ipmeprint.c

it-base: \
qmail-local qmail-rspawn qmail-lspawn qmail-send \
qmail-clean qmail-start qmail-queue qmail-inject qmail-todo

it-mbox: \
forward predate preline condredirect bouncesaying except \
datemail maildirmake maildir2mbox maildirwatch qreceipt

it-clients: \
mailsubj qmail-remote qmail-qmqpc qmail-smtpam sendmail

it-dns: \
dnscname dnsptr dnsip dnsmxip dnsfq dnstxt \
hostname ipmeprint spfquery

it-control: \
qmail-badmimetypes qmail-badloadertypes \
qmail-mfrules qmail-recipients qmail-showctl \
qmail-authuser qmail-vmailuser

it-log: \
splogger qmail-mrtg qmail-mrtg-queue tai64nfrac

it-queue: \
qmail-qread qmail-qstat qmail-tcpto qmail-tcpok
# qmail-upq

it-server: \
qmail-qmtpd qmail-qmqpd qmail-smtpd dnsip

#it-setup: \
#config config-fast install instcheck

it-user: \
qmail-getpw qmail-newu qmail-pw2u qmail-newmrh 

load:
#make-load warn-auto.sh systype
#	( cat warn-auto.sh; ./make-load "`cat systype`" ) > load
#	chmod 755 load

maildir.o:
	$(COMPILE) maildir.c

maildir2mbox: maildir.o prioq.o now.o myctime.o gfrom.o
	$(COMPILE) maildir2mbox.c
	./load maildir2mbox maildir.o prioq.o now.o myctime.o \
	gfrom.o lock.a getln.a env.a open.a strerr.a stralloc.a \
	alloc.a substdio.a error.a str.a fs.a datetime.o     qlibs/buffer.a qlibs/errmsg.a

maildirmake:
	./compile maildirmake.c
	./load maildirmake strerr.a substdio.a error.a buffer.a str.a errmsg.a

maildirwatch: hfield.o headerbody.o maildir.o prioq.o now.o
	./compile maildirwatch.c
	./load maildirwatch hfield.o headerbody.o maildir.o \
	prioq.o now.o getln.a env.a open.a strerr.a stralloc.a \
	alloc.a substdio.a error.a str.a     qlibs/buffer.a qlibs/errmsg.a

mailsubj: \
warn-auto.sh mailsubj.sh
# ../conf-home ../conf-break ../conf-split
	cat warn-auto.sh mailsubj.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> mailsubj
	chmod 755 mailsubj

makelib:
#make-makelib warn-auto.sh systype
#	( cat warn-auto.sh; ./make-makelib "`cat systype`" ) > \
#	makelib
#	chmod 755 makelib

myctime.o:
	./compile myctime.c

mfrules.o:
	./compile mfrules.c

newfield.o:
	$(COMPILE) newfield.c

now.o:
	$(COMPILE) now.c

predate: datetime.o
	./compile predate.c
	./load predate datetime.o strerr.a sig.a fd.a wait.a \
	substdio.a error.a str.a fs.a buffer.a errmsg.a

preline:
	$(COMPILE) preline.c
	./load preline strerr.a fd.a wait.a sig.a env.a getopt.a \
	substdio.a error.a str.a    qlibs/buffer.a qlibs/errmsg.a

prioq.o:
	$(COMPILE) prioq.c

prot.o:
	cp qlibs/prot.o prot.o

qmail-authuser: \
auto_qmail.o alloc.a case.a control.o constmap.o hmac_md5.o md5c.o shadow.lib crypt.lib \
s.lib sha1.o sha256.o hasspnam.h hasuserpw.h
	$(COMPILE) qmail-authuser.c
	./load qmail-authuser auto_qmail.o control.o constmap.o \
	pathexec.o prot.o \
	hmac_md5.o md5c.o sha1.o sha256.o \
	stralloc.a alloc.a case.a error.a env.a fd.a fs.a getln.a \
	sig.a substdio.a open.a seek.a str.a substdio.a stralloc.a \
	wait.a `cat shadow.lib` `cat crypt.lib` `cat s.lib`    qlibs/buffer.a

qmail-badloadertypes: auto_qmail.o
	$(COMPILE) qmail-badloadertypes.c
	./load qmail-badloadertypes qlibs/cdb.a getln.a open.a \
	seek.a case.a qlibs/stralloc.a alloc.a strerr.a \
	error.a qlibs/str.a auto_qmail.o    qlibs/buffer.a qlibs/errmsg.a

qmail-badmimetypes: auto_qmail.o
	$(COMPILE) qmail-badmimetypes.c
	./load qmail-badmimetypes qlibs/cdb.a getln.a open.a \
	seek.a case.a qlibs/stralloc.a alloc.a strerr.a \
	error.a qlibs/str.a auto_qmail.o   qlibs/buffer.a qlibs/errmsg.a

qmail-clean: load fmtqfn.o now.o auto_qmail.o auto_split.o
	$(COMPILE) qmail-clean.c
	./load qmail-clean fmtqfn.o now.o getln.a sig.a stralloc.a \
	alloc.a substdio.a error.a str.a fs.a auto_qmail.o \
	auto_split.o     qlibs/buffer.a

qmail-getpw: auto_usera.o
	$(COMPILE) qmail-getpw.c
	./load qmail-getpw case.a substdio.a error.a str.a fs.a \
	auto_break.o auto_usera.o

qmail-inject: \
headerbody.o hfield.o newfield.o quote.o now.o \
control.o date822fmt.o constmap.o qmail.o case.a fd.a wait.a open.a \
getln.a sig.a getopt.a datetime.o token822.o env.a stralloc.a alloc.a \
substdio.a error.a str.a fs.a auto_qmail.o
	./compile qmail-inject.c
	./load qmail-inject headerbody.o hfield.o newfield.o \
	quote.o now.o control.o date822fmt.o constmap.o qmail.o \
	case.a fd.a wait.a open.a getln.a sig.a getopt.a datetime.o \
	token822.o env.a stralloc.a alloc.a substdio.a error.a \
	str.a fs.a auto_qmail.o     qlibs/buffer.a

qmail-local: \
load qmail.o quote.o now.o gfrom.o myctime.o \
slurpclose.o case.a getln.a getopt.a sig.a open.a seek.a lock.a fd.a \
wait.a env.a stralloc.a alloc.a strerr.a substdio.a error.a str.a \
fs.a datetime.o auto_qmail.o auto_patrn.o socket.lib
	$(COMPILE) -Iqlibs/include qmail-local.c
	./load qmail-local qmail.o quote.o now.o gfrom.o myctime.o \
	slurpclose.o case.a getln.a getopt.a sig.a open.a seek.a \
	lock.a fd.a wait.a env.a stralloc.a alloc.a qlibs/strerr.a \
	substdio.a str.a fs.a datetime.o auto_qmail.o \
	auto_patrn.o `cat socket.lib` qlibs/buffer.a qlibs/errmsg.a \
	error.a

qmail-lspawn: \
load qmail-lspawn.o spawn.o prot.o slurpclose.o sig.a wait.a \
case.a fd.a open.a stralloc.a alloc.a substdio.a error.a str.a \
fs.a auto_qmail.o auto_uids.o auto_spawn.o
	./load qmail-lspawn spawn.o prot.o slurpclose.o \
	sig.a wait.a case.a qlibs/cdb.a fd.a open.a stralloc.a alloc.a \
	substdio.a error.a str.a fs.a auto_qmail.o auto_uids.o \
	auto_spawn.o

qmail-lspawn.o:
	$(COMPILE) qmail-lspawn.c

qmail-mfrules: auto_qmail.o
	$(COMPILE) qmail-mfrules.c
	./load qmail-mfrules case.a qlibs/cdb.a getln.a open.a \
	seek.a fs.a stralloc.a alloc.a strerr.a substdio.a \
	error.a str.a auto_qmail.o     qlibs/buffer.a qlibs/errmsg.a

qmail-mrtg: \
getln.a open.a now.o \
fs.a stralloc.a alloc.a strerr.a substdio.a error.a str.a case.a
	./compile qmail-mrtg.c
	./load qmail-mrtg open.a getln.a now.o \
	fs.a stralloc.a alloc.a strerr.a substdio.a \
	error.a str.a case.a     qlibs/buffer.a

qmail-mrtg-queue: \
warn-auto.sh qmail-mrtg-queue.sh
	cat warn-auto.sh qmail-mrtg-queue.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> qmail-mrtg-queue
	chmod 755 qmail-mrtg-queue

qmail-newmrh: auto_qmail.o
	$(COMPILE) qmail-newmrh.c
	./load qmail-newmrh qlibs/cdb.a getln.a open.a \
	seek.a case.a stralloc.a alloc.a strerr.a \
	error.a str.a auto_qmail.o    qlibs/buffer.a qlibs/errmsg.a

qmail-newu: auto_qmail.o
	$(COMPILE) qmail-newu.c
	$(LOAD) qmail-newu qlibs/cdb.a getln.a open.a seek.a \
	case.a stralloc.a alloc.a error.a str.a \
	auto_qmail.o qlibs/buffer.a

qmail-pw2u: constmap.o control.o auto_break.o auto_qmail.o auto_usera.o
	./compile qmail-pw2u.c
	./load qmail-pw2u constmap.o control.o open.a getln.a \
	case.a getopt.a stralloc.a alloc.a substdio.a error.a str.a \
	fs.a auto_usera.o auto_break.o auto_qmail.o    qlibs/buffer.a

qmail-qmqpc: \
socket.a timeoutread.o timeoutwrite.o \
timeoutconn.o constmap.o case.a ip.a control.o auto_qmail.o sig.a ndelay.a open.a \
getln.a substdio.a stralloc.a alloc.a error.a str.a fs.a socket.lib
	./compile qmail-qmqpc.c
	./load qmail-qmqpc slurpclose.o socket.a timeoutread.o \
	timeoutwrite.o timeoutconn.o constmap.o case.a ip.a control.o auto_qmail.o \
	sig.a ndelay.a open.a getln.a substdio.a stralloc.a alloc.a \
	error.a str.a fs.a  `cat socket.lib`    qlibs/buffer.a

qmail-qmqpd: \
received.o now.o date822fmt.o qmail.o auto_qmail.o \
env.a substdio.a sig.a error.a wait.a fd.a str.a datetime.o fs.a
	./compile qmail-qmqpd.c
	./load qmail-qmqpd received.o now.o date822fmt.o qmail.o \
	auto_qmail.o env.a substdio.a sig.a error.a wait.a fd.a \
	str.a datetime.o fs.a case.a buffer.a

qmail-qmtpd: \
rcpthosts.o control.o constmap.o received.o \
date822fmt.o now.o qmail.o fd.a wait.a datetime.o open.a \
getln.a sig.a case.a env.a stralloc.a alloc.a substdio.a error.a \
str.a fs.a auto_qmail.o
	./compile qmail-qmtpd.c
	./load qmail-qmtpd rcpthosts.o control.o constmap.o \
	received.o date822fmt.o now.o qmail.o qlibs/cdb.a fd.a wait.a \
	datetime.o open.a getln.a sig.a case.a env.a stralloc.a \
	alloc.a substdio.a error.a str.a fs.a auto_qmail.o    qlibs/buffer.a

qmail-qread: \
fmtqfn.o readsubdir.o date822fmt.o datetime.o \
open.a getln.a stralloc.a alloc.a substdio.a error.a str.a fs.a \
auto_qmail.o auto_split.o
	$(COMPILE) qmail-qread.c
	./load qmail-qread fmtqfn.o readsubdir.o date822fmt.o \
	datetime.o open.a getln.a stralloc.a alloc.a substdio.a \
	error.a str.a fs.a auto_qmail.o auto_split.o    qlibs/buffer.a

qmail-qstat: \
warn-auto.sh qmail-qstat.sh
# ../conf-home ../conf-break ../conf-split
	cat warn-auto.sh qmail-qstat.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> qmail-qstat
	chmod 755 qmail-qstat

qmail-queue: \
triggerpull.o fmtqfn.o now.o date822fmt.o \
datetime.o seek.a ndelay.a open.a sig.a alloc.a substdio.a error.a \
env.a wait.a \
str.a fs.a auto_qmail.o auto_split.o auto_uids.o
	$(COMPILE) qmail-queue.c
	./load qmail-queue triggerpull.o fmtqfn.o now.o \
	date822fmt.o datetime.o seek.a ndelay.a open.a sig.a \
	env.a wait.a alloc.a substdio.a error.a str.a fs.a \
	auto_qmail.o auto_split.o auto_uids.o 

qmail-recipients: \
getln.a open.a seek.a case.a \
stralloc.a alloc.a strerr.a error.a str.a auto_qmail.o
	$(COMPILE) qmail-recipients.c
	./load qmail-recipients qlibs/cdb.a getln.a open.a \
	seek.a case.a stralloc.a alloc.a strerr.a \
	error.a str.a auto_qmail.o     qlibs/buffer.a qlibs/errmsg.a

qmail-remote: \
control.o constmap.o timeoutread.o timeoutwrite.o \
timeoutconn.o tcpto.o now.o dns.o ip.a ipalloc.o ipme.o quote.o strsalloc.o \
ndelay.a sig.a open.a lock.a seek.a getln.a stralloc.a alloc.a case.a \
tls_timeoutio.o tls_errors.o tls_remote.o base64.o md5c.o hmac_md5.o \
substdio.a error.a str.a fs.a auto_qmail.o socket.a dns.lib socket.lib idn2.lib
	$(COMPILE) qmail-remote.c
	./load qmail-remote control.o constmap.o timeoutread.o \
	timeoutwrite.o timeoutconn.o tcpto.o now.o case.a ip.a \
	tls_errors.o tls_remote.o tls_timeoutio.o \
	base64.o md5c.o hmac_md5.o socket.a strsalloc.o \
	ipalloc.o ipme.o quote.o dns.o ndelay.a sig.a open.a \
	lock.a seek.a getln.a stralloc.a alloc.a substdio.a \
	str.a fs.a ucspissl.a case.a error.a auto_qmail.o \
	`cat ssl.lib` `cat dns.lib` `cat socket.lib` `cat idn2.lib`    qlibs/buffer.a

qmail-rspawn: \
spawn.o tcpto_clean.o now.o sig.a open.a \
seek.a lock.a wait.a stralloc.a alloc.a substdio.a error.a str.a \
auto_qmail.o auto_uids.o auto_spawn.o
	./compile qmail-rspawn.c
	./load qmail-rspawn spawn.o tcpto_clean.o now.o \
	sig.a open.a seek.a lock.a wait.a fd.a stralloc.a alloc.a \
	substdio.a error.a str.a auto_qmail.o auto_uids.o \
	auto_spawn.o

qmail-send: \
qsutil.o control.o constmap.o newfield.o prioq.o \
trigger.o fmtqfn.o quote.o now.o readsubdir.o qmail.o date822fmt.o \
datetime.o auto_qmail.o auto_split.o
# case.a ndelay.a getln.a wait.a seek.a fd.a sig.a open.a \
#lock.a stralloc.a alloc.a substdio.a error.a str.a fs.a env.a
	./compile qmail-send.c
	./load qmail-send qsutil.o control.o constmap.o newfield.o \
	prioq.o trigger.o fmtqfn.o quote.o now.o readsubdir.o \
	qmail.o date822fmt.o datetime.o case.a ndelay.a getln.a \
	wait.a seek.a fd.a sig.a open.a lock.a stralloc.a alloc.a \
	substdio.a error.a str.a fs.a auto_qmail.o auto_split.o env.a qlibs/buffer.a

#qmail-send.o: \
#compile qmail-send.c
# readwrite.h control.h select.h \
#open.h seek.h exit.h lock.h ndelay.h now.h datetime.h getln.h \
#substdio.h error.h gen_alloc.h fmt.h \
#scan.h auto_qmail.h trigger.h newfield.h quote.h \
#qmail.h qsutil.h prioq.h datetime.h gen_alloc.h constmap.h \
#fmtqfn.h readsubdir.h

qmail-showctl: \
auto_uids.o control.o open.a getln.a stralloc.a \
alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_break.o \
auto_patrn.o auto_spawn.o auto_split.o
	./compile qmail-showctl.c
	./load qmail-showctl auto_uids.o control.o open.a getln.a \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	auto_qmail.o auto_break.o auto_patrn.o auto_spawn.o \
	auto_split.o     qlibs/buffer.a

#qmail-showctl.o:
#compile qmail-showctl.c

qmail-smtpd: \
auto_break.o rcpthosts.o commands.o timeoutread.o \
timeoutwrite.o ip.a ipme.o ipalloc.o control.o constmap.o received.o \
recipients.o mfrules.o tls_start.o smtpdlog.o dns.o \
date822fmt.o now.o qmail.o wildmat.o spf.o spfdnsip.o strsalloc.o \
fd.a wait.a datetime.o getln.a open.a sig.a case.a env.a stralloc.a \
alloc.a substdio.a error.a str.a seek.a fs.a auto_qmail.o base64.o socket.lib qmail-spp.o
	./compile qmail-smtpd.c
	./load qmail-smtpd rcpthosts.o recipients.o commands.o timeoutread.o \
	mfrules.o tls_start.o auto_break.o smtpdlog.o \
	timeoutwrite.o ip.a ipme.o ipalloc.o control.o constmap.o dns.o \
	spf.o spfdnsip.o received.o date822fmt.o now.o qmail.o wildmat.o \
	base64.o strsalloc.o qlibs/cdb.a seek.a fd.a wait.a datetime.o getln.a \
	open.a sig.a case.a  env.a stralloc.a alloc.a substdio.a str.a \
	qmail-spp.o \
	fs.a error.a auto_qmail.o `cat dns.lib` `cat socket.lib`    qlibs/buffer.a
#        qlibs/uint32p.o
#       mfrules.o uint32_unpack.o tls_start.o auto_break.o smtpdlog.o \
#cdb2.a fd.a wait.a datetime.o getln.a open.a sig.a case.a env.a stralloc.a \

qmail-spp.o:
	$(COMPILE) qmail-spp.c

qmail-smtpam: \
control.o constmap.o strsalloc.o timeoutread.o timeoutwrite.o \
timeoutconn.o tcpto.o now.o dns.o ip.a ipalloc.o ipme.o quote.o socket.a \
ndelay.a sig.a open.a lock.a seek.a getln.a stralloc.a alloc.a case.a error.a \
substdio.a error.a str.a fs.a auto_qmail.o dns.lib socket.lib ssl.lib idn2.lib \
tls_timeoutio.o tls_errors.o tls_remote.o
	./compile qmail-smtpam.c
	./load qmail-smtpam control.o constmap.o strsalloc.o timeoutread.o \
	timeoutwrite.o timeoutconn.o tcpto.o now.o dns.o ip.a ipalloc.o \
	ipme.o quote.o socket.a ndelay.a sig.a open.a lock.a seek.a \
	getln.a stralloc.a alloc.a substdio.a error.a str.a fs.a auto_qmail.o \
	tls_errors.o tls_remote.o tls_timeoutio.o case.a ucspissl.a \
	`cat ssl.lib` `cat dns.lib` `cat socket.lib`    qlibs/buffer.a

qmail-start: prot.o fd.a auto_uids.o
	./compile qmail-start.c
	./load qmail-start prot.o fd.a auto_uids.o

#qmail-start.o: \
#compile qmail-start.c
#	./compile qmail-start.c

qmail-tcpok: auto_qmail.o
# open.a lock.a strerr.a substdio.a error.a str.a
	./compile qmail-tcpok.c
	./load qmail-tcpok open.a lock.a strerr.a substdio.a \
	error.a str.a auto_qmail.o buffer.a errmsg.a

qmail-tcpto: ip.a now.o auto_qmail.o
# open.a lock.a substdio.a error.a str.a \
#stralloc.a alloc.a fs.a
	./compile qmail-tcpto.c
	./load qmail-tcpto ip.a now.o open.a lock.a substdio.a \
	error.a str.a stralloc.a alloc.a fs.a auto_qmail.o    qlibs/buffer.a

#qmail-tcpto.o: \
#compile qmail-tcpto.c
# substdio.h subfd.h auto_qmail.h \
#fmt.h ip.h lock.h error.h exit.h datetime.h now.h datetime.h

qmail-todo: \
control.o constmap.o trigger.o fmtqfn.o now.o qsutil.o \
readsubdir.o auto_qmail.o auto_split.o
# case.a ndelay.a getln.a sig.a open.a stralloc.a alloc.a \
#substdio.a error.a str.a fs.a
	./compile qmail-todo.c
	./load qmail-todo control.o constmap.o trigger.o fmtqfn.o now.o \
	readsubdir.o case.a ndelay.a getln.a sig.a open.a stralloc.a qsutil.o \
	alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_split.o \
	qlibs/buffer.a

#qmail-upq: warn-auto.sh qmail-upq.sh
##conf-home ../conf-break ../conf-split
#	cat warn-auto.sh qmail-upq.sh \
#	| sed s}QMAIL}"`head -1 conf-home`"}g \
#	| sed s}BREAK}"`head -1 conf-break`"}g \
#	| sed s}SPLIT}"`head -1 conf-split`"}g \
#	> qmail-upq
#	chmod 755 qmail-upq

qmail-vmailuser: \
auto_qmail.o alloc.a case.a control.o constmap.o \
env.a error.a fd.a fs.a  getln.a substdio.a open.a seek.a \
stralloc.a str.a 
	./compile qmail-vmailuser.c
	./load qmail-vmailuser auto_qmail.o control.o constmap.o \
	getln.a stralloc.a alloc.a case.a error.a env.a fd.a fs.a  \
	substdio.a open.a seek.a str.a substdio.a stralloc.a    qlibs/buffer.a

qmail.o:
	$(COMPILE) qmail.c

qreceipt: \
headerbody.o hfield.o quote.o token822.o qmail.o \
getln.a fd.a wait.a sig.a env.a stralloc.a alloc.a substdio.a error.a \
str.a auto_qmail.o
	./compile qreceipt.c
	./load qreceipt headerbody.o hfield.o quote.o token822.o \
	qmail.o getln.a fd.a wait.a sig.a env.a stralloc.a alloc.a \
	substdio.a error.a str.a auto_qmail.o     qlibs/buffer.a

qsutil.o:
	$(COMPILE) qsutil.c

quote.o:
	$(COMPILE) quote.c

rcpthosts.o:
	$(COMPILE) rcpthosts.c

recipients.o:
	$(COMPILE) recipients.c

smtpdlog.o:
	$(COMPILE) smtpdlog.c

s.lib: \
tryslib.c compile load
	( ( ./compile tryslib.c && \
        ./load tryslib -ls ) >/dev/null 2>&1 \
	&& echo -ls || exit 0 ) > s.lib
	rm -f tryslib.o tryslib

shadow.lib: \
tryshadow.c compile load
	( ( ./compile tryshadow.c && \
	./load tryshadow -lshadow ) >/dev/null 2>&1 \
	&& echo -lshadow || exit 0 ) > shadow.lib
	rm -f tryshadow.o tryshadow

readsubdir.o: \
compile readsubdir.c
# readsubdir.h fmt.h scan.h auto_split.h
	./compile readsubdir.c

received.o: \
compile received.c
# fmt.h qmail.h substdio.h now.h datetime.h \
#datetime.h date822fmt.h received.h
	./compile received.c

seek.a:
#	cp qlibs/seek.a seek.a

#select.h: \
#compile trysysel.c select.h1 select.h2
#	( ./compile trysysel.c >/dev/null 2>&1 \
#	&& cat select.h2 || cat select.h1 ) > select.h
#	rm -f trysysel.o trysysel

sendmail: \
load sendmail.o env.a getopt.a alloc.a substdio.a error.a str.a \
auto_qmail.o
	./load sendmail env.a getopt.a alloc.a substdio.a error.a \
	str.a auto_qmail.o     qlibs/buffer.a

sendmail.o: \
compile sendmail.c
# sgetopt.h subgetopt.h substdio.h subfd.h \
#auto_qmail.h exit.h env.h
	./compile sendmail.c

#sgetopt.o: \
#compile sgetopt.c
# substdio.h subfd.h sgetopt.h subgetopt.h \
#subgetopt.h
#	./compile sgetopt.c

sha1.o : \
compile sha1.c sha1.h
	./compile sha1.c

sha256.o : \
compile sha256.c sha256.h
	./compile sha256.c

#sig.a:
#	cp qlibs/sig.a sig.a

slurpclose.o:
	ln -sf qlibs/readclose.o slurpclose.o

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

spawn.o:
	$(COMPILE) spawn.c

spfdnsip.o:
	$(COMPILE) spfdnsip.c

spf.o:
#compile spf.c
# gen_alloc.h ipme.h ip.h ipalloc.h \
#strsalloc.h fmt.h scan.h now.h
	./compile spf.c

spfquery: \
spf.o spfdnsip.o ip.a ipme.o ipalloc.o strsalloc.o now.o dns.o \
datetime.o stralloc.a alloc.a str.a substdio.a error.a fs.a case.a dnsresolv.a dns.lib
	./compile spfquery.c
	./load spfquery spf.o spfdnsip.o ip.a ipme.o ipalloc.o strsalloc.o \
	now.o dns.o datetime.o stralloc.a alloc.a str.a substdio.a \
	case.a error.a fs.a dnsresolv.a `cat dns.lib` `cat socket.lib`

#spfquery.o: \
#compile spfquery.c
# substdio.h subfd.h gen_alloc.h \
#spf.h exit.h dns.h ipalloc.h

splogger: \
load splogger.o substdio.a error.a str.a fs.a syslog.lib socket.lib
	./load splogger substdio.a error.a str.a fs.a  `cat \
	syslog.lib` `cat socket.lib`

splogger.o:
#compile splogger.c
# error.h substdio.h subfd.h exit.h \
#scan.h fmt.h
	./compile splogger.c

#str.a:
#	cp qlibs/str.a str.a

#stralloc.a:
#	cp qlibs/stralloc.a stralloc.a

#strerr.a:
#	cp qlibs/strerr.a strerr.a

strsalloc.o: \
compile strsalloc.c
	./compile strsalloc.c

#substdio.a:
#	cp qlibs/substdio.a substdio.a

syslog.lib: \
trysyslog.c compile load
	( ( ./compile trysyslog.c && \
	./load trysyslog -lgen ) >/dev/null 2>&1 \
	&& echo -lgen || exit 0 ) > syslog.lib
	rm -f trysyslog.o trysyslog

strset.o: \
compile strset.c
# strset.h uint32.h
	./compile strset.c

tai64nfrac: \
getln.a open.a \
fs.a stralloc.a alloc.a strerr.a substdio.a error.a str.a
	./compile tai64nfrac.c
	./load tai64nfrac open.a getln.a \
	fs.a stralloc.a alloc.a strerr.a substdio.a \
	error.a str.a     qlibs/buffer.a

tcpto.o:
#compile tcpto.c
# tcpto.h open.h lock.h seek.h now.h datetime.h ip.h \
#datetime.h readwrite.h
	./compile tcpto.c

tcpto_clean.o:
#compile tcpto_clean.c
# tcpto.h open.h substdio.h readwrite.h
	./compile tcpto_clean.c

timeoutconn.o: \
compile timeoutconn.c
# ndelay.h select.h error.h readwrite.h ip.h \
#timeoutconn.h control.h constmap.h socket_if.h
	./compile timeoutconn.c

timeoutread.o: \
compile timeoutread.c
# timeoutread.h select.h error.h readwrite.h
	./compile timeoutread.c

timeoutwrite.o: \
compile timeoutwrite.c
# timeoutwrite.h select.h error.h readwrite.h
	./compile timeoutwrite.c

tls_errors.o: \
compile tls_errors.c tls_errors.h
	./compile tls_errors.c

tls_remote.o: \
compile tls_remote.c
# tls_remote.h select.h error.h ndelay.h
	./compile tls_remote.c

tls_start.o: \
compile tls_start.c tls_start.h
	./compile tls_start.c

tls_timeoutio.o: \
compile tls_timeoutio.c
# tls_timeoutio.h select.h error.h ndelay.h
	./compile tls_timeoutio.c

token822.o: \
compile token822.c
# gen_alloc.h token822.h \
#gen_alloc.h gen_allocdefs.h
	./compile token822.c

trigger.o: \
compile trigger.c hasnpbg1.h open.h
	./compile trigger.c

triggerpull.o:
	$(COMPILE) triggerpull.c

#wait.a:
#	ln -sf qlibs/wait.a wait.a

wildmat.o:
	$(COMPILE) wildmat.c

xqp: \
warn-auto.sh xqp.sh
	cat warn-auto.sh xqp.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> xqp
	chmod 755 xqp
