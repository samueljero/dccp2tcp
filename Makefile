###############################################################################
#Author: Samuel Jero
#
# Date: 4/2011
#
# Makefile for program dccp2tcp
###############################################################################

CFLAGS= -O2 -Wall -Werror -g

# for solaris, you probably want:
#	LDLIBS = -lpcap -lnsl -lsocket
# for HP, I'm told that you need:
#	LDLIBS = -lpcap -lstr
# everybody else (that I know of) just needs:
#	LDLIBS = -lpcap
LDLIBS = -lpcap

BINDIR = /usr/local/bin
MANDIR = /usr/local/man


all: dccp2tcp

dccp2tcp: dccp2tcp.o encap.o
	gcc ${CFLAGS} ${LDLIBS} --std=gnu99 dccp2tcp.o encap.o -odccp2tcp

dccp2tcp.o: dccp2tcp.h dccp2tcp.c
	gcc ${CFLAGS} ${LDLIBS} --std=gnu99 -c dccp2tcp.c -odccp2tcp.o

encap.o: encap.c dccp2tcp.h
	gcc ${CFLAGS} ${LDLIBS} --std=gnu99 -c encap.c -oencap.o

install: dccp2tcp
	install -m 755 -o bin -g bin dccp2tcp ${BINDIR}/dccp2tcp
#	install -m 444 -o bin -g bin dccp2tcp.1 ${MANDIR}/man1/dccp2tcp.1

uninstall:
	rm -f ${BINDIR}/dccp2tcp
#	rm -r ${MANDIR}/man1/dccp2tcp.1

clean:
	rm -f *~ dccp2tcp core *.o
