PROG=	secadm
SRCS=	config.c \
	secadm.c
BINDIR?=	/usr/sbin

LDADD=	-lucl -lm -lsecadm

CFLAGS+=	-fPIE -g -O0 -I${.CURDIR}/../libsecadm -I/usr/local/include
LDFLAGS+=	-pie -L${.CURDIR}/../libsecadm -L/usr/local/lib

NO_MAN=	"yes"

.include <bsd.prog.mk>
