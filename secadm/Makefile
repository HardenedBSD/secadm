PROG=	secadm
SRCS=	secadm.c

USE_LIBXO_PORTS= yes

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/man/man
.else
BINDIR?=	/usr/sbin
.endif

LDADD=	-lutil -lsecadm -lxo -lucl
WANTS_PIE=	yes

CFLAGS+=	-I${.CURDIR}/../libsecadm -I/usr/local/include
LDFLAGS+=	-L${.CURDIR}/../libsecadm/obj -L/usr/local/lib

MAN=	secadm.rules.5 secadm.8

.include <bsd.prog.mk>
