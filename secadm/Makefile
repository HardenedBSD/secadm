PROG=	secadm
SRCS=	secadm.c

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

LDADD=	-lsecadm
WANTS_PIE=	yes

CFLAGS+=	-I${.CURDIR}/../libsecadm -I/usr/local/include
LDFLAGS+=	-L${.CURDIR}/../libsecadm -L/usr/local/lib

NO_MAN=	"yes"

.include <bsd.prog.mk>
