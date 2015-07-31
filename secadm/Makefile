PROG=	secadm
SRCS=	secadm.c

USE_LIBXO_PORTS= yes

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

LDADD=	-lutil -lsecadm -lxo -lucl
WANTS_PIE=	yes

CFLAGS+=	-g -I${.CURDIR}/../libsecadm -I/usr/local/include
LDFLAGS+=	-L${.CURDIR}/../libsecadm -L/usr/local/lib

NO_MAN=	"yes"

.include <bsd.prog.mk>
