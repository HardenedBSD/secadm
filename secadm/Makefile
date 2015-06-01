PROG=	secadm
SRCS=	config.c \
	secadm.c

.if defined(PREFIX)
BINDIR?=	${PREFIX}/sbin
.else
BINDIR?=	/usr/sbin
.endif

LDADD=	-lucl -lm -lsecadm
WANTS_PIE=	yes

CFLAGS+=	-I${.CURDIR}/../libsecadm -I/usr/local/include
LDFLAGS+=	-L${.CURDIR}/../libsecadm/obj -L/usr/local/lib

NO_MAN=	"yes"

.include <bsd.prog.mk>
