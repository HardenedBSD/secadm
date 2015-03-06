SHLIB=	secadm
SHLIB_MAJOR=	0
SRCS=	integriforce.c libsecadm.c rules.c
INCS=	secadm.h libsecadm.h

.if defined(PREFIX)
INCLUDEDIR?=	${PREFIX}/include
.endif

LDADD+=	-lmd

CFLAGS+=	-g -O0 -I${.CURDIR}

NO_MAN=	"yes"

.include <bsd.lib.mk>
