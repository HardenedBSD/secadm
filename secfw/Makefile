PROG=	secfw
SRCS=	secfw.c config.c
LDADD=	-lucl -lm

CFLAGS+=	-fpie -I../libucl/include -I../libsecfw
LDFLAGS+=	-pie -L../libucl -L../libsecfw

NO_MAN=	"yes"

.include <bsd.prog.mk>
