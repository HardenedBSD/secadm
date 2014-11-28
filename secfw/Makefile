PROG=	secfw
SRCS=	config.c \
	kld.c \
	secfw.c

LDADD=	-lucl -lm

CFLAGS+=	-fpie -I../libucl/include -I../libsecfw
LDFLAGS+=	-pie -L../libucl -L../libsecfw

NO_MAN=	"yes"

.include <bsd.prog.mk>
