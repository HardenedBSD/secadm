PROG=	secfw
SRCS=	config.c \
	kld.c \
	secfw.c

LDADD=	-lucl -lm

CFLAGS+=	-fpie -I../libsecfw -I/usr/local/include
LDFLAGS+=	-pie -L../libsecfw -L/usr/local/lib

NO_MAN=	"yes"

.include <bsd.prog.mk>
