PROG=	secfw
SRCS=	config.c \
	kld.c \
	secfw.c

LDADD=	-lucl -lm -lsecfw

CFLAGS+=	-fPIE -g -O0 -I../libsecfw -I/usr/local/include
LDFLAGS+=	-pie -L../libsecfw -L/usr/local/lib -L../libsecfw

NO_MAN=	"yes"

.include <bsd.prog.mk>
