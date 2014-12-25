PROG=	secadm
SRCS=	config.c \
	kld.c \
	secadm.c
BINDIR?=	/usr/sbin

LDADD=	-lucl -lm -lsecadm

CFLAGS+=	-fPIE -g -O0 -I../libsecadm -I/usr/local/include
LDFLAGS+=	-pie -L../libsecadm -L/usr/local/lib -L../libsecadm

NO_MAN=	"yes"

.include <bsd.prog.mk>
