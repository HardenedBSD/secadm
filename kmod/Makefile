KMOD=	secadm
SRCS=	\
	integriforce.c \
	secadm.c \
	secadm_mac.c \
	secadm_sysctl.c \
	secadm_vnode.c \
	vnode_if.h

CFLAGS+=	-g -O0 -I${.CURDIR}/../libsecadm

.include <bsd.kmod.mk>
