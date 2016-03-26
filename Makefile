# Build everything by default
SUBDIR=		etc\
		kmod \
		libsecadm \
		secadm

# ports/hardenedbsd/secadm-kmod
.if defined(KMOD)
SUBDIR=		kmod
.endif

# ports/hardenedbsd/secadm
.if defined(CLI)
SUBDIR=		etc \
		libsecadm \
		secadm
.endif

.include <bsd.subdir.mk>
