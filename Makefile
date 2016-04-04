# Build everything unless explicitly overridden

# ports/hardenedbsd/secadm-kmod
.if ! defined(WITHOUT_KMOD)
SUBDIR+=	kmod
.endif

# ports/hardenedbsd/secadm
.if ! defined(WITHOUT_CLI)
SUBDIR+=	etc \
		libsecadm \
		secadm
.endif

.include <bsd.subdir.mk>
