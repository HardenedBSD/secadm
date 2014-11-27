# $FreeBSD$

LIB=		ucl
SHLIB_MAJOR=	1
SRCS=		src/ucl_emitter_streamline.c \
		src/ucl_emitter_utils.c \
		src/ucl_emitter.c \
		src/ucl_hash.c \
		src/ucl_parser.c  \
		src/ucl_schema.c \
		src/ucl_util.c \
		src/xxhash.c

.PATH:		${LIBUCL}/src

WARNS=		1
CFLAGS+=	-I./include \
		-I./src \
		-I./uthash

.include <bsd.lib.mk>
