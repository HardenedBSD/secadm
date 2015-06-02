#ifndef __secadm_compat_h
#define	__secadm_compat_h

#include <sys/param.h>

#if __FreeBSD_version < 1100000
#warning reallocarry does not exists on your system, falling back to realloc!
#define	reallocarray(p, nr, s)	realloc(p, (nr) * (s))
#endif

#endif /* __secadm_compat_h */
