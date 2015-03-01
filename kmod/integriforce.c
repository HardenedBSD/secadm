/*-
 * Copyright (c) 2015 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kernel.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/pax.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include <crypto/sha2/sha256.h>
#include <security/mac/mac_policy.h>

#include "secadm.h"

int
do_integriforce_check(secadm_rule_t *rule, struct vattr *vap,
    struct image_params *imgp, struct ucred *ucred)
{
	secadm_feature_t *feature;
	secadm_integriforce_t *integriforce_p;
	SHA256_CTX sha256ctx;
	struct iovec iov;
	struct uio uio;
	unsigned char *buf, hash[32];
	size_t total, amt;
	int err;

	feature = lookup_integriforce_feature(rule);
	if (feature == NULL)
		return (0);
	integriforce_p = feature->metadata;

	err = VOP_OPEN(imgp->vp, FREAD, ucred, curthread, NULL);
	if (err)
		return (0);

	buf = malloc(8192, M_SECADM, M_WAITOK);
	SHA256_Init(&sha256ctx);

	total = vap->va_size;
	while (total > 0) {
		amt = MIN(total, 8192);
		iov.iov_base = buf;
		iov.iov_len = amt;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = vap->va_size - total;
		uio.uio_resid = amt;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = curthread;
		err = VOP_READ(imgp->vp, &uio, 0, ucred);
		if (err) {
			VOP_CLOSE(imgp->vp, FREAD, ucred, curthread);
			free(buf, M_SECADM);
			return (0);
		}
		SHA256_Update(&sha256ctx, buf, amt);
		total -= amt;
	}

	free(buf, M_SECADM);
	VOP_CLOSE(imgp->vp, FREAD, ucred, curthread);
	SHA256_Final(hash, &sha256ctx);

	if (memcmp(integriforce_p->si_hash, hash, 32)) {
		switch (integriforce_p->si_mode) {
		case si_mode_soft:
			printf("secadm warning: hash did not match for rule %zu\n", rule->sr_id);
			err = 0;
			break;
		default:
			printf("secadm error: hash did not match for rule %zu. Blocking execution.\n", rule->sr_id);
			err = EPERM;
			break;
		}

	}

	return (err);
}

secadm_feature_t *
lookup_integriforce_feature(secadm_rule_t *rule)
{
	size_t i;

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].type == integriforce)
			return (&(rule->sr_features[i]));

	return (NULL);
}
