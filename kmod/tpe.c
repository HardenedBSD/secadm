/*-
 * Copyright (c) 2016 Shawn Webb <shawn.webb@hardenedbsd.org>
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

#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/tree.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

int
tpe_check(struct image_params *imgp, secadm_prison_entry_t *entry)
{
	char *path, *p1, *newpath;
	struct nameidata nd;
	struct vattr vap;
	int err;

	err = 0;
	newpath = NULL;

	if (!(entry->sp_tpe_flags & SECADM_TPE_ENABLED)) {
		return (0);
	}

	if ((entry->sp_tpe_flags & SECADM_TPE_ALL) != SECADM_TPE_ALL) {
		if (entry->sp_tpe_flags & SECADM_TPE_INVERT) {
			if (curthread->td_ucred->cr_gid == entry->sp_tpe_gid) {
				return (0);
			}
		} else {
			if (curthread->td_ucred->cr_gid != entry->sp_tpe_gid) {
				return (0);
			}
		}
	}

	if (imgp->args == NULL) {
		return (0);
	}

	if (imgp->args == (struct image_args *)0xdeadc0de || imgp->args == (struct image_args *)0xdeadc0dedeadc0de) {
		return (0);
	}

	err = 0;

	path = imgp->args->fname;

	if (path == NULL) {
		return (0);
	}

	p1 = strrchr(path, '/');
	if (p1 == NULL) {
		return (0);
	}

	newpath = malloc((p1 - path) + 1, M_SECADM, M_WAITOK | M_ZERO);
	strncpy(newpath, path, p1 - path);

	memset(&nd, 0x00, sizeof(nd));
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, newpath, curthread);
	if ((err = namei(&nd))) {
		free(newpath, M_SECADM);
		NDFREE(&nd, NDF_ONLY_PNBUF);
		return (err);
	}

	err = VOP_GETATTR(nd.ni_vp, &vap, curthread->td_ucred);
	if (err) {
		err = 0;
		goto cleanup;
	}

	if (vap.va_uid != 0) {
		err = EPERM;
		goto cleanup;
	}

	if (vap.va_mode & (S_IWGRP | S_IWOTH)) {
		err = EPERM;
		goto cleanup;
	}

cleanup:
	NDFREE(&nd, NDF_ONLY_PNBUF);
	free(newpath, M_SECADM);

	return (err);
}
