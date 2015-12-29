/*-
 * Copyright (c) 2015 Shawn Webb <shawn.webb@hardenedbsd.org>
 * Copyright (c) 2015 Brian Salcedo <brian.salcedo@hardenedbsd.org>
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
#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/pax.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <crypto/sha1.h>
#if __FreeBSD_version > 1100000
#include <crypto/sha2/sha256.h>
#else
#include <crypto/sha2/sha2.h>
#endif
#include <security/mac/mac_policy.h>

#include "secadm.h"

FEATURE(integriforce, "HardenedBSD Integriforce");

static int sysctl_integriforce_so(SYSCTL_HANDLER_ARGS);

SYSCTL_DECL(_hardening_secadm);

SYSCTL_NODE(_hardening_secadm, OID_AUTO, integriforce_so,
    CTLFLAG_MPSAFE | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_ANYBODY, sysctl_integriforce_so,
    "secadm integriforce checking for shared objects");

int
do_integriforce_check(secadm_rule_t *rule, struct vattr *vap,
    struct vnode *vp, struct ucred *ucred)
{
	SHA256_CTX sha256ctx;
	SHA1_CTX sha1ctx;
	struct iovec iov;
	struct uio uio;
	unsigned char *buf, hash[SHA256_DIGEST_LENGTH];
	size_t total, amt, hashsz;
	int err;

	switch (rule->sr_integriforce_data->si_cache) {
	case 0:
		break;

	case 1:
		return (0);

	default:
		if (rule->sr_integriforce_data->si_mode == 0) {
			printf("[SECADM] Warning: hash did not match for file"
			       " (%s)\n", rule->sr_integriforce_data->si_path);
			return (0);
		} else {
			printf("[SECADM] Error: hash did not match for file"
			       " (%s). Blocking execution.\n",
			       rule->sr_integriforce_data->si_path);
			return (EPERM);
		}
	}

	err = VOP_OPEN(vp, FREAD, ucred, curthread, NULL);
	if (err) {
		return (0);
	}

	buf = malloc(8192, M_SECADM, M_NOWAIT);
	if (buf == NULL) {
		VOP_CLOSE(vp, FREAD, ucred, curthread);
		return (0);
	}

	switch (rule->sr_integriforce_data->si_type) {
	case secadm_hash_sha1:
		hashsz = SHA1_RESULTLEN;
		SHA1Init(&sha1ctx);
		break;
	case secadm_hash_sha256:
		hashsz = SHA256_DIGEST_LENGTH;
		SHA256_Init(&sha256ctx);
		break;
	default:
		VOP_CLOSE(vp, FREAD, ucred, curthread);
		free(buf, M_SECADM);
		return (0);
	}

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
		err = VOP_READ(vp, &uio, 0, ucred);
		if (err) {
			VOP_CLOSE(vp, FREAD, ucred, curthread);
			free(buf, M_SECADM);
			return (0);
		}

		switch (rule->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			SHA1Update(&sha1ctx, buf, amt);
			break;
		case secadm_hash_sha256:
			SHA256_Update(&sha256ctx, buf, amt);
			break;
		default:
			break;
		}

		total -= amt;
	}

	free(buf, M_SECADM);
	VOP_CLOSE(vp, FREAD, ucred, curthread);

	switch (rule->sr_integriforce_data->si_type) {
	case secadm_hash_sha1:
		SHA1Final(hash, &sha1ctx);
		break;
	case secadm_hash_sha256:
		SHA256_Final(hash, &sha256ctx);
		break;
	default:
		break;
	}

	if (memcmp(rule->sr_integriforce_data->si_hash, hash, hashsz)) {
		switch (rule->sr_integriforce_data->si_mode) {
		case 0:
			printf("[SECADM] Warning: hash did not match for file"
			       " (%s)\n",
			       rule->sr_integriforce_data->si_path);
			err = 0;
			break;
		default:
			printf("[SECADM] Error: hash did not match for file"
			       " (%s). Blocking execution.\n",
			       rule->sr_integriforce_data->si_path);
			err = EPERM;
			break;
		}

		rule->sr_integriforce_data->si_cache = 2;
	} else {
		rule->sr_integriforce_data->si_cache = 1;
	}

	return (err);
}

static int
sysctl_integriforce_so(SYSCTL_HANDLER_ARGS)
{
	integriforce_so_check_t *integriforce_so;
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t r, *rule;
	struct nameidata nd;
	struct vattr vap;
	secadm_key_t key;
	int err;

	if (!(req->newptr) || req->newlen != sizeof(integriforce_so_check_t))
		return (EINVAL);

	if (!(req->oldptr) || req->oldlen != sizeof(integriforce_so_check_t))
		return (EINVAL);

	integriforce_so = malloc(sizeof(integriforce_so_check_t), M_SECADM, M_WAITOK);

	err = SYSCTL_IN(req, integriforce_so, sizeof(integriforce_so_check_t));
	if (err) {
		free(integriforce_so, M_SECADM);
		return (err);
	}

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, integriforce_so->isc_path, req->td);
	err = namei(&nd);
	if (err) {
		free(integriforce_so, M_SECADM);
		NDFREE(&nd, 0);
		return (err);
	}

	if ((err = vn_lock(nd.ni_vp, LK_SHARED | LK_RETRY)) != 0) {
		free(integriforce_so, M_SECADM);
		NDFREE(&nd, 0);
		return (err);
	}

	err = VOP_GETATTR(nd.ni_vp, &vap, req->td->td_ucred);
	if (err) {
		free(integriforce_so, M_SECADM);
		NDFREE(&nd, 0);
		return (err);
	}

	VOP_UNLOCK(nd.ni_vp, 0);

	key.sk_jid = req->td->td_ucred->cr_prison->pr_id;
	key.sk_type = secadm_integriforce_rule;
	key.sk_fileid = vap.va_fileid;
	strncpy(key.sk_mntonname,
	    nd.ni_vp->v_mount->mnt_stat.f_mntonname, MNAMELEN);
	r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);

	entry = get_prison_list_entry(
	    req->td->td_ucred->cr_prison->pr_id);

	RM_PE_RLOCK(entry, tracker);
	rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

	if (rule) {
		integriforce_so->isc_result =
		    do_integriforce_check(rule, &vap, nd.ni_vp,
		    req->td->td_ucred);
	}

	RM_PE_RUNLOCK(entry, tracker);

	SYSCTL_OUT(req, integriforce_so, sizeof(integriforce_so_check_t));
	free(integriforce_so, M_SECADM);

	NDFREE(&nd, 0);

	return (0);
}
