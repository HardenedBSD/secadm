/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
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
 *
 * $FreeBSD$
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
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/stat.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

int
secadm_vnode_check_exec(struct ucred *ucred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel)
{
	struct rm_priotracker tracker;
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule;
	struct vattr vap;
	size_t i;
	int err=0, flags=0;

	entry = get_prison_list_entry(ucred->cr_prison->pr_name, 0);
	if (entry == NULL)
		return (0);

	err = VOP_GETATTR(imgp->vp, &vap, ucred);
	if (err)
		return (err);

	SPL_RLOCK(entry, tracker);
	for (rule = entry->spl_rules; rule != NULL; rule = rule->sr_next) {
		if (vap.va_fileid != rule->sr_inode)
			continue;

		if (strcmp(imgp->vp->v_mount->mnt_stat.f_mntonname,
		    rule->sr_mount))
			continue;

		for (i=0; i < rule->sr_nfeatures; i++) {
			switch(rule->sr_features[i].sf_type) {
			case pageexec_enabled:
				flags |= PAX_NOTE_PAGEEXEC;
				break;
			case pageexec_disabled:
				flags |= PAX_NOTE_NOPAGEEXEC;
				break;
			case mprotect_enabled:
				flags |= PAX_NOTE_MPROTECT;
				break;
			case mprotect_disabled:
				flags |= PAX_NOTE_NOMPROTECT;
				break;
			case segvguard_enabled:
				flags |= PAX_NOTE_SEGVGUARD;
				break;
			case segvguard_disabled:
				flags |= PAX_NOTE_NOSEGVGUARD;
				break;
			case aslr_enabled:
				flags |= PAX_NOTE_ASLR;
				break;
			case aslr_disabled:
				flags |= PAX_NOTE_NOASLR;
				break;
			case integriforce:
				err = do_integriforce_check(rule, &vap, imgp->vp, ucred);
				break;
#if __HardenedBSD_version > 21
			case shlibrandom_enabled:
				flags |= PAX_NOTE_SHLIBRANDOM;
				break;
			case shlibrandom_disabled:
				flags |= PAX_NOTE_NOSHLIBRANDOM;
				break;
#endif
			default:
				break;
			}
		}

		break;
	}

	SPL_RUNLOCK(entry, tracker);

	if (err == 0 && flags)
		err = pax_elf(imgp, flags);

	return (err);
}

int
secadm_vnode_check_unlink(struct ucred *ucred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	struct rm_priotracker tracker;
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule;
	struct vattr vap;
	int err, res=0;

	entry = get_prison_list_entry(ucred->cr_prison->pr_name, 0);
	if (entry == NULL)
		return (0);

	err = VOP_GETATTR(vp, &vap, ucred);
	if (err)
		return (err);

	SPL_RLOCK(entry, tracker);
	for (rule = entry->spl_rules; rule != NULL; rule = rule->sr_next) {
		if (vap.va_fileid != rule->sr_inode)
			continue;

		if (strcmp(vp->v_mount->mnt_stat.f_mntonname,
		    rule->sr_mount))
			continue;

		KASSERT(rule != NULL && rule->sr_path != NULL,
		    ("%s: failed ...", __func__));
		printf("[SECADM] Prevented to unlink %s: protected by a secadm rule.\n",
		    rule->sr_path);
		res=EPERM;
		break;
	}
	SPL_RUNLOCK(entry, tracker);

	return (res);
}

int
secadm_vnode_check_open(struct ucred *ucred, struct vnode *vp,
    struct label *label, accmode_t accmode)
{
	struct rm_priotracker tracker;
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule;
	struct vattr vap;
	int err, res;

	if (!(accmode & (VWRITE | VAPPEND)))
		return (0);

	res = 0;

	entry = get_prison_list_entry(ucred->cr_prison->pr_name, 0);
	if (entry == NULL)
		return (0);

	err = VOP_GETATTR(vp, &vap, ucred);
	if (err)
		return (err);

	SPL_RLOCK(entry, tracker);
	for (rule = entry->spl_rules; rule != NULL; rule = rule->sr_next) {
		if (vap.va_fileid != rule->sr_inode)
			continue;

		if (strcmp(vp->v_mount->mnt_stat.f_mntonname,
		    rule->sr_mount))
			continue;

		if (lookup_integriforce_feature(rule) != NULL) {
			KASSERT(rule != NULL && rule->sr_path != NULL,
			    ("%s: failed ...", __func__));
			printf("[SECADM] Warning: A process tried to modify "
			    "file %s, which is protected by a secadm rule. "
			    "Returning EPERM.\n", rule->sr_path);
			res=EPERM;
		}
		break;
	}
	SPL_RUNLOCK(entry, tracker);

	return (res);
}
