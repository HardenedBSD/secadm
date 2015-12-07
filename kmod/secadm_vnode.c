/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
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

#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/rmlock.h>
#include <sys/tree.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

int
secadm_vnode_check_exec(struct ucred *ucred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t r, *rule;
	int err, flags = 0;
	secadm_key_t key;
	struct vattr vap;

	if ((err = VOP_GETATTR(imgp->vp, &vap, ucred))) {
		return (err);
	}

	key.sk_jid = ucred->cr_prison->pr_id;
	key.sk_fileid = vap.va_fileid;
	strncpy(key.sk_mntonname,
	    imgp->vp->v_mount->mnt_stat.f_mntonname, MNAMELEN);

	entry = get_prison_list_entry(ucred->cr_prison->pr_id);

	RM_PE_RLOCK(entry, tracker);
	if (entry->sp_num_integriforce_rules) {
		key.sk_type = secadm_integriforce_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);
		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule != NULL) {
			if (rule->sr_active == 0) {
				goto rule_inactive;
			}

			RM_PE_RUNLOCK(entry, tracker);
			err = do_integriforce_check(rule, &vap, imgp->vp, ucred);
			RM_PE_RLOCK(entry, tracker);

			if (err) {
				RM_PE_RUNLOCK(entry, tracker);

				return (err);
			}
		}
	}

	if (entry->sp_num_pax_rules) {
		key.sk_type = secadm_pax_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);
		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule) {
			if (rule->sr_active == 0) {
				goto rule_inactive;
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_PAGEEXEC_SET) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_PAGEEXEC) {
					flags |= PAX_NOTE_PAGEEXEC;
				} else {
					flags |= PAX_NOTE_NOPAGEEXEC;
				}
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MPROTECT_SET) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_MPROTECT) {
					flags |= PAX_NOTE_MPROTECT;
				} else {
					flags |= PAX_NOTE_NOMPROTECT;
				}
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_ASLR_SET) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_ASLR) {
					flags |= PAX_NOTE_ASLR;
				} else {
					flags |= PAX_NOTE_NOASLR;
				}
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SEGVGUARD_SET) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_SEGVGUARD) {
					flags |= PAX_NOTE_SEGVGUARD;
				} else {
					flags |= PAX_NOTE_NOSEGVGUARD;
				}
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SHLIBRANDOM_SET) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_SHLIBRANDOM) {
					flags |= PAX_NOTE_SHLIBRANDOM;
				} else {
					flags |= PAX_NOTE_NOSHLIBRANDOM;
				}
			}

			if (rule->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MAP32) {
				if (rule->sr_pax_data->sp_pax &
				    SECADM_PAX_MAP32) {
					flags |=
					    PAX_NOTE_DISALLOWMAP32BIT;
				} else {
					flags |=
					    PAX_NOTE_NODISALLOWMAP32BIT;
				}
			}
		}
	}
rule_inactive:
	RM_PE_RUNLOCK(entry, tracker);

#if __HardenedBSD_version > 35
	if (err == 0 && flags)
		err = pax_elf(imgp, curthread, flags);

#else
	if (err == 0 && flags)
		err = pax_elf(imgp, flags);
#endif

	return (err);
}

int
secadm_vnode_check_open(struct ucred *ucred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t r, *rule;
	secadm_key_t key;
	struct vattr vap;
	int err;

	if (!(accmode & (VWRITE | VAPPEND))) {
		return (0);
	}

	if ((err = VOP_GETATTR(vp, &vap, ucred))) {
		return (err);
	}

	key.sk_jid = ucred->cr_prison->pr_id;
	key.sk_fileid = vap.va_fileid;
	strncpy(key.sk_mntonname,
	    vp->v_mount->mnt_stat.f_mntonname, MNAMELEN);

	entry = get_prison_list_entry(ucred->cr_prison->pr_id);

	RM_PE_RLOCK(entry, tracker);
	if (entry->sp_num_integriforce_rules) {
		key.sk_type = secadm_integriforce_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);

		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule) {
			printf(
			    "[SECADM] Prevented modification of (%s): "
			    "protected by a SECADM rule.\n",
			    rule->sr_integriforce_data->si_path);

			RM_PE_RUNLOCK(entry, tracker);
			return (EPERM);
		}
	}

	if (entry->sp_num_pax_rules) {
		key.sk_type = secadm_pax_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);

		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule) {
			printf(
			    "[SECADM] Prevented modification of (%s): "
			    "protected by a SECADM rule.\n",
			    rule->sr_pax_data->sp_path);

			RM_PE_RUNLOCK(entry, tracker);
			return (EPERM);
		}
	}

	RM_PE_RUNLOCK(entry, tracker);
	return (0);
}

int
secadm_vnode_check_unlink(struct ucred *ucred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp,
    struct label *vplabel, struct componentname *cnp)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t r, *rule;
	secadm_key_t key;
	struct vattr vap;
	int err;

	if ((err = VOP_GETATTR(vp, &vap, ucred))) {
		return (err);
	}

	entry = get_prison_list_entry(ucred->cr_prison->pr_id);

	key.sk_jid = ucred->cr_prison->pr_id;
	key.sk_fileid = vap.va_fileid;
	strncpy(key.sk_mntonname,
	    vp->v_mount->mnt_stat.f_mntonname, MNAMELEN);

	entry = get_prison_list_entry(ucred->cr_prison->pr_id);

	RM_PE_RLOCK(entry, tracker);
	if (entry->sp_num_integriforce_rules) {
		key.sk_type = secadm_integriforce_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);

		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule) {
			printf(
			    "[SECADM] Prevented unlink of (%s): "
			    "protected by a SECADM rule.\n",
			    rule->sr_integriforce_data->si_path);

			RM_PE_RUNLOCK(entry, tracker);
			return (EPERM);
		}
	}

	if (entry->sp_num_pax_rules) {
		key.sk_type = secadm_pax_rule;
		r.sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);

		rule = RB_FIND(secadm_rules_tree, &(entry->sp_rules), &r);

		if (rule) {
			printf(
			    "[SECADM] Prevented unlink of (%s): "
			    "protected by a SECADM rule.\n",
			    rule->sr_pax_data->sp_path);

			RM_PE_RUNLOCK(entry, tracker);
			return (EPERM);
		}
	}

	RM_PE_RUNLOCK(entry, tracker);
	return (0);
}
