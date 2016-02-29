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

#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/tree.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include "secadm.h"

FEATURE(secadm, "HardenedBSD Security Administration (secadm)");

MALLOC_DEFINE(M_SECADM, "secadm", "HardenedBSD SECADM data");
RB_GENERATE(secadm_rules_tree, secadm_rule, sr_tree, secadm_rule_cmp);

secadm_prisons_t secadm_prison_list;

int
secadm_rule_cmp(secadm_rule_t *a, secadm_rule_t *b)
{
	if (a->sr_key < b->sr_key)
		return (-1);

	if (a->sr_key > b->sr_key)
		return (1);

	return (0);
}

secadm_prison_entry_t *
get_prison_list_entry(int jid)
{
	secadm_prison_entry_t *entry;

	PL_RLOCK();
	SLIST_FOREACH(entry, &(secadm_prisons_list.sp_prison), sp_entries) {
		if (entry->sp_id == jid) {
			PL_RUNLOCK();
			return (entry);
		}
	}
	PL_RUNLOCK();

	entry = malloc(sizeof(secadm_prison_entry_t),
	    M_SECADM, M_WAITOK | M_ZERO);

	PE_INIT(entry);
	PE_WLOCK(entry);
	entry->sp_id = jid;
	RB_INIT(&(entry->sp_rules));
	RB_INIT(&(entry->sp_staging));
	PE_WUNLOCK(entry);

	PL_WLOCK();
	SLIST_INSERT_HEAD(&(secadm_prisons_list.sp_prison),
	    entry, sp_entries);
	PL_WUNLOCK();

	return (entry);
}

int
get_mntonname_vattr(struct thread *td, u_char *path, char *mntonname,
    struct vattr *vap)
{
	struct nameidata nd;
	int error = 1;

	if (path == NULL)
		return (error);

	if (path[0] != '/')
		return (error);

	NDINIT(&nd, LOOKUP, LOCKLEAF | FOLLOW, UIO_SYSSPACE, path, td);

	if ((error = namei(&nd))) {
		return (error);
	}

	strlcpy(mntonname,
	    nd.ni_vp->v_mount->mnt_stat.f_mntonname, MNAMELEN);

	error = VOP_GETATTR(nd.ni_vp, vap, td->td_ucred);

	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_vp);

	return (error);
}

void
kernel_free_rule(secadm_rule_t *rule)
{
	if (rule == NULL)
		return;

	switch (rule->sr_type) {
	case secadm_integriforce_rule:
		if (rule->sr_integriforce_data == NULL) {
			break;
		}

		if (rule->sr_integriforce_data->si_path) {
			free(rule->sr_integriforce_data->si_path, M_SECADM);
		}

		if (rule->sr_integriforce_data->si_hash) {
			free(rule->sr_integriforce_data->si_hash, M_SECADM);
		}

		free(rule->sr_integriforce_data, M_SECADM);
		break;

	case secadm_pax_rule:
		if (rule->sr_pax_data == NULL) {
			break;
		}

		if (rule->sr_pax_data->sp_path) {
			free(rule->sr_pax_data->sp_path, M_SECADM);
		}

		free(rule->sr_pax_data, M_SECADM);
		break;

	case secadm_extended_rule:
		if (rule->sr_extended_data == NULL) {
			break;
		}

		if (rule->sr_extended_data->sm_object.mo_path) {
			free(rule->sr_extended_data->sm_object.mo_path,
			    M_SECADM);
		}

		free(rule->sr_extended_data, M_SECADM);
	}

	free(rule, M_SECADM);
}

void
kernel_flush_ruleset(int jid)
{
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *next;

	entry = get_prison_list_entry(jid);

	PE_WLOCK(entry);
	for (r = RB_MIN(secadm_rules_tree, &(entry->sp_rules));
	    r != NULL; r = next) {
		next = RB_NEXT(secadm_rules_tree, &(entry->sp_rules), r);
		RB_REMOVE(secadm_rules_tree, &(entry->sp_rules), r);

		kernel_free_rule(r);
	}

	entry->sp_num_rules = 0;
	entry->sp_num_integriforce_rules = 0;
	entry->sp_num_pax_rules = 0;
	entry->sp_num_extended_rules = 0;
	PE_WUNLOCK(entry);
}

int
kernel_finalize_rule(struct thread *td, secadm_rule_t *rule, int ruleset)
{
	struct secadm_rules_tree *head;
	secadm_prison_entry_t *entry;
	secadm_rule_t *r;
	struct vattr vap;
	int error;

	switch (rule->sr_type) {
	case secadm_integriforce_rule:
		error = get_mntonname_vattr(td,
		    rule->sr_integriforce_data->si_path,
		    rule->sr_integriforce_data->si_mntonname, &vap);

		if (error) {
			return (error);
		}

		if (vap.va_type != VREG) {
#ifdef SECADM_DEBUG
			printf("[secadm debug] %s is not a regular file.\n",
			    rule->sr_integriforce_data->si_path);
#endif
			return (1);
		}

		rule->sr_integriforce_data->si_fileid = vap.va_fileid;
		break;

	case secadm_pax_rule:
		error = get_mntonname_vattr(td,
		    rule->sr_pax_data->sp_path,
		    rule->sr_pax_data->sp_mntonname, &vap);

		if (error) {
			return (error);
		}

		if (vap.va_type != VREG) {
			return (1);
		}

		rule->sr_pax_data->sp_fileid = vap.va_fileid;
		break;

	case secadm_extended_rule:
		/* TODO(bs): Implement extended (ugidfw) rules. */
		break;
	}

	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_id);

	PE_RLOCK(entry);
	if (ruleset == 1) {
		head = &(entry->sp_staging);
	} else {
		head = &(entry->sp_rules);
	}

	RB_FOREACH(r, secadm_rules_tree, head) {
		if (r->sr_type != rule->sr_type) {
			continue;
		}

		switch (r->sr_type) {
		case secadm_integriforce_rule:
			if (!strncmp(r->sr_integriforce_data->si_mntonname,
			    rule->sr_integriforce_data->si_mntonname,
			    MAXPATHLEN) && r->sr_integriforce_data->si_fileid ==
			    rule->sr_integriforce_data->si_fileid) {
#ifdef SECADM_DEBUG
				printf("[secadm debug] %s is the same as %s (or hash collision)\n", r->sr_integriforce_data->si_path,
				    rule->sr_integriforce_data->si_path);
#endif
				PE_RUNLOCK(entry);
				return (EEXIST);
			}

			break;

		case secadm_pax_rule:
			if (!strncmp(r->sr_pax_data->sp_mntonname,
			    rule->sr_pax_data->sp_mntonname,
			    MAXPATHLEN) && r->sr_pax_data->sp_fileid ==
			    rule->sr_pax_data->sp_fileid) {
				PE_RUNLOCK(entry);
				return (EEXIST);
			}

			break;

		case secadm_extended_rule:
			PE_RUNLOCK(entry);
			return (1);
		}
	}
	PE_RUNLOCK(entry);

	return (0);
}

int
kernel_load_ruleset(struct thread *td, secadm_rule_t *rule)
{
	secadm_rule_t *r = rule, *r2;
	secadm_prison_entry_t *entry;
	int err;

	r2 = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);

	do {
		if ((err = kernel_add_rule(td, r, 1))) {
			free(r2, M_SECADM);
			goto ruleset_load_fail;
		}

		if ((err = copyin(r, r2, sizeof(secadm_rule_t)))) {
			free(r2, M_SECADM);
			goto ruleset_load_fail;
		}

		r = r2->sr_next;
	} while (r != NULL);

	free(r2, M_SECADM);

	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_id);
	kernel_flush_ruleset(entry->sp_id);

	PE_WLOCK(entry);
	for (r = RB_MIN(secadm_rules_tree, &(entry->sp_staging));
	     r != NULL; r = r2) {
		r2 = RB_NEXT(secadm_rules_tree, &(entry->sp_staging), r);
		RB_REMOVE(secadm_rules_tree, &(entry->sp_staging), r);

		r->sr_id = entry->sp_last_id++;
		entry->sp_num_rules++;

		switch (r->sr_type) {
		case secadm_integriforce_rule:
			entry->sp_num_integriforce_rules++;
			break;

		case secadm_pax_rule:
			entry->sp_num_pax_rules++;
			break;

		case secadm_extended_rule:
			entry->sp_num_extended_rules++;
			break;
		}

		RB_INSERT(secadm_rules_tree, &(entry->sp_rules), r);
	}

	entry->sp_loaded = 1;
	PE_WUNLOCK(entry);

	return (0);

ruleset_load_fail:
	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_id);

	PE_WLOCK(entry);
	for (r = RB_MIN(secadm_rules_tree, &(entry->sp_staging));
	     r != NULL; r = r2) {
		r2 = RB_NEXT(secadm_rules_tree, &(entry->sp_staging), r);
		RB_REMOVE(secadm_rules_tree, &(entry->sp_staging), r);

		kernel_free_rule(r);
	}
	PE_WUNLOCK(entry);

	return (err);
}

int
kernel_add_rule(struct thread *td, secadm_rule_t *rule, int ruleset)
{
	secadm_prison_entry_t *entry;
	u_char *path, *hash;
	secadm_key_t key;
	secadm_rule_t *r;
	void *ptr;
	int error;

	r = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK | M_ZERO);

	if (copyin(rule, r, sizeof(secadm_rule_t))) {
		free(r, M_SECADM);
		return (EINVAL);
	}

	switch (r->sr_type) {
	case secadm_integriforce_rule:
		ptr = malloc(sizeof(secadm_integriforce_data_t),
		    M_SECADM, M_WAITOK);

		if (copyin(r->sr_integriforce_data, ptr,
		    sizeof(secadm_integriforce_data_t))) {
			r->sr_integriforce_data = NULL;
			free(ptr, M_SECADM);
			free(r, M_SECADM);

			return (EINVAL);
		}

		r->sr_integriforce_data = ptr;

		if (r->sr_integriforce_data->si_pathsz == 0 ||
		    r->sr_integriforce_data->si_pathsz >= MAXPATHLEN) {
			memset(r->sr_integriforce_data, 0x00,
			    sizeof(secadm_integriforce_data_t));
			kernel_free_rule(r);

			return (EINVAL);
		}

		path = malloc(r->sr_integriforce_data->si_pathsz + 1,
		    M_SECADM, M_WAITOK);

		if (copyin(r->sr_integriforce_data->si_path, path,
		    r->sr_integriforce_data->si_pathsz)) {
			memset(r->sr_integriforce_data, 0x00,
			    sizeof(secadm_integriforce_data_t));
			free(path, M_SECADM);
			kernel_free_rule(r);

			return (EINVAL);
		}

		path[r->sr_integriforce_data->si_pathsz] = '\0';
		r->sr_integriforce_data->si_path = path;

		switch (r->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			hash = malloc(SECADM_SHA1_DIGEST_LEN,
			    M_SECADM, M_WAITOK);

			if (copyin(r->sr_integriforce_data->si_hash, hash,
			    SECADM_SHA1_DIGEST_LEN)) {
				r->sr_integriforce_data->si_hash = NULL;
				free(hash, M_SECADM);
				kernel_free_rule(r);

				return (EINVAL);
			}

			break;

		case secadm_hash_sha256:
			hash = malloc(SECADM_SHA256_DIGEST_LEN,
			    M_SECADM, M_WAITOK);

			if (copyin(r->sr_integriforce_data->si_hash, hash,
			    SECADM_SHA256_DIGEST_LEN)) {
				r->sr_integriforce_data->si_hash = NULL;
				free(hash, M_SECADM);
				kernel_free_rule(r);

				return (EINVAL);
			}

			break;

		default:
			kernel_free_rule(r);
			return (EINVAL);
		}

		r->sr_integriforce_data->si_hash = hash;
		r->sr_integriforce_data->si_cache = 0;

		if (!(rule->sr_integriforce_data->si_mode == 0 ||
		    rule->sr_integriforce_data->si_mode == 1)) {
			kernel_free_rule(r);
			return (EINVAL);
		}

		break;

	case secadm_pax_rule:
		ptr = malloc(sizeof(secadm_pax_data_t), M_SECADM, M_WAITOK);

		if (copyin(r->sr_pax_data, ptr,
		    sizeof(secadm_pax_data_t))) {
			free(ptr, M_SECADM);
			free(r, M_SECADM);

			return (EINVAL);
		}

		r->sr_pax_data = ptr;

		if (!(r->sr_pax_data->sp_pax_set)) {
			r->sr_pax_data->sp_path = NULL;
			kernel_free_rule(r);
			return (EINVAL);
		}

		if (r->sr_pax_data->sp_pathsz == 0 ||
		    r->sr_pax_data->sp_pathsz >= MAXPATHLEN) {
			r->sr_pax_data->sp_path = NULL;
			kernel_free_rule(r);
			return (EINVAL);
		}

		path = malloc(r->sr_pax_data->sp_pathsz + 1,
		    M_SECADM, M_WAITOK);

		if (copyin(r->sr_pax_data->sp_path, path,
		    r->sr_pax_data->sp_pathsz)) {
			r->sr_pax_data->sp_path = NULL;
			free(path, M_SECADM);
			kernel_free_rule(r);

			return (EINVAL);
		}

		path[r->sr_pax_data->sp_pathsz] = '\0';
		r->sr_pax_data->sp_path = path;

		if (r->sr_pax_data->sp_pax_set &
		    SECADM_PAX_MPROTECT_SET) {
			if (r->sr_pax_data->sp_pax & SECADM_PAX_MPROTECT) {
				r->sr_pax_data->sp_pax |=
				    SECADM_PAX_PAGEEXEC;
				r->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_PAGEEXEC_SET;
			}
		}

		if (r->sr_pax_data->sp_pax_set &
		    SECADM_PAX_PAGEEXEC_SET) {
			if (!(r->sr_pax_data->sp_pax &
			    SECADM_PAX_PAGEEXEC)) {
				r->sr_pax_data->sp_pax &=
				    ~(SECADM_PAX_MPROTECT);
				r->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MPROTECT_SET;
			}
		}

		break;

	case secadm_extended_rule:
		r->sr_extended_data = NULL;
		printf("bsdextended rules not supported yet.\n");

	default:
		kernel_free_rule(r);
		return (EINVAL);
	}

	if ((error = kernel_finalize_rule(td, r, ruleset))) {
		if (r->sr_type == secadm_integriforce_rule) {
			if (error == EEXIST) {
				error = 0;
			}
		}

		kernel_free_rule(r);
		return (error);
	}

	r->sr_active = 1;
	r->sr_jid = td->td_ucred->cr_prison->pr_id;

	switch (r->sr_type) {
	case secadm_integriforce_rule:
		key.sk_jid = r->sr_jid;
		key.sk_type = secadm_integriforce_rule;
		key.sk_fileid = r->sr_integriforce_data->si_fileid;
		strncpy(key.sk_mntonname,
		    r->sr_integriforce_data->si_mntonname, MNAMELEN);

		break;

	case secadm_pax_rule:
		key.sk_jid = r->sr_jid;
		key.sk_type = secadm_pax_rule;
		key.sk_fileid = r->sr_pax_data->sp_fileid;
		strncpy(key.sk_mntonname,
		    r->sr_pax_data->sp_mntonname, MNAMELEN);

		break;

	case secadm_extended_rule:
		kernel_free_rule(r);
		return (EINVAL);
	}

	r->sr_key = fnv_32_buf(&key, sizeof(secadm_key_t), FNV1_32_INIT);
	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_id);

	PE_WLOCK(entry);
	if (ruleset == 1) {
		RB_INSERT(secadm_rules_tree, &(entry->sp_staging), r);
	} else {
		r->sr_id = entry->sp_last_id++;
		entry->sp_num_rules++;

		switch (r->sr_type) {
		case secadm_integriforce_rule:
			entry->sp_num_integriforce_rules++;
			break;

		case secadm_pax_rule:
			entry->sp_num_pax_rules++;
			break;

		case secadm_extended_rule:
			entry->sp_num_extended_rules++;
			break;
		}

		RB_INSERT(secadm_rules_tree, &(entry->sp_rules), r);
	}
	PE_WUNLOCK(entry);

	return (0);
}

void
kernel_del_rule(struct thread *td, secadm_rule_t *rule)
{
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *v, *next;

	r = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);

	if (copyin(rule, r, sizeof(secadm_rule_t))) {
		kernel_free_rule(r);
		return;
	}

	entry = get_prison_list_entry(
	    td->td_ucred->cr_prison->pr_id);

	PE_WLOCK(entry);
	for (v = RB_MIN(secadm_rules_tree, &(entry->sp_rules));
	    v != NULL; v = next) {
		next = RB_NEXT(secadm_rules_tree, &(entry->sp_rules), v);

		if (r->sr_id == v->sr_id) {
			RB_REMOVE(secadm_rules_tree, &(entry->sp_rules), v);
			entry->sp_num_rules--;

			switch (v->sr_type) {
			case secadm_integriforce_rule:
				entry->sp_num_integriforce_rules--;
				break;

			case secadm_extended_rule:
				entry->sp_num_extended_rules--;
				break;

			case secadm_pax_rule:
				entry->sp_num_pax_rules--;
				break;
			}

			kernel_free_rule(v);
			break;
		}
	}
	PE_WUNLOCK(entry);

	free(r, M_SECADM);
}

void
kernel_active_rule(struct thread *td, secadm_rule_t *rule, int active)
{
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *v;

	r = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);

	if (copyin(rule, r, sizeof(secadm_rule_t))) {
		kernel_free_rule(r);
		return;
	}

	entry = get_prison_list_entry(
	    td->td_ucred->cr_prison->pr_id);

	PE_WLOCK(entry);
	RB_FOREACH(v, secadm_rules_tree, &(entry->sp_rules)) {
		if (r->sr_id == v->sr_id) {
			v->sr_active = active;
			break;
		}
	}
	PE_WUNLOCK(entry);

	free(r, M_SECADM);
}

secadm_rule_t *
kernel_get_rule(struct thread *td, secadm_rule_t *rule)
{
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *v;
	int found = 0;

	r = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);

	if (copyin(rule, r, sizeof(secadm_rule_t))) {
		kernel_free_rule(r);
		return (NULL);
	}

	entry = get_prison_list_entry(
	    td->td_ucred->cr_prison->pr_id);

	PE_RLOCK(entry);
	RB_FOREACH(v, secadm_rules_tree, &(entry->sp_rules)) {
		if (v->sr_id == r->sr_id) {
			found = 1;
			break;
		}
	}
	PE_RUNLOCK(entry);

	free(r, M_SECADM);

	if (found) {
		return (v);
	}

	return (NULL);
}
