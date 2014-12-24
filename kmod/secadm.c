/*-
 * Copyright (c) 2014 Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

MALLOC_DEFINE(M_SECADM, "secadm", "secadm rule data");

secadm_kernel_t kernel_data;

struct secadm_prison_entry *
get_prison_list_entry(const char *name, int create)
{
	struct secadm_prison_entry *entry;
	struct rm_priotracker tracker;

	SKD_RLOCK(tracker);
	SLIST_FOREACH(entry, &(kernel_data.skd_prisons), spl_entries) {
		if (!strcmp(entry->spl_prison, name)) {
			SKD_RUNLOCK(tracker);
			return (entry);
		}
	}
	SKD_RUNLOCK(tracker);

	if (create) {
		entry = malloc(sizeof(struct secadm_prison_entry),
		    M_SECADM, M_WAITOK | M_ZERO);

		SPL_INIT(entry, "secadm per-prison lock");

		entry->spl_prison = malloc(strlen(name)+1,
		    M_SECADM, M_WAITOK | M_ZERO);
		strlcpy(entry->spl_prison, name, strlen(name)+1);


		SKD_WLOCK();
		/*
		 * this inserts to list's head, rather then the
		 * list tail, as in previous implementation
		 */
		SLIST_INSERT_HEAD(&(kernel_data.skd_prisons), entry,
		    spl_entries);

		SKD_WUNLOCK();
	}

	return (entry);
}

int
pre_validate_rule(struct thread *td, secadm_rule_t *rule)
{
	KASSERT(rule != NULL, ("validate_rule: rule cannot be null!"));

	if (rule->sr_features == NULL || rule->sr_nfeatures == 0
	    || rule->sr_nfeatures > SECADM_MAX_FEATURES) {
		return (1);
	}

	if (rule->sr_path != NULL && rule->sr_pathlen > MNAMELEN)
		return (1);

	return (0);
}

int
validate_ruleset(struct thread *td, secadm_rule_t *head)
{
	secadm_rule_t *rule;
	size_t nrules, maxid;

	nrules = maxid = 0;
	for (rule = head; rule != NULL; rule = rule->sr_next) {
		if (pre_validate_rule(td, rule))
			return (1);

		if (rule->sr_id > maxid)
			maxid = rule->sr_id;

		nrules++;
	}

	if (maxid > nrules)
		return (1);

	return (0);
}

void
free_rule(secadm_rule_t *rule, int freerule)
{
	size_t i;
	
	if (rule->sr_path)
		free(rule->sr_path, M_SECADM);

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].metadata)
			free(rule->sr_features[i].metadata, M_SECADM);

	if (rule->sr_features)
		free(rule->sr_features, M_SECADM);

	if (rule->sr_prison != NULL)
		free(rule->sr_prison, M_SECADM);

	if (rule->sr_kernel != NULL)
		free(rule->sr_kernel, M_SECADM);

	if (freerule)
		free(rule, M_SECADM);
}

secadm_rule_t *
get_first_rule(struct thread *td)
{

	return (get_first_prison_rule(td->td_ucred->cr_prison));
}

secadm_rule_t *
get_first_prison_rule(struct prison *pr)
{
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule;
	struct rm_priotracker prisons_tracker, rule_tracker;

	rule = NULL;

	SKD_RLOCK(prisons_tracker);
	SLIST_FOREACH(entry, &(kernel_data.skd_prisons), spl_entries)
		if (!strcmp(entry->spl_prison, pr->pr_name))
			break;

	if (entry != NULL) {
		SPL_RLOCK(entry, rule_tracker);
		rule = entry->spl_rules;
		SPL_RUNLOCK(entry, rule_tracker);
	}
	SKD_RUNLOCK(prisons_tracker);

	return (rule);
}

void
cleanup_jail_rules(struct secadm_prison_entry *entry)
{
	secadm_rule_t *rule, *next;
	struct secadm_prison_entry *tmp;

	SKD_WLOCK();
	tmp = SLIST_FIRST(&(kernel_data.skd_prisons));
	if (entry == tmp)
		SLIST_REMOVE_HEAD(&(kernel_data.skd_prisons), spl_entries);
	else
		SLIST_REMOVE(&(kernel_data.skd_prisons), tmp,
		    secadm_prison_entry, spl_entries);
	SKD_WUNLOCK();

	SPL_WLOCK(tmp);
	// XXXOP: queue macros in rules too?
	rule = entry->spl_rules;
	while (rule != NULL) {
		next = rule->sr_next;
		free_rule(rule, 1);
		rule = next;
	}
	SPL_WUNLOCK(tmp);
	SPL_DESTROY(tmp);

	free(tmp->spl_prison, M_SECADM);
	free(tmp, M_SECADM);
}

void
flush_rules(struct thread *td)
{
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule, *next;

	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 0);
	if (entry == NULL)
		return;

	SPL_WLOCK(entry);
	rule = entry->spl_rules;
	while (rule != NULL) {
		next = rule->sr_next;
		free_rule(rule, 1);
		rule = next;
	}

	entry->spl_rules = NULL;
	SPL_WUNLOCK(entry);
}

int
read_rule_from_userland(struct thread *td, secadm_rule_t *rule)
{
	secadm_feature_t *features;
	secadm_kernel_metadata_t *kernel_metadata;
	size_t i;
	int err = 0;
	char *path;

	rule->sr_mount[MNAMELEN-1] = '\0';

	if (pre_validate_rule(td, rule))
		goto error;

	features = malloc(sizeof(secadm_feature_t) *
	    rule->sr_nfeatures, M_SECADM, M_WAITOK);

	err = copyin(rule->sr_features, features,
	    sizeof(secadm_feature_t) * rule->sr_nfeatures);
	if (err) {
		free(features, M_SECADM);
		goto error;
	}

	for (i=0; i<rule->sr_nfeatures; i++) {
		/* We have no features that require extra metadata */
		features[i].metadata = NULL;
		features[i].metadatasz = 0;
	}

	rule->sr_features = features;

	if (rule->sr_path && rule->sr_pathlen) {
		path = malloc(rule->sr_pathlen+1, M_SECADM, M_WAITOK | M_ZERO);
		err = copyin(rule->sr_path, path, rule->sr_pathlen);
		if (err) {
			free(path, M_SECADM);
			goto error;
		}

		path[rule->sr_pathlen] = '\0';
		rule->sr_path = path;
	} else {
		rule->sr_path = NULL;
		rule->sr_pathlen = 0;
	}

	kernel_metadata = malloc(sizeof(secadm_kernel_metadata_t), M_SECADM, M_WAITOK);
	kernel_metadata->skm_owner = td->td_ucred->cr_prison;
	rule->sr_kernel = kernel_metadata;
	rule->sr_prison = malloc(strlen(kernel_metadata->skm_owner->pr_name)+1,
	    M_SECADM, M_WAITOK | M_ZERO);
	strcpy(rule->sr_prison, kernel_metadata->skm_owner->pr_name);

	return (0);

error:
	rule->sr_path = NULL;
	rule->sr_pathlen = 0;
	rule->sr_features = NULL;
	rule->sr_nfeatures = 0;
	rule->sr_prison = NULL;
	rule->sr_kernel = NULL;
	return (1);
}

secadm_rule_t
*get_rule_by_id(struct thread *td, size_t id)
{
	struct rm_priotracker tracker;
	struct secadm_prison_entry *entry;
	secadm_rule_t *rule;

	rule = get_first_rule(td);
	if (rule == NULL)
		return (NULL);

	entry = get_prison_list_entry(rule->sr_prison, 0);
	if (entry == NULL)
		return (NULL);

	SPL_RLOCK(entry, tracker);
	for ( ; rule != NULL; rule = rule->sr_next) {
		if (rule->sr_id == id) {
			SPL_RUNLOCK(entry, tracker);
			return (rule);
		}
	}
	SPL_RUNLOCK(entry, tracker);

	return (NULL);
}

size_t
get_rule_size(struct thread *td, size_t id)
{
	secadm_rule_t *rule;
	size_t size, i;

	size = 0;
	rule = get_rule_by_id(td, id);
	if (rule == NULL)
		goto end;

	size += sizeof(secadm_rule_t);
	size += rule->sr_pathlen+1;
	size += sizeof(secadm_feature_t) * rule->sr_nfeatures;
	size += strlen(rule->sr_prison)+1;

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].metadata)
			size += rule->sr_features[i].metadatasz;
end:
	return (size);
}

int
handle_get_rule_size(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	size_t id, size;
	int err;

	if (reply->sr_size < sizeof(size_t) || cmd->sc_bufsize != sizeof(size_t))
		return (EINVAL);

	if ((err = copyin(cmd->sc_buf, &id, sizeof(size_t)))) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = err;
		return (err);
	}

	size = get_rule_size(td, id);

	if ((err = copyout(&size, reply->sr_metadata, sizeof(size_t)))) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = err;
	}

	return (0);
}

int
get_num_rules(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	struct secadm_prison_entry *entry;
	size_t nrules;
	int err;
	struct rm_priotracker tracker;

	if (reply->sr_size < sizeof(size_t))
		return (EINVAL);

	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 0);
	nrules = (entry != NULL) ? entry->spl_max_id : 0;
	if (entry != NULL) {
		SPL_RLOCK(entry, tracker);
		nrules = entry->spl_max_id;
		SPL_RUNLOCK(entry, tracker);
	} else
		nrules = 0;

	if ((err = copyout(&nrules, reply->sr_metadata, sizeof(size_t)))) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = err;
	}

	return (0);
}

int
handle_get_rule(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	secadm_rule_t *rule, *newrule;
	secadm_feature_t *newrule_features;
	size_t id, size, written, i;
	char *buf, *path;
	int err;

	if (cmd->sc_bufsize != sizeof(size_t))
		return (EINVAL);

	/*
	 * Get the requested rule ID and ensure the userland buffer
	 * can hold the rule
	 */
	if ((err = copyin(cmd->sc_buf, &id, sizeof(size_t)))) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = err;
		return (err);
	}

	rule = get_rule_by_id(td, id);
	if (rule == NULL) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = ENOENT;
		return (1);
	}

	size = get_rule_size(td, id);
	if (size == 0) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = ENOENT;
		return (1);
	}

	if (reply->sr_size < size) {
		reply->sr_code = secadm_fail;
		reply->sr_errno = EOVERFLOW;
		return (1);
	}

	written=0;
	buf = malloc(size, M_SECADM, M_WAITOK);

	memcpy(buf, rule, sizeof(secadm_rule_t));
	newrule = (secadm_rule_t *)buf;
	written += sizeof(secadm_rule_t);

	/* Sanitize sensitive data */
	newrule->sr_next = NULL;
	newrule->sr_kernel = NULL;

	newrule->sr_features = (secadm_feature_t *)(buf+written);
	newrule_features = (secadm_feature_t *)((char *)(reply->sr_metadata) + written);
	written += sizeof(secadm_feature_t) * rule->sr_nfeatures;

	for (i=0; i < rule->sr_nfeatures; i++)
		memcpy(&(newrule->sr_features[i]), &rule->sr_features[i], sizeof(secadm_feature_t));

	newrule->sr_features = newrule_features;

	if (rule->sr_pathlen) {
		path = buf + written;
		memcpy(path, rule->sr_path, rule->sr_pathlen+1);
		newrule->sr_path = (char *)(reply->sr_metadata) + written;
		written += rule->sr_pathlen + 1;
	}

	newrule->sr_prison = (char *)(reply->sr_metadata) + written;
	memcpy(buf + written, rule->sr_prison, strlen(rule->sr_prison)+1);
	written += strlen(rule->sr_prison)+1;

	copyout(newrule, reply->sr_metadata, size);

	free(buf, M_SECADM);

	reply->sr_code = secadm_success;
	reply->sr_errno = 0;

	return (0);
}

void log_location(const char *name, int line)
{
	printf("Here: %s : %d\n", name, line);
	uprintf("Here: %s : %d\n", name, line);
}
