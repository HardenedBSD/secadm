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
#include <sys/rmlock.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

MALLOC_DEFINE(M_SECADM, "secadm", "secadm rule data");

secadm_kernel_t kernel_data;

secadm_prison_list_t *
get_prison_list_entry(const char *name, int create)
{
	secadm_prison_list_t *list, *entry;
	struct rm_priotracker tracker;

	rm_rlock(&(kernel_data.skd_prisons_lock), &tracker);

	for (list = kernel_data.skd_prisons; list != NULL; list = list->spl_next) {
		if (!strcmp(list->spl_prison, name)) {
			rm_runlock(&(kernel_data.skd_prisons_lock), &tracker);
			return (list);
		}
	}

	rm_runlock(&(kernel_data.skd_prisons_lock), &tracker);

	if (create) {
		list = malloc(sizeof(secadm_prison_list_t), M_SECADM, M_WAITOK | M_ZERO);

		rm_init(&(list->spl_lock), "secadm per-prison lock");
		list->spl_prison = malloc(strlen(name)+1, M_SECADM, M_WAITOK | M_ZERO);
		strlcpy(list->spl_prison, name, strlen(name)+1);

		rm_wlock(&(kernel_data.skd_prisons_lock));

		if (kernel_data.skd_prisons == NULL) {
			kernel_data.skd_prisons = list;
		} else {
			for (entry = kernel_data.skd_prisons; entry->spl_next != NULL; entry = entry->spl_next)
				;

			entry->spl_next = list;
			list->spl_prev = entry;
		}

		rm_wunlock(&(kernel_data.skd_prisons_lock));
	}

	return (list);
}

int
pre_validate_rule(struct thread *td, secadm_rule_t *rule)
{
	KASSERT(rule != NULL, ("validate_rule: rule cannot be null!"));

	if (rule->sr_features == NULL || rule->sr_nfeatures == 0
	    || rule->sr_nfeatures > SECADM_MAX_FEATURES) {
		return (-1);
	}

	if (rule->sr_path != NULL && rule->sr_pathlen > MNAMELEN)
		return (-1);

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
			return (-1);

		if (rule->sr_id > maxid)
			maxid = rule->sr_id;

		nrules++;
	}

	if (maxid > nrules)
		return (-1);

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
	secadm_prison_list_t *list;
	secadm_rule_t *rule=NULL;
	struct rm_priotracker prisons_tracker, rule_tracker;

	rm_rlock(&(kernel_data.skd_prisons_lock), &prisons_tracker);

	for (list = kernel_data.skd_prisons; list != NULL; list = list->spl_next)
		if (!strcmp(list->spl_prison, pr->pr_name))
			break;

	if (list != NULL) {
		rm_rlock(&(list->spl_lock), &rule_tracker);
		rule = list->spl_rules;
		rm_runlock(&(list->spl_lock), &rule_tracker);
	}

	rm_runlock(&(kernel_data.skd_prisons_lock), &prisons_tracker);

	return (rule);
}

void
cleanup_jail_rules(secadm_prison_list_t *list)
{
	secadm_rule_t *rule, *next;

	rm_wlock(&(list->spl_lock));

	if (list == kernel_data.skd_prisons)
		kernel_data.skd_prisons = list->spl_next;

	if (list->spl_prev != NULL)
		list->spl_prev->spl_next = list->spl_next;
	if (list->spl_next != NULL)
		list->spl_next->spl_prev = list->spl_prev;

	rule = list->spl_rules;
	while (rule != NULL) {
		next = rule->sr_next;
		free_rule(rule, 1);
		rule = next;
	}

	rm_wunlock(&(list->spl_lock));

	rm_destroy(&(list->spl_lock));

	free(list->spl_prison, M_SECADM);
	free(list, M_SECADM);
}

void
flush_rules(struct thread *td)
{
	secadm_prison_list_t *list;
	secadm_rule_t *rule, *next;

	list = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 0);
	if (list == NULL)
		return;

	rm_wlock(&(list->spl_lock));

	rule = list->spl_rules;
	while (rule != NULL) {
		next = rule->sr_next;
		free_rule(rule, 1);
		rule = next;
	}

	list->spl_rules = NULL;

	rm_wunlock(&(list->spl_lock));
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
	return (-1);
}

secadm_rule_t
*get_rule_by_id(struct thread *td, size_t id)
{
	struct rm_priotracker tracker;
	secadm_prison_list_t *list;
	secadm_rule_t *rule;

	rule = get_first_rule(td);
	if (rule == NULL)
		return (NULL);

	list = get_prison_list_entry(rule->sr_prison, 0);
	if (list == NULL)
		return (NULL);

	rm_rlock(&(list->spl_lock), &tracker);

	for ( ; rule != NULL; rule = rule->sr_next) {
		if (rule->sr_id == id) {
			rm_runlock(&(list->spl_lock), &tracker);
			return (rule);
		}
	}

	rm_runlock(&(list->spl_lock), &tracker);

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

	if ((err = copyin(cmd->sc_buf, &id, sizeof(size_t))))
		return (err);

	size = get_rule_size(td, id);

	if ((err = copyout(&size, reply->sr_metadata, sizeof(size_t))))
		reply->sr_code = err;

	return (0);
}

int
get_num_rules(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	secadm_prison_list_t *list;
	size_t nrules;
	int err;

	if (reply->sr_size < sizeof(size_t))
		return (EINVAL);

	list = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 0);
	nrules = (list != NULL) ? list->spl_max_id : 0;

	if ((err = copyout(&nrules, reply->sr_metadata, sizeof(size_t))))
		reply->sr_code = err;

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
	if ((err = copyin(cmd->sc_buf, &id, sizeof(size_t))))
		return (err);

	rule = get_rule_by_id(td, id);
	if (rule == NULL)
		return (ENOENT);

	size = get_rule_size(td, id);
	if (size == 0)
		return (ENOENT);

	if (reply->sr_size < size)
		return (EOVERFLOW);

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

	return (0);
}

void log_location(const char *name, int line)
{
	printf("Here: %s : %d\n", name, line);
	uprintf("Here: %s : %d\n", name, line);
}
