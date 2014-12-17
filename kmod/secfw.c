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

#include "secfw.h"

MALLOC_DEFINE(M_SECFW, "secfw", "secfw rule data");

secfw_kernel_t rules;

void
secfw_lock_init(void)
{
	rm_init(&(rules.rules_lock), "mac_secfw rules lock");
	rm_init(&(rules.admins_lock), "mac_secfw admins lock");
	rm_init(&(rules.views_lock), "mac_secfw views lock");
	memset(&(rules.rules_tracker), 0x00, sizeof(struct rm_priotracker));
	memset(&(rules.admins_tracker), 0x00, sizeof(struct rm_priotracker));
	memset(&(rules.views_tracker), 0x00, sizeof(struct rm_priotracker));
}

void
secfw_lock_destroy(void)
{
	rm_destroy(&(rules.rules_lock));
	rm_destroy(&(rules.admins_lock));
	rm_destroy(&(rules.views_lock));
}

void
secfw_rules_lock_read(void)
{
	rm_rlock(&(rules.rules_lock), &(rules.rules_tracker));
}

void
secfw_rules_unlock_read(void)
{
	rm_runlock(&(rules.rules_lock), &(rules.rules_tracker));
}

void
secfw_rules_lock_write(void)
{
	rm_wlock(&(rules.rules_lock));
}

void
secfw_rules_unlock_write(void)
{
	rm_wunlock(&(rules.rules_lock));
}

void
secfw_admins_lock_read(void)
{
	rm_rlock(&(rules.admins_lock), &(rules.admins_tracker));
}

void
secfw_admins_unlock_read(void)
{
	rm_runlock(&(rules.admins_lock), &(rules.admins_tracker));
}

void
secfw_admins_lock_write(void)
{
	rm_wlock(&(rules.admins_lock));
}

void
secfw_admins_unlock_write(void)
{
	rm_wunlock(&(rules.admins_lock));
}

void
secfw_views_lock_read(void)
{
	rm_rlock(&(rules.views_lock), &(rules.views_tracker));
}

void
secfw_views_unlock_read(void)
{
	rm_runlock(&(rules.views_lock), &(rules.views_tracker));
}

void
secfw_views_lock_write(void)
{
	rm_wlock(&(rules.views_lock));
}

void
secfw_views_unlock_write(void)
{
	rm_wunlock(&(rules.views_lock));
}

int
validate_rule(struct thread *td, secfw_rule_t *head, secfw_rule_t *rule)
{
	KASSERT(rule != NULL, ("validate_rule: rule cannot be null!"));

	if (rule->sr_nfeatures == 0)
		return (1);

	return (0);
}

void
free_rule(secfw_rule_t *rule, int freerule)
{
	size_t i;
	
	if (rule->sr_path)
		free(rule->sr_path, M_SECFW);

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].metadata)
			free(rule->sr_features[i].metadata, M_SECFW);

	if (rule->sr_features)
		free(rule->sr_features, M_SECFW);

	free(rule->sr_prison, M_SECFW);
	free(rule->sr_kernel, M_SECFW);

	if (freerule)
		free(rule, M_SECFW);
}

secfw_rule_t *
get_first_rule(struct thread *td)
{
	secfw_rule_t *rule;

	for (rule = rules.rules; rule != NULL; rule = rule->sr_next)
		if (td == NULL || !strcmp(rule->sr_prison, td->td_ucred->cr_prison->pr_name))
			return rule;

	return NULL;
}

secfw_rule_t *
get_first_prison_rule(struct prison *pr)
{
	secfw_rule_t *rule;

	for (rule = rules.rules; rule != NULL; rule = rule->sr_next)
		if (!strcmp(rule->sr_prison, pr->pr_name))
			return rule;

	return NULL;
}

void
cleanup_jail_rules(struct prison *pr)
{
	secfw_rule_t *prev, *rule;

	while ((rule = get_first_prison_rule(pr)) != NULL) {
		if (rule == rules.rules) {
			rules.rules = rule->sr_next;
			free_rule(rule, 1);
		} else {
			prev = rules.rules;
			while (prev->sr_next != rule)
				prev = prev->sr_next;

			prev->sr_next = rule->sr_next;
			free_rule(rule, 1);
		}
	}
}

void
flush_rules(struct thread *td)
{
	secfw_rule_t *prev, *rule;

	while ((rule = get_first_rule(td)) != NULL) {
		if (rule == rules.rules) {
			rules.rules = rule->sr_next;
			free_rule(rule, 1);
		} else {
			prev = rules.rules;
			while (prev->sr_next != rule)
				prev = prev->sr_next;

			prev->sr_next = rule->sr_next;
			free_rule(rule, 1);
		}
	}
}

/* XXX This is more of a PoC. This needs to be cleaned up for
 * production use */
int
read_rule_from_userland(struct thread *td, secfw_rule_t *rule)
{
	secfw_rule_t *newrule, *next;
	secfw_feature_t *features;
	secfw_kernel_metadata_t *kernel_metadata;
	void *metadata;
	size_t i, j;
	int err = 0;
	char *path;

	if (rule->sr_features == NULL || rule->sr_nfeatures == 0) {
		return (-1);
	}

	features = malloc(sizeof(secfw_feature_t) *
	    rule->sr_nfeatures, M_SECFW, M_WAITOK);

	err = copyin(rule->sr_features, features,
	    sizeof(secfw_feature_t) * rule->sr_nfeatures);
	if (err) {
		free(features, M_SECFW);
		return (-1);
	}

	for (i=0; i<rule->sr_nfeatures; i++) {
		if (features[i].metadata && features[i].metadatasz) {
			metadata = malloc(features[i].metadatasz,
			    M_SECFW, M_WAITOK | M_ZERO);

			err = copyin(features[i].metadata, metadata,
			    features[i].metadatasz);
			if (err) {
				for (j=0; j < i; j++) {
					free(features[j].metadata,
					    M_SECFW);
				}

				free(features, M_SECFW);
				return (-1);
			}
		} else {
			features[i].metadata = NULL;
			features[i].metadatasz = 0;
		}
	}

	rule->sr_features = features;

	if (rule->sr_path && rule->sr_pathlen) {
		path = malloc(rule->sr_pathlen+1, M_SECFW, M_WAITOK | M_ZERO);
		err = copyin(rule->sr_path, path, rule->sr_pathlen);
		if (err) {
			rule->sr_path = NULL;
			free_rule(rule, 0);
			return (-1);
		}

		rule->sr_path = path;
	} else {
		rule->sr_path = NULL;
		rule->sr_pathlen = 0;
	}

	kernel_metadata = malloc(sizeof(secfw_kernel_metadata_t), M_SECFW, M_WAITOK);
	kernel_metadata->skm_owner = td->td_ucred->cr_prison;
	rule->sr_kernel = kernel_metadata;
	rule->sr_prison = malloc(strlen(kernel_metadata->skm_owner->pr_name)+1, M_SECFW, M_WAITOK | M_ZERO);
	strcpy(rule->sr_prison, kernel_metadata->skm_owner->pr_name);

	if (validate_rule(td, rules.rules, rule)) {
		free_rule(rule, 0);
		return (EINVAL);
	}

	next = rule->sr_next;
	if (next) {
		newrule = malloc(sizeof(secfw_rule_t), M_SECFW, M_WAITOK);
		err = copyin(next, newrule, sizeof(secfw_rule_t));
		if (err) {
			free(newrule, M_SECFW);
			rule->sr_next = NULL;
			return 0;
		}

		if (read_rule_from_userland(td, newrule)) {
			free(newrule, M_SECFW);
			rule->sr_next = NULL;
			return 0;
		}

		rule->sr_next = newrule;
	}

	return 0;
}

secfw_rule_t
*get_rule_by_id(struct thread *td, size_t id)
{
	secfw_rule_t *rule;

	for (rule = rules.rules; rule != NULL; rule = rule->sr_next)
		if (rule->sr_id == id)
			if (!strcmp(rule->sr_prison, td->td_ucred->cr_prison->pr_name))
				return rule;

	return NULL;
}

size_t
get_rule_size(struct thread *td, size_t id)
{
	secfw_rule_t *rule;
	size_t size, i;

	size = 0;
	rule = get_rule_by_id(td, id);
	if (rule == NULL)
		goto end;

	size += sizeof(secfw_rule_t);
	size += rule->sr_pathlen+1;
	size += sizeof(secfw_feature_t) * rule->sr_nfeatures;
	size += strlen(rule->sr_prison)+1;

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].metadata)
			size += rule->sr_features[i].metadatasz;
end:
	return (size);
}

int
handle_get_rule_size(struct thread *td, secfw_command_t *cmd, secfw_reply_t *reply)
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

	return 0;
}

int
get_num_rules(struct thread *td, secfw_command_t *cmd, secfw_reply_t *reply)
{
	secfw_rule_t *rule;
	size_t nrules;
	int err;

	if (reply->sr_size < sizeof(size_t))
		return (EINVAL);

	nrules=0;
	for (rule = rules.rules; rule != NULL; rule = rule->sr_next) {
		if (!strcmp(rule->sr_prison, td->td_ucred->cr_prison->pr_name))
			nrules++;
	}

	if ((err = copyout(&nrules, reply->sr_metadata, sizeof(size_t))))
		reply->sr_code = err;

	return 0;
}

int
handle_get_rule(struct thread *td, secfw_command_t *cmd, secfw_reply_t *reply)
{
	secfw_rule_t *rule, *newrule;
	secfw_feature_t *newrule_features;
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
	buf = malloc(size, M_SECFW, M_WAITOK);

	memcpy(buf, rule, sizeof(secfw_rule_t));
	newrule = (secfw_rule_t *)buf;
	written += sizeof(secfw_rule_t);

	/* Sanitize sensitive data */
	newrule->sr_next = NULL;
	newrule->sr_kernel = NULL;

	newrule->sr_features = (secfw_feature_t *)(buf+written);
	newrule_features = (secfw_feature_t *)((char *)(reply->sr_metadata) + written);
	written += sizeof(secfw_feature_t) * rule->sr_nfeatures;

	for (i=0; i < rule->sr_nfeatures; i++)
		memcpy(&(newrule->sr_features[i]), &rule->sr_features[i], sizeof(secfw_feature_t));

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

	free(buf, M_SECFW);

	return 0;
}
