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

static struct rmlock secfw_mtx;
secfw_kernel_t rules;
struct rm_priotracker tracker;

void
secfw_lock_init(void)
{
	rm_init(&secfw_mtx, "mac_secfw lock");
	memset(&tracker, 0x00, sizeof(struct rm_priotracker));
}

void
secfw_lock_destroy(void)
{
	rm_destroy(&secfw_mtx);
}

void
secfw_lock_read(void)
{
	rm_rlock(&secfw_mtx, &tracker);
}

void
secfw_unlock_read(void)
{
	rm_runlock(&secfw_mtx, &tracker);
}

void
secfw_lock_write(void)
{
	rm_wlock(&secfw_mtx);
}

void
secfw_unlock_write(void)
{
	rm_wunlock(&secfw_mtx);
}

int
validate_rule(struct thread *td, secfw_rule_t *rule)
{
	struct prison *pr;
#if 0
	secfw_kernel_t *prules;
	secfw_rule_t *prule;
#endif

	KASSERT(rule != NULL, ("validate_rule: rule cannot be null!"));

	if (rule->sr_nfeatures == 0)
		return (1);

	pr = td->td_ucred->cr_prison;

	return (0);
}

int
add_rule(struct thread *td, secfw_command_t *cmd, secfw_rule_t *rule)
{
#if 0
	struct prison *pr;
	secfw_kernel_t *prules;
	int err = 0;

	err = validate_rule(td, rule);
	if (err)
		return (err);

	pr = td->td_ucred->cr_prison;

	prison_lock(pr);

	prules = (secfw_kernel_t *)(pr->pr_secfw_mac);
	if (prules == NULL) {
		prules = malloc(sizeof(secfw_kernel_t), M_SECFW, M_WAITOK);
		LIST_INIT(&(prules->sk_rules));
		pr->pr_secfw_mac = prules;
	}

	LIST_INSERT_HEAD(&(prules->sk_rules), rule,
	    sr_entry);

	prison_unlock(pr);
#endif

	return (0);
}

void
free_rule(secfw_rule_t *rule, int freerule)
{
	size_t i;
	
	if (rule->sr_path) {
		free(rule->sr_path, M_SECFW);
	}

	for (i=0; i < rule->sr_nfeatures; i++)
		if (rule->sr_features[i].metadata)
			free(rule->sr_features[i].metadata, M_SECFW);

	if (rule->sr_features)
		free(rule->sr_features, M_SECFW);

	if (freerule)
		free(rule, M_SECFW);
}

/* XXX This is more of a PoC. This needs to be cleaned up for
 * production use */
int
read_rule_from_userland(struct thread *td, secfw_rule_t *rule)
{
	char *path;
	secfw_rule_t *newrule, *next;
	secfw_feature_t *features;
	void *metadata;
	size_t i, j;
	int err = 0;

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
		path = malloc(rule->sr_pathlen+2, M_SECFW, M_WAITOK | M_ZERO);
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

	if (validate_rule(td, rule)) {
		free_rule(rule, 0);
		return (-1);
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
