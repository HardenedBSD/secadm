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

#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/rmlock.h>
#include <sys/systm.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

secadm_prisons_t secadm_prisons_list;

static void
secadm_destroy(struct mac_policy_conf *mpc)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *next;

	RM_PL_RLOCK(tracker);
	SLIST_FOREACH(entry, &(secadm_prisons_list.sp_prison), sp_entries) {
		RM_PE_WLOCK(entry);
		for (r = RB_MIN(secadm_rules_tree, &(entry->sp_rules));
		    r != NULL; r = next) {
			next = RB_NEXT(secadm_rules_tree,
			    &(entry->sp_rules), r);
			RB_REMOVE(secadm_rules_tree, &(entry->sp_rules), r);

			kernel_free_rule(r);
		}
		RM_PE_WUNLOCK(entry);
	}
	RM_PL_RUNLOCK(tracker);

	RM_PL_WLOCK();
	while (!SLIST_EMPTY(&(secadm_prisons_list.sp_prison))) {
		entry = SLIST_FIRST(&(secadm_prisons_list.sp_prison));

		SLIST_REMOVE_HEAD(&(secadm_prisons_list.sp_prison), sp_entries);
		free(entry, M_SECADM);
	}
	RM_PL_WUNLOCK();
}

static void
secadm_init(struct mac_policy_conf *mpc)
{
	RM_PL_INIT();
	SLIST_INIT(&(secadm_prisons_list.sp_prison));
}

static void
secadm_prison_destroy(struct prison *prison)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_rule_t *r, *next;

	RM_PL_RLOCK(tracker);
	SLIST_FOREACH(entry, &(secadm_prisons_list.sp_prison), sp_entries) {
		if (entry->sp_id == prison->pr_id) {
			RM_PE_WLOCK(entry);
			for (r = RB_MIN(secadm_rules_tree, &(entry->sp_rules));
			    r != NULL; r = next) {
				next = RB_NEXT(secadm_rules_tree,
				    &(entry->sp_rules), r);
				RB_REMOVE(secadm_rules_tree,
				    &(entry->sp_rules), r);

				kernel_free_rule(r);
			}
			RM_PE_WUNLOCK(entry);

			break;
		}
	}
	RM_PL_RUNLOCK(tracker);
}

static struct mac_policy_ops secadm_ops = {
	.mpo_destroy		= secadm_destroy,
	.mpo_init		= secadm_init,

	.mpo_vnode_check_exec	= secadm_vnode_check_exec,
	.mpo_vnode_check_open	= secadm_vnode_check_open,
	.mpo_vnode_check_unlink	= secadm_vnode_check_unlink,

	.mpo_prison_destroy	= secadm_prison_destroy
};

MAC_POLICY_SET(&secadm_ops, secadm, "HardenedBSD SECADM Module",
	       MPC_LOADTIME_FLAG_UNLOADOK, NULL);
