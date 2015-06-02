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
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

static void handle_version_command(secadm_command_t *cmd, secadm_reply_t *reply);
static int sysctl_control(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_hardening, OID_AUTO, secadm, CTLFLAG_RD, 0,
    "HardenedBSD Security Firewall");

SYSCTL_NODE(_hardening_secadm, OID_AUTO, control,
    CTLFLAG_MPSAFE | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_ANYBODY, sysctl_control,
    "secadm management interface");

static void
handle_version_command(secadm_command_t *cmd, secadm_reply_t *reply)
{
	reply->sr_metadata = cmd->sc_buf;
	reply->sr_size = sizeof(unsigned long);
	if ((reply->sr_errno = copyout(&(reply->sr_version), cmd->sc_buf, sizeof(unsigned long))))
		reply->sr_code = secadm_fail;
	else
		reply->sr_code = secadm_success;
}

static secadm_error_t
handle_add_rule(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	secadm_rule_t *rule, *next, *tail;
	struct secadm_prison_entry *entry;
	size_t maxid=0;
	secadm_error_t res=secadm_success;
	int err;

	entry = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 1);

	rule = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);
	if ((err = copyin(cmd->sc_metadata, rule, sizeof(secadm_rule_t))) != 0) {
		free(rule, M_SECADM);
		reply->sr_code = secadm_fail;
		reply->sr_errno = err;
		return (secadm_fail);
	}

	if (read_rule_from_userland(td, rule)) {
		reply->sr_errno = EINVAL;
		rule->sr_next = NULL;
		goto error;
	}

	rule->sr_id = maxid++;

	tail = rule;
	while (tail->sr_next != NULL) {
		next = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);
		if ((err = copyin(tail->sr_next, next, sizeof(secadm_rule_t))) != 0) {
			reply->sr_errno = err;
			free(next, M_SECADM);
			tail->sr_next = NULL;
			goto error;
		}

		if (read_rule_from_userland(td, next)) {
			res=secadm_fail;
			reply->sr_errno = EINVAL;
			free_rule(next, 1);
			tail->sr_next = NULL;
			goto error;
		}

		next->sr_id = maxid++;

		tail->sr_next = next;
		tail = next;
	}

	if (validate_ruleset(td, rule)) {
		res = secadm_fail;
		reply->sr_errno = EINVAL;
		goto error;
	}

	flush_rules(td);

	SPL_WLOCK(entry);
	entry->spl_rules = rule;
	entry->spl_max_id = maxid;
	SPL_WUNLOCK(entry);

	reply->sr_code = secadm_success;
	reply->sr_errno = 0;

	return (0);

error:
	while (rule != NULL) {
		next = rule->sr_next;
		free_rule(rule, 1);
		rule = next;
	}

	reply->sr_code = secadm_fail;

	return (res);
}

static int
sysctl_control(SYSCTL_HANDLER_ARGS)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err;

	if (!(req->newptr) || (req->newlen != sizeof(secadm_command_t)))
		return (EINVAL);

	if (!(req->oldptr) || (req->oldlen) != sizeof(secadm_reply_t))
		return (EINVAL);

	err = SYSCTL_IN(req, &cmd, sizeof(secadm_command_t));
	if (err)
		return (err);

	/* Access control comes first */
	switch (cmd.sc_type) {
	case secadm_flush_rules:
	case secadm_set_rules:
		/* XXX Should we cache the ucred for local use in the
		 * sysctl lifecycle? */
		// XXXOP LOCKING
		if (req->td->td_ucred->cr_uid != 0) {
			printf("[SECADM] disallowed command (0x%x) by %u uid\n",
			    cmd.sc_type, req->td->td_ucred->cr_uid);
			return (EPERM);
		}

		// XXXOP LOCKING
		if (securelevel_gt(req->td->td_ucred, 0))
			return (EPERM);
		break;
	default:
		printf("[SECADM] unknown cmd: %x\n", cmd.sc_type);
		break;
	}

	/* XXX We should relax this check once we get stable releases. */
	if (cmd.sc_version < SECADM_VERSION)
		return (EINVAL);

	memset(&reply, 0x00, sizeof(reply));
	if ((err = copyin(req->oldptr, &reply, sizeof(reply))))
		return (err);

	reply.sr_version = SECADM_VERSION;
	reply.sr_id = cmd.sc_id;

	switch (cmd.sc_type) {
	case  secadm_get_version:
		if (cmd.sc_bufsize < sizeof(unsigned long))
			return (EINVAL);

		handle_version_command(&cmd, &reply);
		break;
	case secadm_set_rules:
		if (cmd.sc_size != sizeof(secadm_rule_t))
			return (EINVAL);

		handle_add_rule(req->td, &cmd, &reply);
		break;
	case secadm_flush_rules:
		flush_rules(req->td);
		break;
	case secadm_get_rule_size:
		handle_get_rule_size(req->td, &cmd, &reply);
		break;
	case secadm_get_num_rules:
		get_num_rules(req->td, &cmd, &reply);
		break;
	case secadm_get_rule:
		handle_get_rule(req->td, &cmd, &reply);
		break;
	case secadm_get_rules:
	case secadm_get_admins:
	case secadm_set_admins:
	case secadm_get_views:
	case secadm_set_views:
		return (ENOTSUP);
	default:
		return (EINVAL);
	}

	err = SYSCTL_OUT(req, &reply, sizeof(secadm_reply_t));
	return (err);
}
