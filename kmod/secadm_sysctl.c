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
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secadm.h"

static void handle_version_command(secadm_command_t *cmd, secadm_reply_t *reply);
static int sysctl_control(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_hardening, OID_AUTO, secadm, CTLFLAG_RD, 0,
    "HardenedBSD Security Firewall");

SYSCTL_NODE(_hardening_secadm, OID_AUTO, control,
    CTLFLAG_MPSAFE | CTLFLAG_RW | CTLFLAG_PRISON, sysctl_control,
    "secadm management interface");

static void
handle_version_command(secadm_command_t *cmd, secadm_reply_t *reply)
{
	reply->sr_metadata = cmd->sc_buf;
	reply->sr_size = sizeof(unsigned long);
	if (copyout(&(reply->sr_version), cmd->sc_buf, sizeof(unsigned long)))
		reply->sr_code = EFAULT;
	else
		reply->sr_code = 0;
}

static unsigned int
handle_add_rule(struct thread *td, secadm_command_t *cmd, secadm_reply_t *reply)
{
	secadm_rule_t *rule, *next, *tail;
	secadm_prison_list_t *list;
	size_t maxid=0;
	unsigned int res=0;
	int err;

	rule = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);
	if ((err = copyin(cmd->sc_metadata, rule, sizeof(secadm_rule_t))) != 0) {
		res = EFAULT;
		goto err;
	}

	if (read_rule_from_userland(td, rule)) {
		res=1;
		goto err;
	}

	rule->sr_id = maxid++;

	tail = rule;
	while (tail->sr_next != NULL) {
		next = malloc(sizeof(secadm_rule_t), M_SECADM, M_WAITOK);
		if ((err = copyin(tail->sr_next, next, sizeof(secadm_rule_t))) != 0) {
			res = EFAULT;
			goto err;
		}

		if (read_rule_from_userland(td, next)) {
			res=1;
			goto err;
		}

		next->sr_id = maxid++;

		tail->sr_next = next;
		tail = next;
	}

	list = get_prison_list_entry(td->td_ucred->cr_prison->pr_name, 1);

	rm_wlock(&(list->spl_lock));
	if (list->spl_rules == NULL) {
		list->spl_rules = rule;
	} else {
		for (tail = list->spl_rules; tail->sr_next != NULL; tail = tail->sr_next)
			;

		tail->sr_next = rule;
	}

	list->spl_max_id = maxid;
	rm_wunlock(&(list->spl_lock));
err:
	reply->sr_code = res;
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

	if (cmd.sc_version < SECADM_VERSION)
		return (EINVAL);

	memset(&reply, 0x00, sizeof(reply));
	if (copyin(req->oldptr, &reply, sizeof(reply)))
		return (EFAULT);

	reply.sr_version = SECADM_VERSION;
	reply.sr_id = cmd.sc_id;

	switch (cmd.sc_type) {
	case  secadm_get_version:
		if (cmd.sc_bufsize < sizeof(unsigned long))
			return (EINVAL);

		handle_version_command(&cmd, &reply);
		break;
	case secadm_set_rules:
		if (cmd.sc_size != sizeof(secadm_rule_t)) {
			printf("Size mismatch\n");
			uprintf("Size mismatch\n");
			return (EINVAL);
		}

		/*
		 * Ideally, we would not want to flush rules prior to
		 * resetting our ruleset. Doing it this way creates a
		 * race condition where there are no rules loaded. So
		 * in the future, behave more like pf and only flush
		 * the ruleset when the new ruleset is 100% ready to
		 * be activated.
		 */

		flush_rules(req->td);

		handle_add_rule(req->td, &cmd, &reply);
		break;
	case secadm_flush_rules:
		flush_rules(req->td);
		break;
	case secadm_get_rule_size:
		reply.sr_code = handle_get_rule_size(req->td, &cmd, &reply);
		break;
	case secadm_get_num_rules:
		reply.sr_code = (unsigned int)get_num_rules(req->td, &cmd,
		    &reply);
		break;
	case secadm_get_rule:
		reply.sr_code = (unsigned int)handle_get_rule(req->td, &cmd,
		    &reply);
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
