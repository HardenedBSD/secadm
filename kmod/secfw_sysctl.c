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
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secfw.h"

static void handle_version_command(secfw_command_t *cmd, secfw_reply_t *reply);
static int sysctl_control(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_hardening, OID_AUTO, secfw, CTLFLAG_RD, 0,
    "HardenedBSD Security Firewall");

SYSCTL_NODE(_hardening_secfw, OID_AUTO, control,
    CTLFLAG_MPSAFE | CTLFLAG_RW | CTLFLAG_PRISON, sysctl_control,
    "secfw management interface");

static void
handle_version_command(secfw_command_t *cmd, secfw_reply_t *reply)
{
	reply->sr_metadata = cmd->sc_buf;
	reply->sr_size = sizeof(unsigned long);
	if (copyout(&(reply->sr_version), cmd->sc_buf, sizeof(unsigned long)))
		reply->sr_code = EFAULT;
	else
		reply->sr_code = 0;
}

static unsigned int
handle_add_rule(struct thread *td, secfw_command_t *cmd, secfw_reply_t *reply)
{
	unsigned int res=0;
	int err;
	secfw_rule_t *rule, *tail;

	rule = malloc(sizeof(secfw_rule_t), M_SECFW, M_WAITOK);
	if ((err = copyin(cmd->sc_metadata, rule, sizeof(secfw_rule_t))) != 0) {
		res = EFAULT;
		goto err;
	}

	if (read_rule_from_userland(td, rule)) {
		res=1;
		goto err;
	}

	secfw_rules_lock_write();

	if (rules.rules == NULL) {
		rules.rules = rule;
	} else {
		for (tail = rules.rules; tail->sr_next != NULL; tail = tail->sr_next)
			;

		tail->sr_next = rule;
	}

	secfw_rules_unlock_write();
err:
	reply->sr_code = res;
	return (res);
}

static int
sysctl_control(SYSCTL_HANDLER_ARGS)
{
	secfw_command_t cmd;
	secfw_reply_t reply;
	int err;

	if (!(req->newptr) || (req->newlen != sizeof(secfw_command_t)))
		return (EINVAL);

	if (!(req->oldptr) || (req->oldlen) != sizeof(secfw_reply_t))
		return (EINVAL);

	err = SYSCTL_IN(req, &cmd, sizeof(secfw_command_t));
	if (err)
		return (err);

	if (cmd.sc_version < SECFW_VERSION)
		return (EINVAL);

	memset(&reply, 0x00, sizeof(reply));

	reply.sr_version = SECFW_VERSION;
	reply.sr_id = cmd.sc_id;

	switch (cmd.sc_type) {
	case  secfw_get_version:
		if (cmd.sc_bufsize < sizeof(unsigned long))
			return (EINVAL);
		handle_version_command(&cmd, &reply);
		break;
	case secfw_set_rules:
		if (cmd.sc_size != sizeof(secfw_rule_t)) {
			printf("Size mismatch\n");
			uprintf("Size mismatch\n");
			return (EINVAL);
		}

		secfw_rules_lock_write();
		flush_rules();
		secfw_rules_unlock_write();

		handle_add_rule(req->td, &cmd, &reply);
		break;
	case secfw_flush_rules:
		secfw_rules_lock_write();
		flush_rules();
		secfw_rules_unlock_write();
	case secfw_get_rules:
		return (ENOTSUP);
	default:
		return (EINVAL);
	}

	err = SYSCTL_OUT(req, &reply, sizeof(secfw_reply_t));
	return (err);
}
