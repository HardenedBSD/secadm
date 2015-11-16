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
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/rmlock.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/tree.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include "secadm.h"

int
secadm_sysctl_handler(SYSCTL_HANDLER_ARGS)
{
	struct rm_priotracker tracker;
	secadm_prison_entry_t *entry;
	secadm_command_t cmd;
	secadm_reply_t reply;
	secadm_rule_t *rule;
	int err, i, rn;

	if (!(req->newptr) || (req->newlen != sizeof(secadm_command_t))) {
		return (EINVAL);
	}

	if (!(req->oldptr) || (req->oldlen) != sizeof(secadm_reply_t)) {
		return (EINVAL);
	}

	if ((err = SYSCTL_IN(req, &cmd, sizeof(secadm_command_t)))) {
		return (err);
	}

	if ((err = copyin(req->oldptr, &reply, sizeof(reply)))) {
		return (err);
	}

	reply.sr_version = SECADM_VERSION;

	switch (cmd.sc_type) {
	case secadm_cmd_flush_ruleset:
	case secadm_cmd_load_ruleset:
	case secadm_cmd_add_rule:
	case secadm_cmd_del_rule:
	case secadm_cmd_enable_rule:
	case secadm_cmd_disable_rule:
		if (req->td->td_ucred->cr_uid) {
			printf("[SECADM] Denied attempt to sysctl by "
			    "(%s) uid:%d jail:%d\n",
			    req->td->td_name, req->td->td_ucred->cr_uid,
			    req->td->td_ucred->cr_prison->pr_id);

			reply.sr_code = secadm_reply_fail;
			SYSCTL_OUT(req, &reply, sizeof(secadm_reply_t));

			return (EPERM);
		}

	default:
		break;
	}

	switch (cmd.sc_type) {
	case secadm_cmd_flush_ruleset:
		if (securelevel_gt(req->td->td_ucred, 1)) {
			return (EPERM);
		}

		kernel_flush_ruleset(req->td->td_ucred->cr_prison->pr_id);
		reply.sr_code = secadm_reply_success;

		break;

	case secadm_cmd_load_ruleset:
		entry = get_prison_list_entry(
		    req->td->td_ucred->cr_prison->pr_id);

		if (entry->sp_loaded &&
		    securelevel_gt(req->td->td_ucred, 1))
			return (EPERM);

		err = kernel_load_ruleset(req->td,
		    (secadm_rule_t *) cmd.sc_data);

		if (err) {
			reply.sr_code = secadm_reply_fail;
		} else {
			reply.sr_code = secadm_reply_success;
		}

		break;

	case secadm_cmd_add_rule:
		if (securelevel_gt(req->td->td_ucred, 1)) {
			return (EPERM);
		}

		err = kernel_add_rule(req->td, (secadm_rule_t *) cmd.sc_data, 0);

		if (err) {
			reply.sr_code = secadm_reply_fail;
		} else {
			reply.sr_code = secadm_reply_success;
		}

		break;

	case secadm_cmd_del_rule:
		if (securelevel_gt(req->td->td_ucred, 0)) {
			return (EPERM);
		}

		kernel_del_rule(req->td, (secadm_rule_t *) cmd.sc_data);
		reply.sr_code = secadm_reply_success;

		break;

	case secadm_cmd_enable_rule:
		if (securelevel_gt(req->td->td_ucred, 0)) {
			return (EPERM);
		}

		kernel_active_rule(req->td, (secadm_rule_t *) cmd.sc_data, 1);
		reply.sr_code = secadm_reply_success;

		break;

	case secadm_cmd_disable_rule:
		if (securelevel_gt(req->td->td_ucred, 0)) {
			return (EPERM);
		}

		kernel_active_rule(req->td, (secadm_rule_t *) cmd.sc_data, 0);
		reply.sr_code = secadm_reply_success;

		break;

	case secadm_cmd_get_rule:
		rule = kernel_get_rule(req->td, (secadm_rule_t *) cmd.sc_data);

		if (rule == NULL) {
			rn = ((secadm_rule_t *) cmd.sc_data)->sr_id + 1;

			entry = get_prison_list_entry(
			    req->td->td_ucred->cr_prison->pr_id);

			if (rn >= entry->sp_last_id) {
				break;
			}

			for (i = rn; i < entry->sp_last_id; i++) {
				((secadm_rule_t *) cmd.sc_data)->sr_id = i;
				rule = kernel_get_rule(req->td,
				    (secadm_rule_t *) cmd.sc_data);

				if (rule != NULL) {
					break;
				}
			}
		}

		if (rule == NULL) {
			reply.sr_code = secadm_reply_fail;
			break;
		}

		if ((err = copyout(rule,
		    reply.sr_data, sizeof(secadm_rule_t)))) {
			reply.sr_code = secadm_reply_fail;
		} else {
			reply.sr_code = secadm_reply_success;
		}

		break;

	case secadm_cmd_get_rule_data:
		rule = kernel_get_rule(req->td, (secadm_rule_t *) cmd.sc_data);

		if (rule == NULL) {
			printf("rule_data: rule is NULL\n");
			reply.sr_code = secadm_reply_fail;
			break;
		}

		switch (rule->sr_type) {
		case secadm_integriforce_rule:
			if ((err = copyout(rule->sr_integriforce_data,
			    reply.sr_data,
			    sizeof(secadm_integriforce_data_t)))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;

		case secadm_pax_rule:
			if ((err = copyout(rule->sr_pax_data,
			    reply.sr_data,
			    sizeof(secadm_pax_data_t)))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;

		case secadm_extended_rule:
			reply.sr_code = secadm_reply_fail;
		}

		break;

	case secadm_cmd_get_rule_path:
		rule = kernel_get_rule(req->td, (secadm_rule_t *) cmd.sc_data);

		if (rule == NULL) {
			reply.sr_code = secadm_reply_fail;
			break;
		}

		switch (rule->sr_type) {
		case secadm_integriforce_rule:
			if ((err = copyout(rule->sr_integriforce_data->si_path,
			    reply.sr_data,
			    rule->sr_integriforce_data->si_pathsz))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;

		case secadm_pax_rule:
			if ((err = copyout(rule->sr_pax_data->sp_path,
			    reply.sr_data,
			    rule->sr_pax_data->sp_pathsz))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;

		case secadm_extended_rule:
			reply.sr_code = secadm_reply_fail;
		}

		break;

	case secadm_cmd_get_rule_hash:
		rule = kernel_get_rule(req->td, (secadm_rule_t *) cmd.sc_data);

		if (rule == NULL) {
			reply.sr_code = secadm_reply_fail;
			break;
		}

		if (rule->sr_type != secadm_integriforce_rule) {
			reply.sr_code = secadm_reply_fail;
			break;
		}

		switch (rule->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			if ((err = copyout(rule->sr_integriforce_data->si_hash,
			    reply.sr_data, SECADM_SHA1_DIGEST_LEN))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;

		case secadm_hash_sha256:
			if ((err = copyout(rule->sr_integriforce_data->si_hash,
			    reply.sr_data, SECADM_SHA256_DIGEST_LEN))) {
				reply.sr_code = secadm_reply_fail;
			} else {
				reply.sr_code = secadm_reply_success;
			}

			break;
		}

		break;

	case secadm_cmd_get_num_rules:
		entry = get_prison_list_entry(
		    req->td->td_ucred->cr_prison->pr_id);

		RM_PE_RLOCK(entry, tracker);
		if ((err = copyout(&(entry->sp_num_rules), reply.sr_data,
		    sizeof(size_t)))) {
			reply.sr_code = secadm_reply_fail;
		} else {
			reply.sr_code = secadm_reply_success;
		}
		RM_PE_RUNLOCK(entry, tracker);

		break;

	default:
		printf("secadm_sysctl: unknown command!\n");

		return (EOPNOTSUPP);
	}

	err = SYSCTL_OUT(req, &reply, sizeof(secadm_reply_t));

	return (err);
}

SYSCTL_NODE(_hardening, OID_AUTO, secadm, CTLFLAG_RD, 0,
	    "HardenedBSD Security Firewall");

SYSCTL_NODE(_hardening_secadm, OID_AUTO, control,
	    CTLFLAG_MPSAFE | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_PRISON,
	    secadm_sysctl_handler, "HardenedBSD SECADM Management Interface");
