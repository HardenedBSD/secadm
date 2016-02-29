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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <malloc_np.h>
#include <sys/mount.h>
#include <errno.h>

#include "secadm.h"

int
_secadm_sysctl(secadm_command_t *cmd, secadm_reply_t *reply)
{
	size_t cmdsz, replysz;
	int err;

	cmdsz = sizeof(secadm_command_t);
	replysz = sizeof(secadm_reply_t);

	err = sysctlbyname("hardening.secadm.control", reply, &replysz,
	    cmd, cmdsz);

	if (err) {
		perror("sysctlbyname");
		return (err);
	}

	if (reply->sr_code != secadm_reply_success) {
		fprintf(stderr, "control channel returned error code %d\n", reply->sr_code);
		return (reply->sr_code);
	}

	return (0);
}

int
secadm_flush_ruleset(void)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_flush_ruleset;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "could not flush rules. error code: %d\n", err);
	}

	return (err);
}

int
_secadm_rule_ops(secadm_rule_t *rule, secadm_command_type_t cmd_type)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = cmd_type;
	cmd.sc_data = rule;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "secadm_rule_ops. error code: %d\n", err);
	}

	return (err);
}

int
secadm_load_ruleset(secadm_rule_t *ruleset)
{
	return (_secadm_rule_ops(ruleset, secadm_cmd_load_ruleset));
}

int
_secadm_integriforce_flags_ops(int mode)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_set_whitelist_mode;
	cmd.sc_data = &mode;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "secadm_rule_ops. error code: %d\n", err);
	}

	return (err);
}

int
secadm_set_whitelist_mode(int mode)
{
	return (_secadm_integriforce_flags_ops(mode));
}

int
secadm_add_rule(secadm_rule_t *rule)
{
	int err;

	if ((err = secadm_validate_rule(rule))) {
		return (err);
	}

	return (_secadm_rule_ops(rule, secadm_cmd_add_rule));
}

int
secadm_del_rule(int rule_id)
{
	secadm_rule_t rule;

	memset(&rule, 0, sizeof(secadm_rule_t));
	rule.sr_id = rule_id;

	return (_secadm_rule_ops(&rule, secadm_cmd_del_rule));
}

int
secadm_enable_rule(int rule_id)
{
	secadm_rule_t rule;

	memset(&rule, 0, sizeof(secadm_rule_t));
	rule.sr_id = rule_id;

	return (_secadm_rule_ops(&rule, secadm_cmd_enable_rule));
}

int
secadm_disable_rule(int rule_id)
{
	secadm_rule_t rule;

	memset(&rule, 0, sizeof(secadm_rule_t));
	rule.sr_id = rule_id;

	return (_secadm_rule_ops(&rule, secadm_cmd_disable_rule));
}

void *
_secadm_get_rule_data(secadm_rule_t *rule, size_t size)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	void *rule_data;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_rule_data;

	if ((rule_data = calloc(1, size)) == NULL) {
		perror("calloc");
		return NULL;
	}

	cmd.sc_data = rule;
	reply.sr_data = rule_data;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get rule data. error code: %d\n", err);
		return NULL;
	}

	return (rule_data);
}

u_char *
_secadm_get_rule_path(secadm_rule_t *rule)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	u_char *rule_path;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_rule_path;

	if ((rule_path = calloc(1, MAXPATHLEN + 1)) == NULL) {
		perror("calloc");
		return NULL;
	}

	cmd.sc_data = rule;
	reply.sr_data = rule_path;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get rule path. error code: %d\n", err);
		return NULL;
	}

	return (rule_path);
}

u_char *
_secadm_get_rule_hash(secadm_rule_t *rule)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	u_char *rule_hash;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_rule_hash;

	if ((rule_hash = calloc(1, SECADM_SHA256_DIGEST_LEN + 1)) == NULL) {
		perror("calloc");
		return NULL;
	}

	cmd.sc_data = rule;
	reply.sr_data = rule_hash;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get rule hash. error code: %d\n", err);
		return NULL;
	}

	return (rule_hash);
}

secadm_rule_t *
secadm_get_rule(int rule_id)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	secadm_rule_t *rule;
	size_t size;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_rule;

	if ((rule = calloc(1, sizeof(secadm_rule_t))) == NULL) {
		perror("calloc");
		return (NULL);
	}

	rule->sr_id = rule_id;
	cmd.sc_data = rule;
	reply.sr_data = rule;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get rule. error code: %d\n", err);
		secadm_free_rule(rule);

		return (NULL);
	}

	switch (rule->sr_type) {
	case secadm_integriforce_rule:
		rule->sr_integriforce_data =
		    _secadm_get_rule_data(rule, sizeof(secadm_integriforce_data_t));
		rule->sr_integriforce_data->si_path = _secadm_get_rule_path(rule);
		rule->sr_integriforce_data->si_hash = _secadm_get_rule_hash(rule);

		break;
	case secadm_pax_rule:
		rule->sr_pax_data =
		    _secadm_get_rule_data(rule, sizeof(secadm_pax_data_t));
		rule->sr_pax_data->sp_path = _secadm_get_rule_path(rule);

		break;
	case secadm_extended_rule:
		rule->sr_extended_data = _secadm_get_rule_data(rule, sizeof(secadm_extended_data_t));

		if (rule->sr_extended_data->sm_object.mo_pathsz) {
			rule->sr_extended_data->sm_object.mo_path =
			    _secadm_get_rule_path(rule);
		}

		break;
	default:
		/* TODO */
		break;
	}

	return (rule);
}

size_t
secadm_get_num_rules(void)
{
	int err;
	secadm_command_t cmd;
	secadm_reply_t reply;
	size_t num_rules;

	num_rules = 0;
	memset(&cmd, 0, sizeof(secadm_command_t));
	memset(&reply, 0, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_num_rules;
	reply.sr_data = &num_rules;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get rules. error code: %d\n", err);
		return (-1);
	}

	return (num_rules);
}

int
secadm_get_whitelist_mode(void)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err, flags;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_cmd_get_whitelist_mode;
	reply.sr_data = &flags;

	if ((err = _secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "unable to get the flags. error code: %d\n", err);
		return (0);
	}

	return (flags);
}

void
secadm_free_rule(secadm_rule_t *rule)
{
	switch (rule->sr_type) {
	case secadm_integriforce_rule:
		if (rule->sr_integriforce_data)
			free(rule->sr_integriforce_data);

		break;

	case secadm_pax_rule:
		if (rule->sr_pax_data)
			free(rule->sr_pax_data);

		break;

	case secadm_extended_rule:
		if (rule->sr_extended_data)
			free(rule->sr_extended_data);

		break;
	}

	free(rule);
}

int
secadm_validate_rule(secadm_rule_t *rule)
{
	struct stat sb;
	char *path;

	switch (rule->sr_type) {
	case secadm_integriforce_rule:
		if (rule->sr_integriforce_data == NULL) {
			fprintf(stderr, "Invalid Integriforce rule.\n");
			return (1);
		}

		if (rule->sr_integriforce_data->si_path == NULL) {
			fprintf(stderr,
			    "Integriforce rule has no path specified.\n");
			return (1);
		}

		if (strlen((const char *)rule->sr_integriforce_data->si_path) >
		    MAXPATHLEN) {
			fprintf(stderr, "Integriforce rule path is too long: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		if (rule->sr_integriforce_data->si_path[0] != '/') {
			fprintf(stderr, "Integriforce rule is not a full path: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		if ((path = realpath(
		     (const char *)rule->sr_integriforce_data->si_path,
		     NULL)) == NULL) {
			fprintf(stderr,
			    "Integriforce rule path is invalid: %s: %s\n",
			    rule->sr_integriforce_data->si_path,
			    strerror(errno));
			return (1);
		}

		if (strncmp((const char *)rule->sr_integriforce_data->si_path,
		    path, strlen(
		    (const char *)rule->sr_integriforce_data->si_path))) {
			fprintf(stderr,
			    "Integriforce rule path is invalid: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		if (stat((const char *)rule->sr_integriforce_data->si_path, &sb)
		    < 0) {
			fprintf(stderr,
			    "Integriforce rule path is invalid: %s: %s\n",
			    rule->sr_integriforce_data->si_path, strerror(errno));
			return (1);
		}

		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr,
			    "Integriforce rule path is not a regular file: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		switch (rule->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			break;
		case secadm_hash_sha256:
			break;
		default:
			fprintf(stderr,
			    "Integriforce rule type invalid: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		if (rule->sr_integriforce_data->si_mode < 0 ||
		    rule->sr_integriforce_data->si_mode > 1) {
			fprintf(stderr,
			    "Integriforce rule mode invalid: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		if (rule->sr_integriforce_data->si_hash == NULL) {
			fprintf(stderr,
			    "Integriforce rule has no hash specified: %s\n",
			    rule->sr_integriforce_data->si_path);
			return (1);
		}

		rule->sr_integriforce_data->si_pathsz = strlen(
		    (const char *)rule->sr_integriforce_data->si_path);

		break;

	case secadm_pax_rule:
		if (rule->sr_pax_data == NULL) {
			fprintf(stderr, "Invalid PaX rule.\n");
			return (1);
		}

		if (rule->sr_pax_data->sp_path == NULL) {
			fprintf(stderr,
			    "PaX rule has no path specified.\n");
			return (1);
		}

		if (strlen((const char *)rule->sr_pax_data->sp_path) >
		    MAXPATHLEN) {
			fprintf(stderr, "PaX rule path is too long: %s\n",
			    rule->sr_pax_data->sp_path);
			return (1);
		}

		if (rule->sr_pax_data->sp_path[0] != '/') {
			fprintf(stderr, "PaX rule is not a full path: %s\n",
			    rule->sr_pax_data->sp_path);
			return (1);
		}

		if ((path = realpath(
		     (const char *)rule->sr_pax_data->sp_path, NULL)) == NULL) {
			fprintf(stderr,
			    "PaX rule path is invalid: %s: %s\n",
			    rule->sr_pax_data->sp_path,
			    strerror(errno));
			return (1);
		}

		if (strncmp((const char *)rule->sr_pax_data->sp_path,
		    path, strlen((const char *)rule->sr_pax_data->sp_path))) {
			fprintf(stderr,
			    "PaX rule path is invalid: %s\n",
			    rule->sr_pax_data->sp_path);
			return (1);
		}

		if (stat((const char *)rule->sr_pax_data->sp_path, &sb)
		    < 0) {
			fprintf(stderr,
			    "PaX rule path is invalid: %s: %s\n",
			    rule->sr_pax_data->sp_path, strerror(errno));
			return (1);
		}

		if (!S_ISREG(sb.st_mode)) {
			fprintf(stderr,
			    "PaX rule path is not a regular file: %s\n",
			    rule->sr_pax_data->sp_path);
			return (1);
		}

		rule->sr_pax_data->sp_pathsz =
		    strlen((const char *)rule->sr_pax_data->sp_path);

		if (!(rule->sr_pax_data->sp_pax_set)) {
			fprintf(stderr,
			    "PaX rule has no features set: %s\n",
			    rule->sr_pax_data->sp_path);
			return (1);
		}

		break;

	case secadm_extended_rule:
		return (1);
	}

	return (0);
}
