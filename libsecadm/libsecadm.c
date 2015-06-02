/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include "secadm.h"
#include "libsecadm.h"

int
secadm_sysctl(secadm_command_t *cmd, secadm_reply_t *reply)
{
	int err;
	size_t cmdsz, replysz;

	cmdsz = sizeof(secadm_command_t);
	replysz = sizeof(secadm_reply_t);

	err = sysctlbyname("hardening.secadm.control", reply, &replysz, cmd,
	    cmdsz);

	if (err) {
		perror("sysctlbyname");
		return (err);
	}

	if (reply->sr_code != secadm_success) {
		fprintf(stderr, "[-] Control channel returned error code %u\n", reply->sr_errno);
		return (reply->sr_errno);
	}

	return (0);
}

unsigned long
secadm_kernel_version(void)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err;
	unsigned long version=0;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_get_version;
	cmd.sc_buf = calloc(1, sizeof(unsigned long));
	if (!(cmd.sc_buf))
		return (0);

	cmd.sc_bufsize = sizeof(unsigned long);

	err = secadm_sysctl(&cmd, &reply);
	if (err == 0) {
		version = *((unsigned long *)(reply.sr_metadata));
	} else {
		fprintf(stderr, "[-] Could not get version: %s\n",
		    strerror(errno));
		goto error;
	}

error:
	if (cmd.sc_buf != NULL)
		free(cmd.sc_buf);

	return (version);
}

unsigned int
secadm_add_rules(secadm_rule_t *rule)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err=0;

	if (secadm_validate_ruleset(rule))
		return ((unsigned int)EINVAL);

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_set_rules;
	cmd.sc_metadata = rule;
	cmd.sc_size = sizeof(secadm_rule_t);

	if ((err = secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Control channel received an error code: %d\n",
		    err);
	}

	return ((unsigned int)err);
}

unsigned int
secadm_flush_all_rules(void)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	int err=0;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_flush_rules;

	if ((err = secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Could not flush rules. Error code: %d\n",
		    err);
	}

	return ((unsigned int)err);
}

void
secadm_debug_print_rule(secadm_rule_t *rule)
{
	secadm_feature_t *feature;
	secadm_integriforce_t *metadata;
	size_t hashsz, i, j;

	printf("[*] Rule %zu\n", rule->sr_id);
	printf("    - Path: %s\n", rule->sr_path);
	for (i=0; i < rule->sr_nfeatures; i++) {
		switch (rule->sr_features[i].sf_type) {
		case pageexec_disabled:
			printf("    - Feature[PAGEEXEC]: Disabled\n");
			break;
		case pageexec_enabled:
			printf("    - Feature[PAGEEXEC]: Enabled\n");
			break;
		case mprotect_disabled:
			printf("    - Feature[MPROTECT]: Disabled\n");
			break;
		case mprotect_enabled:
			printf("    - Feature[MPROTECT]: Enabled\n");
			break;
		case segvguard_enabled:
			printf("    - Feature[SEGVGUARD] - Enabled\n");
			break;
		case segvguard_disabled:
			printf("    - Feature[SEGVGUARD] - Disabled\n");
			break;
		case aslr_disabled:
			printf("    - Feature[ASLR]: Disabled\n");
			break;
		case aslr_enabled:
			printf("    - Feature[ASLR]: Enabled\n");
			break;
		case integriforce:
			if (rule->sr_features[i].sf_metadata == NULL) {
				printf("    - Integriforce enabled, but NULL\n");
				break;
			}

			metadata = (secadm_integriforce_t *)(rule->sr_features[i].sf_metadata);
			printf("     - Integriforce:\n");
			printf("       + Enforcing mode: %s\n",
			    convert_from_integriforce_mode(metadata->si_mode));
			printf("       + Hash: ");
			switch (metadata->si_hashtype) {
			case si_hash_sha1:
				hashsz=SHA1_DIGESTLEN;
				break;
			case si_hash_sha256:
				hashsz=SHA256_DIGESTLEN;
				break;
			default:
				hashsz=0;
				break;
			}

			for (j=0; j<hashsz; j++)
				printf("%02x", metadata->si_hash[j]);
			printf("\n");
		case shlibrandom_disabled:
			printf("    - Feature[SHLIBRANDOM]: Disabled\n");
			break;
		case shlibrandom_enabled:
			printf("    - Feature[SHLIBRANDOM]: Enabled\n");
			break;
		default:
			printf("    - Feature %d unknown\n",
			    rule->sr_features[i].sf_type);
			break;
		}
	}

	if (rule->sr_prison)
		printf("    - Owning jail: %s\n", rule->sr_prison);
}

void
secadm_debug_print_rules(secadm_rule_t *rules)
{
	secadm_rule_t *rule;

	for (rule = rules; rule != NULL; rule = rule->sr_next)
		secadm_debug_print_rule(rule);
}

size_t
secadm_get_kernel_rule_size(size_t id)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	size_t size;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_get_rule_size;
	cmd.sc_buf = &id;
	cmd.sc_bufsize = sizeof(size_t);

	reply.sr_metadata = &size;
	reply.sr_size = sizeof(size_t);

	if ((err = secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Could not get rule size for id %zu: %s\n",
		    id, strerror(err));
		return (0);
	}

	return (size);
}

size_t
secadm_get_num_kernel_rules(void)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	size_t size;
	int err;

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_get_num_rules;

	reply.sr_metadata = &size;
	reply.sr_size = sizeof(size_t);

	if ((err = secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Could not get number of kernel rules: %s\n",
		    strerror(err));
		return (0);
	}

	return (size);

}

secadm_rule_t *
secadm_get_kernel_rule(size_t id)
{
	secadm_command_t cmd;
	secadm_reply_t reply;
	void *buf;
	size_t size;
	int err;

	size = secadm_get_kernel_rule_size(id);
	if (size == 0)
		return (NULL);

	buf = calloc(1, size);
	if (buf == NULL)
		return (NULL);

	memset(&cmd, 0x00, sizeof(secadm_command_t));
	memset(&reply, 0x00, sizeof(secadm_reply_t));

	cmd.sc_version = SECADM_VERSION;
	cmd.sc_type = secadm_get_rule;
	cmd.sc_buf = &id;
	cmd.sc_bufsize = sizeof(size_t);

	reply.sr_metadata = buf;
	reply.sr_size = size;

	if ((err = secadm_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Could not get rule %zu: %s\n", id,
		    strerror(err));
		free(buf);
		return (NULL);
	}

	return ((secadm_rule_t *)buf);
}
