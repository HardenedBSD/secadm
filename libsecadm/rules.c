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

#include <fcntl.h>

#include "secadm.h"
#include "libsecadm.h"

int
secadm_parse_path(secadm_rule_t *rule, const char *path)
{
	struct stat sb;
	struct statfs fsb;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[-] Cannot open %s for stat. Skipping.\n",
		    path);
		return (1);
	}

	if (fstat(fd, &sb)) {
		fprintf(stderr, "[-] fstat(%s): %s\n", path, strerror(errno));
		close(fd);
		return (1);
	}

	memset(&fsb, 0x00, sizeof(struct statfs));
	if (fstatfs(fd, &fsb)) {
		fprintf(stderr, "[-] fstatfs(%s): %s\n", path, strerror(errno));
		close(fd);
		return (1);
	}

	close(fd);

	strlcpy(rule->sr_mount, fsb.f_mntonname, MNAMELEN);
	rule->sr_inode = sb.st_ino;
	rule->sr_path = strdup(path);
	if (rule->sr_path)
		rule->sr_pathlen = strlen(path);
	else
		rule->sr_pathlen = 0;

	return (0);
}

int
secadm_validate_rule(secadm_rule_t *rule)
{
	secadm_integriforce_t *p_integriforce;
	struct stat sb;
	size_t i, len;

	if (rule->sr_features == NULL || rule->sr_nfeatures == 0
	    || rule->sr_nfeatures > SECADM_MAX_FEATURES)
		return (1);

	if (rule->sr_path == NULL)
		return (1);

	len = strlen(rule->sr_path);
	if (len != rule->sr_pathlen || rule->sr_pathlen > MNAMELEN)
		return (1);

	if (stat(rule->sr_path, &sb))
		return (1);

	if (rule->sr_inode != sb.st_ino)
		return (1);

	if (!strlen(rule->sr_mount))
		return (1);

	/*
	 * Perform extra validation for rules in userland. Since these
	 * fields get overwritten in kernel, they should not be used
	 * in userland.
	 */

	if (rule->sr_kernel != NULL)
		return (1);

	if (rule->sr_prison != NULL)
		return (1);

	for (i=0; i < rule->sr_nfeatures; i++) {
		switch (rule->sr_features[i].sf_type) {
		case integriforce:
			if (rule->sr_features[i].sf_metadata == NULL) {
				fprintf(stderr, "[-] Rule[%s]: Integriforce enabled, but no valid metadata\n",
				    rule->sr_path);
				return (1);
			}

			if (rule->sr_features[i].sf_metadatasz != sizeof(secadm_integriforce_t)) {
				fprintf(stderr, "[-] Rule[%s]: Integriforce enabled, but metadata has incorrect size\n",
				    rule->sr_path);
				return (1);
			}

			p_integriforce = (secadm_integriforce_t *)
			    (rule->sr_features[i].sf_metadata);

			if (p_integriforce->si_hash == NULL) {
				fprintf(stderr, "[-] Rule[%s]: No Integriforce hash specified\n",
				    rule->sr_path);
				return (1);
			}

			switch (p_integriforce->si_hashtype) {
			case si_hash_sha1:
			case si_hash_sha256:
				break;
			default:
				fprintf(stderr, "[-] Rule[%s]: Invalid Integriforce hash\n",
				    rule->sr_path);
				return (1);
			}

			switch (p_integriforce->si_mode) {
			case si_mode_soft:
			case si_mode_hard:
				break;
			default:
				fprintf(stderr, "[-] Rule[%s]: Invalid Integriforce mode\n",
				    rule->sr_path);
				return (1);
			}

			if (secadm_verify_file(
			    p_integriforce->si_hashtype,
			    rule->sr_path,
			    p_integriforce->si_hash)) {
				fprintf(stderr, "[-] Rule[%s]: Integrity check failed\n",
				    rule->sr_path);
				return (1);
			}

			break;
		default:
			break;
		}
	}

	return (0);
}

int
secadm_validate_ruleset(secadm_rule_t *rules)
{
	secadm_rule_t *rule;
	size_t nrules, maxid;

	nrules = maxid = 0;
	for (rule = rules; rule != NULL; rule = rule->sr_next) {
		if (secadm_validate_rule(rule)) {
			fprintf(stderr, "[-] Rule[%s] failed to validate\n",
			    rule->sr_path);
			return (1);
		}

		if (rule->sr_id > maxid)
			maxid = rule->sr_id;

		nrules++;
	}

	if (maxid > nrules)
		return (1);

	return (0);
}

void
secadm_free_rule(secadm_rule_t *rule, int freerule)
{
	secadm_integriforce_t *integriforce_p;
	size_t i;

	if (rule->sr_path)
		free(rule->sr_path);

	for (i=0; i < rule->sr_nfeatures; i++) {
		if (rule->sr_features[i].sf_metadata) {
			switch (rule->sr_features[i].sf_type) {
			case integriforce:
				integriforce_p =
				    rule->sr_features[i].sf_metadata;
				if (integriforce_p->si_hash != NULL)
					free(integriforce_p->si_hash);
				break;
			default:
				break;
			}

			free(rule->sr_features[i].sf_metadata);
		}
	}

	if (rule->sr_features)
		free(rule->sr_features);

	if (freerule)
		free(rule);
}

void
secadm_free_ruleset(secadm_rule_t *rules)
{
	secadm_rule_t *rule, *next;

	for (rule = rules; rule != NULL; rule = next) {
		next = rule->sr_next;
		secadm_free_rule(rule, 1);
	}
}
