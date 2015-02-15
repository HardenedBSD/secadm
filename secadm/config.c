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

#include <sys/types.h>
#include <fcntl.h>
#include <sys/pax.h>
#include <sys/stat.h>
#include <sys/pax.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>

#include "ucl.h"
#include "libsecadm.h"
#include "secadm_internal.h"

static secadm_rule_t * find_rule(secadm_rule_t *head,
    const char *path);

secadm_rule_t *
load_config(const char *config)
{
	struct ucl_parser *parser=NULL;
	secadm_rule_t *rules, *rule;
	unsigned char *map;
	size_t sz;
	int fd;
	struct stat sb;
	size_t id=0;

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (!(parser)) {
		fprintf(stderr, "[-] Could not create new parser\n");
		return (NULL);
	}

	fd = open(config, O_RDONLY);
	if (fd < 0) {
		perror("[-] open");
		fprintf(stderr, "config is %s\n", config);
		ucl_parser_free(parser);
		return (NULL);
	}

	if (fstat(fd, &sb)) {
		perror("[-] fstat");
		close(fd);
		ucl_parser_free(parser);
		return (NULL);
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		perror("[-] mmap");
		close(fd);
		ucl_parser_free(parser);
		return (NULL);
	}

	ucl_parser_add_chunk(parser, map, sb.st_size);

	munmap(map, sb.st_size);
	close(fd);

	if (ucl_parser_get_error(parser)) {
		fprintf(stderr, "[-] The parser had an error: %s\n",
		    ucl_parser_get_error(parser));
		return (NULL);
	}

	rules = parse_object(parser);

	for (rule = rules; rule != NULL; rule = rule->sr_next)
		rule->sr_id = id++;

	return (rules);
}

secadm_rule_t *
parse_object(struct ucl_parser *parser)
{
	secadm_rule_t *rules=NULL, *newrules, *rule;
	ucl_object_t *obj;
	const ucl_object_t *curobj;
	ucl_object_iter_t it=NULL;
	const char *key;

	obj = ucl_parser_get_object(parser);

	curobj = ucl_lookup_path(obj, "integriforce");
	if (curobj != NULL) {
		rules = parse_integriforce(curobj);
#if 0
		if (rules == NULL)
			return (NULL);
#endif
	}

	curobj = ucl_lookup_path(obj, "applications");
	if (curobj != NULL) {
		newrules = parse_applications_object(rules, curobj);
		if (newrules == NULL) {
			if (rules != NULL)
				secadm_free_ruleset(rules);

			return (NULL);
		}

		rules = newrules;
	}

	ucl_object_unref(obj);
	return (rules);
}

void
add_feature(secadm_rule_t *rule, const ucl_object_t *obj, secadm_feature_type_t feature)
{
	void *f;

	f = reallocarray(rule->sr_features, rule->sr_nfeatures + 1,
	    sizeof(secadm_feature_t));
	if (f == NULL)
		return;
	rule->sr_features = f;

	memset(&(rule->sr_features[rule->sr_nfeatures]), 0x00,
	    sizeof(secadm_feature_t));

	switch (feature) {
	case pageexec_enabled:
	case pageexec_disabled:
	case mprotect_enabled:
	case mprotect_disabled:
	case segvguard_enabled:
	case segvguard_disabled:
	case aslr_enabled:
	case aslr_disabled:
		rule->sr_features[rule->sr_nfeatures].type = feature;
		break;
	default:
		fprintf(stderr, "Unknown feature\n");
	}

	rule->sr_nfeatures++;
}

secadm_rule_t *
parse_applications_object(secadm_rule_t *head, const ucl_object_t *obj)
{
	const ucl_object_t *appindex, *ucl_feature, *appdata, *ucl_jails,
	    *ucl_jail;
	ucl_object_iter_t it=NULL, jailit=NULL;
	secadm_rule_t *apprule;
	const char *path, *datakey, *key;
	bool enabled;

	while ((appindex = ucl_iterate_object(obj, &it, 1))) {
		appdata = ucl_lookup_path(appindex, "path");
		if (!(appdata)) {
			free(apprule);
			fprintf(stderr, "Object does not have a path!\n");
			continue;
		}

		if (ucl_object_tostring_safe(appdata, &path) == false) {
			free(apprule);
			fprintf(stderr, "Object's path is not a string!\n");
			continue;
		}

		apprule = find_rule(head, path);
		if (apprule == NULL) {
			apprule = calloc(1, sizeof(secadm_rule_t));
			if (apprule == NULL)
				return (head);

			if (secadm_parse_path(apprule, path)) {
				fprintf(stderr, "Could not set the rule's path!\n");
				free(apprule);
				continue;
			}

			if (head) {
				apprule->sr_next = head->sr_next;
				head->sr_next = apprule;
			} else {
				head = apprule;
			}
		}

		if ((ucl_feature = ucl_lookup_path(appindex, "features.pageexec")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? pageexec_enabled : pageexec_disabled);
		}

		if ((ucl_feature = ucl_lookup_path(appindex, "features.mprotect")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? mprotect_enabled : mprotect_disabled);
		}

		if ((ucl_feature = ucl_lookup_path(appindex, "features.segvguard")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? segvguard_enabled : segvguard_disabled);
		}

		if ((ucl_feature = ucl_lookup_path(appindex, "features.aslr")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? aslr_enabled : aslr_disabled);
		}
	}

	return (head);
}

secadm_rule_t *
parse_integriforce(const ucl_object_t *uclintegriforce)
{
	const ucl_object_t *index, *ucldata, *files;
	ucl_object_iter_t it=NULL;
	secadm_rule_t *head=NULL, *rule;
	secadm_integriforce_mode_t defmode;
	secadm_feature_t *feature;
	secadm_integriforce_t *metadata;
	const char *path, *data;

	defmode = DEFAULT_MODE;
	ucldata = ucl_lookup_path(uclintegriforce, "enforcing");
	if (ucldata != NULL) {
		if (ucl_object_tostring_safe(ucldata, &data) == false) {
			fprintf(stderr, "Eforcing mode must be a string.\n");
			return (NULL);
		}

		defmode = convert_to_integriforce_mode(data);
	}

	files = ucl_lookup_path(uclintegriforce, "files");

	while ((index = ucl_iterate_object(files, &it, 1))) {
		ucldata = ucl_lookup_path(index, "path");
		if (!(ucldata)) {
			fprintf(stderr, "Object does not have a path!\n");
			continue;
		}

		if (ucl_object_tostring_safe(ucldata, &path) == false) {
			fprintf(stderr, "Object's path is not a string!\n");
			continue;
		}

		rule = calloc(1, sizeof(secadm_rule_t));
		if (rule == NULL)
			return (head);

		if (secadm_parse_path(rule, path)) {
			fprintf(stderr, "Could not set the rule's path!\n");
			free(rule);
			continue;
		}

		metadata = calloc(1, sizeof(secadm_integriforce_t));
		if (metadata == NULL)
			return (head);

		ucldata = ucl_lookup_path(index, "hash_type");
		if (ucldata == NULL) {
			free(rule);
			free(metadata);
			fprintf(stderr, "hash_type (md5, sha1, sha256) not specified for integriforce path %s\n",
			    path);
			continue;
		}

		if (ucl_object_tostring_safe(ucldata, &data) == false) {
			free(rule);
			free(metadata);
			fprintf(stderr, "hash_type must be a string.\n");
			continue;
		}

		metadata->si_hashtype = convert_to_hash_type(data);
		if (metadata->si_hashtype == invalid_hash) {
			free(rule);
			free(metadata);
			fprintf(stderr, "Invalid hash type\n");
			continue;
		}

		ucldata = ucl_lookup_path(index, "hash");
		if (ucldata == NULL) {
			free(rule);
			free(metadata);
			fprintf(stderr, "No hash specified\n");
			continue;
		}

		if (ucl_object_tostring_safe(ucldata, &data) == false) {
			free(rule);
			free(metadata);
			fprintf(stderr, "hash must be a string\n");
			continue;
		}

		metadata->si_hash = strdup(data);
		if (!(metadata->si_hash)) {
			free(rule);
			free(metadata);
			return (head);
		}

		metadata->si_mode = defmode;
		ucldata = ucl_lookup_path(index, "enforcing");
		if (ucldata != NULL)
			if (ucl_object_tostring_safe(ucldata, &data))
				metadata->si_mode = convert_to_integriforce_mode(data);

		feature = calloc(1, sizeof(secadm_feature_t));
		if (feature == NULL) {
			free(rule);
			free(metadata);
			return (head);
		}

		feature->metadata = metadata;
		feature->type = integriforce;
		feature->metadatasz = sizeof(secadm_integriforce_t);

		rule->sr_features = feature;
		rule->sr_nfeatures++;

		if (head) {
			rule->sr_next = head->sr_next;
			head->sr_next = rule;
		} else {
			head = rule;
		}
	}

	return (NULL);
}

static secadm_rule_t *
find_rule(secadm_rule_t *head, const char *path)
{
	secadm_rule_t *rule;

	for (rule = head; rule != NULL; rule = rule->sr_next)
		if (!strcmp(rule->sr_path, path))
			break;

	return (rule);
}
