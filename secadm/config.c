/*-
 * Copyright (c) 2014, Shawn Webb
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
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>

#include "ucl.h"
#include "libsecadm.h"
#include "secadm_internal.h"

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
		return NULL;
	}

	fd = open(config, O_RDONLY);
	if (fd < 0) {
		perror("[-] open");
		fprintf(stderr, "config is %s\n", config);
		ucl_parser_free(parser);
		return NULL;
	}

	if (fstat(fd, &sb)) {
		perror("[-] fstat");
		close(fd);
		ucl_parser_free(parser);
		return NULL;
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		perror("[-] mmap");
		close(fd);
		ucl_parser_free(parser);
		return NULL;
	}

	ucl_parser_add_chunk(parser, map, sb.st_size);

	munmap(map, sb.st_size);
	close(fd);

	if (ucl_parser_get_error(parser)) {
		fprintf(stderr, "[-] The parser had an error: %s\n",
		    ucl_parser_get_error(parser));
		return NULL;
	}

	rules = parse_object(parser);

	for (rule = rules; rule != NULL; rule = rule->sr_next)
		rule->sr_id = id++;

	return rules;
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

	while ((curobj = ucl_iterate_object(obj, &it, 1))) {
		key = ucl_object_key(curobj);
		newrules=NULL;

		if (!strcmp(key, "applications")) {
			newrules = parse_applications_object(curobj);
		}

		if (newrules != NULL) {
			if (rules != NULL) {
				for (rule = rules; rule->sr_next != NULL;
				    rule = rule->sr_next)
					;

				rule->sr_next = newrules;
			} else {
				rules = newrules;
			}
		}
	}

	ucl_object_unref(obj);
	return rules;
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
parse_applications_object(const ucl_object_t *obj)
{
	const ucl_object_t *appindex, *ucl_feature, *appdata, *ucl_jails,
	    *ucl_jail;
	ucl_object_iter_t it=NULL, jailit=NULL;
	secadm_rule_t *head=NULL, *apprule;
	const char *path, *datakey, *key;
	bool enabled;

	while ((appindex = ucl_iterate_object(obj, &it, 1))) {
		apprule = calloc(1, sizeof(secadm_rule_t));
		if (!(apprule))
			return head;

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

		if (secadm_parse_path(apprule, path)) {
			fprintf(stderr, "Could not set the rule's path!\n");
			free(apprule);
			continue;
		}

#ifdef PAX_NOTE_PAGEEXEC
		if ((ucl_feature = ucl_lookup_path(appindex, "features.pageexec")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? pageexec_enabled : pageexec_disabled);
		}
#endif

#ifdef PAX_NOTE_MPROTECT
		if ((ucl_feature = ucl_lookup_path(appindex, "features.mprotect")) != NULL) {
			if (ucl_object_toboolean_safe(ucl_feature, &enabled) == true)
				add_feature(apprule, ucl_feature,
				    enabled ? mprotect_enabled : mprotect_disabled);
		}
#endif

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

		if (apprule->sr_nfeatures == 0) {
			fprintf(stderr, "Application %s has no features. Skipping application rule.\n",
			    apprule->sr_path);
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

	return head;
}
