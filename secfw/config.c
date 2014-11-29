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
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>

#include "ucl.h"
#include "secfw.h"
#include "secfw_internal.h"

secfw_rule_t *load_config(const char *config)
{
	struct ucl_parser *parser=NULL;
	secfw_rule_t *rules;
	unsigned char *map;
	size_t sz;
	int fd;
	struct stat sb;

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
		fprintf(stderr, "[-] The parser had an error: %s\n", ucl_parser_get_error(parser));
		return NULL;
	}

	rules = parse_object(parser);
	return rules;
}

secfw_rule_t *parse_object(struct ucl_parser *parser)
{
	secfw_rule_t *rules=NULL, *newrules;
	ucl_object_t *obj;
	const ucl_object_t *curobj;
	ucl_object_iter_t it=NULL;
	const char *key;

	obj = ucl_parser_get_object(parser);

	while ((curobj = ucl_iterate_object(obj, &it, 1))) {
		key = ucl_object_key(curobj);
		if (!strcmp(key, "applications")) {
			newrules = parse_applications_object(curobj);
		}
	}

	ucl_object_unref(obj);
	return NULL;
}

secfw_rule_t *parse_applications_object(const ucl_object_t *obj)
{
	const ucl_object_t *app, *appdata;
	ucl_object_iter_t it=NULL, it_data=NULL;
	secfw_rule_t *rules, *apprules;
	secfw_feature_t *features;
	const char *path, *datakey;

	while ((app = ucl_iterate_object(obj, &it, 1))) {
		path = ucl_object_key(app);
		apprules = calloc(1, sizeof(secfw_rule_t));
		if (!(apprules)) {
			return rules;
		}

		while ((appdata = ucl_iterate_object(app, &it_data, 1))) {
			datakey = ucl_object_key(appdata);
			if (!strcmp(datakey, "features")) {
				if (!(apprules->sr_features))
					parse_application_features(path, appdata, apprules);
				else
					fprintf(stderr, "[*] Warning: Extra features for \"%s\" ignored.\n", path);
			}
		}
	}

	return NULL;
}

secfw_feature_t *parse_application_features(const char *path, const ucl_object_t *obj, secfw_rule_t *rule)
{
	const ucl_object_t *feature=NULL;
	ucl_object_iter_t it=NULL;
	secfw_feature_t *features=NULL, *f;
	const char *value, *key;

	while ((feature = ucl_iterate_object(obj, &it, 1))) {
		key = ucl_object_key(feature);
		if (!strcmp(key, "aslr")) {
			bool enabled;
			ucl_object_toboolean_safe(feature, &enabled);

			f = realloc(features, sizeof(secfw_feature_t) * (rule->sr_nfeatures + 1));
			if (!(f))
				return features;

			features = f;
			features[rule->sr_nfeatures].type = enabled ? aslr_enabled : aslr_disabled;

			rule->sr_features = features;
			rule->sr_nfeatures++;
		} else {
			fprintf(stderr, "[*] Warning: Unknown feature \"%s\" ignored.\n", key);
		}
	}

	return features;
}
