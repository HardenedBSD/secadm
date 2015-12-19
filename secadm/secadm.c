/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
 * Copyright (c) 2015 Brian Salecdo <brian.salcedo@hardenedbsd.org>
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libxo/xo.h>
#include <ucl.h>

#include "secadm.h"

int show_action(int, char **);
int load_action(int, char **);
int validate_action(int, char **);
int flush_action(int, char **);
int add_action(int, char **);
int delete_action(int, char **);
int enable_action(int, char **);
int disable_action(int, char **);
int version_action(int, char **);

void free_ruleset(secadm_rule_t *);

void emit_rules_xo(secadm_rule_t **, size_t, int);
void emit_rules_ucl(secadm_rule_t **, size_t);

int parse_pax_object(const ucl_object_t *, secadm_rule_t *);
int parse_integriforce_object(const ucl_object_t *, secadm_rule_t *);

static int validate = 0;

typedef int (*command_t)(int, char **);

struct secadm_commands {
	const char	*command;
	const char	*options;
	const char	*help;
	command_t	 op;
} commands[] = {
	{
		"show",
		"[-f json|ucl|xml]",
		"show loaded ruleset",
		show_action
	},
	{
		"list",
		"[-f json|ucl|xml]",
		"alias for \"show\" command",
		show_action
	},
	{
		"load",
		"<file>",
		"load ruleset",
		load_action
	},
	{
		"validate",
		"<file>",
		"validate ruleset",
		validate_action
	},
	{
		"version",
		"",
		"show version number",
		version_action
	},
	{
		"flush",
		"",
		"flush ruleset",
		flush_action
	},
	{
		"add",
		"<extended|integriforce|pax>",
		"add rule",
		add_action
	},
	{
		"del",
		"<id>",
		"delete rule",
		delete_action
	},
	{
		"enable",
		"<id>",
		"enable rule",
		enable_action
	},
	{
		"disable",
		"<id>",
		"disable rule",
		disable_action
	}
};

void
usage(int argc, char **argv)
{
	int i;

	if (argc <= 2) {
		printf("usage: secadm <command> [[modifiers] args]\n");
		for (i = 0; i < sizeof(commands) /
		    sizeof(struct secadm_commands); i++) {
			printf("    secadm %-9s%-30s- %s\n",
			    commands[i].command,
			    commands[i].options,
			    commands[i].help);
		}
	} else if (argc >= 2 && !strncmp(argv[1], "add", 3)) {
		if (argc == 2) {
			usage(1, argv);
		}

		if (argc == 3 && !strncmp(argv[2], "extended", 8)) {
			printf("usage: secadm add extended <args>\n");
		} else if (argc == 3 && !strncmp(argv[2], "integriforce", 12)) {
			printf(
			    "usage: secadm add integriforce "
			    "<path> <type> <mode> <hash>\n");
		} else if (argc == 3 && !strncmp(argv[2], "pax", 3)) {
			printf("usage: secadm add pax <path> <flags>\n");
		} else {
			usage(1, argv);
		}
	} else {
		usage(1, argv);
	}
}

int
main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		usage(argc, argv);
		return (1);
	}

	for (i = 0; i < sizeof(commands) /
	    sizeof(struct secadm_commands); i++) {
		if (!strncmp(argv[1], commands[i].command, 9)) {
			return (commands[i].op(argc, argv));
		}
	}

	usage(argc, argv);

	return (1);
}

int
show_action(int argc, char **argv)
{
	int ch, f = 0;
	secadm_rule_t **ruleset;
	size_t num_rules, i, j, rn;
	char format[5];

	optind = 2;
	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		case 'f':
			strncpy(format, optarg, sizeof(format) - 1);
			format[sizeof(format) - 1] = '\0';
			f = 1;
			break;

		case '?':
		default:
			usage(1, argv);
			return (1);
		}
	}

	if ((num_rules = secadm_get_num_rules()) == -1) {
		return (1);
	}

	if (num_rules == 0) {
		return (0);
	}

	if ((ruleset = calloc(num_rules, sizeof(secadm_rule_t))) == NULL) {
		perror("calloc");
		return (1);
	}

	for (i = 0, rn = 0; i < num_rules; i++) {
		if ((ruleset[i] = secadm_get_rule(rn)) == NULL) {
			for (j = 0; j < i; j++) {
				secadm_free_rule(ruleset[j]);
			}

			free(ruleset);
			return (1);
		}

		rn = ruleset[i]->sr_id + 1;
	}

	if (f) {
		if (!strncmp(format, "json", sizeof(format))) {
			emit_rules_xo(ruleset, num_rules, XO_STYLE_JSON);
		} else if (!strncmp(format, "xml", sizeof(format))) {
			emit_rules_xo(ruleset, num_rules, XO_STYLE_XML);
			xo_set_style(NULL, XO_STYLE_XML);
		} else if (!strncmp(format, "ucl", sizeof(format))) {
			emit_rules_ucl(ruleset, num_rules);
		} else {
			usage(1, argv);
		}

		for (i = 0; i < num_rules; i++) {
			secadm_free_rule(ruleset[i]);
		}

		free(ruleset);
		return (0);
	}

	for (i = 0; i < num_rules; i++) {
		printf("%c%d: ",
		    (ruleset[i]->sr_active ? '+' : '-'), ruleset[i]->sr_id);

		switch (ruleset[i]->sr_type) {
		case secadm_pax_rule:
			printf("pax %s ",
			    ruleset[i]->sr_pax_data->sp_path);
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_ASLR_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_ASLR ? 'A' : 'a'));
			}

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MAP32_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MAP32 ? 'B' : 'b'));
			}

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SHLIBRANDOM_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SHLIBRANDOM ? 'L' : 'l'));
			}

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MPROTECT_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MPROTECT ? 'M' : 'm'));
			}

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_PAGEEXEC_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_PAGEEXEC ? 'P' : 'p'));
			}

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SEGVGUARD_SET) {
				printf("%c",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SEGVGUARD ? 'S' : 's'));
			}

			printf("\n");

			break;

		case secadm_integriforce_rule:
			printf("integriforce %s %s %s ",
			    ruleset[i]->sr_integriforce_data->si_path,
			    (ruleset[i]->sr_integriforce_data->si_type ==
			     secadm_hash_sha1 ? "sha1" : "sha256"),
			    (ruleset[i]->sr_integriforce_data->si_mode ==
			     0 ? "soft" : "hard"));

			switch (ruleset[i]->sr_integriforce_data->si_type) {
			case secadm_hash_sha1:
				for (j = 0; j < SECADM_SHA1_DIGEST_LEN; j++) {
					printf("%02x",
					    ruleset[i]->sr_integriforce_data->si_hash[j]);
				}

				break;

			case secadm_hash_sha256:
				for (j = 0; j < SECADM_SHA256_DIGEST_LEN; j++) {
					printf("%02x",
					    ruleset[i]->sr_integriforce_data->si_hash[j]);
				}
			}

			printf("\n");
			break;

		case secadm_extended_rule:
			printf("extended\n");
			break;
		}

		secadm_free_rule(ruleset[i]);
	}

	free(ruleset);
	return (0);
}

int
load_action(int argc, char **argv)
{
	const ucl_object_t *top, *section, *cur;
	secadm_rule_t *ruleset, *rule, *r;
	ucl_object_iter_t it = NULL;
	struct ucl_parser *parser;
	int n = 0, err;

	if (argc < 3) {
		usage(1, argv);
		return (1);
	}

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (parser == NULL) {
		fprintf(stderr, "Could not create new parser.\n");
		return (1);
	}

	if (ucl_parser_add_file(parser, argv[2]) == false) {
		fprintf(stderr, "Could not parse: %s\n", ucl_parser_get_error(parser));
		ucl_parser_free(parser);

		return (1);
	}

	top = ucl_parser_get_object(parser);
	if (top == NULL) {
		fprintf(stderr, "Nothing to load.\n");
		ucl_parser_free(parser);

		return (1);
	}

	section = ucl_lookup_path(top, "secadm.pax");
	if (section) {
		while ((cur = ucl_iterate_object(section, &it, false))) {
			if ((r =
			    calloc(1, sizeof(secadm_rule_t))) == NULL) {
				perror("calloc");
				ucl_parser_free(parser);
				free_ruleset(ruleset);

				return (1);
			}

			r->sr_type = secadm_pax_rule;
			if (parse_pax_object(cur, r)) {
				ucl_parser_free(parser);
				free_ruleset(ruleset);

				return (1);
			}

			if ((err = secadm_validate_rule(r))) {
				ucl_parser_free(parser);
				free_ruleset(ruleset);

				return (err);
			}

			if (n == 0) {
				ruleset = rule = r;
			} else {
				rule->sr_next = r;
				rule = r;
			}

			n++;
		}
	}

	it = NULL;
	section = ucl_lookup_path(top, "secadm.integriforce");
	if (section) {
		while ((cur = ucl_iterate_object(section, &it, false))) {
			if ((r= calloc(1, sizeof(secadm_rule_t)))
			    == NULL) {
				perror("calloc");
				ucl_parser_free(parser);
				return (1);
			}

			memset(r, 0, sizeof(secadm_rule_t));

			r->sr_type = secadm_integriforce_rule;
			if (parse_integriforce_object(cur, r)) {
				ucl_parser_free(parser);
				free_ruleset(ruleset);
				return (1);
			}

			if ((err = secadm_validate_rule(r))) {
				ucl_parser_free(parser);
				free_ruleset(ruleset);

				return (err);
			}

			if (n == 0) {
				ruleset = rule = r;
			} else {
				rule->sr_next = r;
				rule = r;
			}

			n++;
		}
	}

	if (n == 0) {
		fprintf(stderr, "No rules.\n");
		ucl_parser_free(parser);

		return (1);
	}

	ucl_parser_free(parser);

	if (validate == 0)
		secadm_load_ruleset(ruleset);

	return (0);
}

int
validate_action(int argc, char **argv)
{
	validate = 1;
	return (load_action(argc, argv));
}

int
flush_action(int argc, char **argv)
{
	return (secadm_flush_ruleset());
}

int
add_action(int argc, char **argv)
{
	secadm_rule_t *rule;
	char *rule_type, *p;
	u_int val;
	int i;

	if (argc <= 3) {
		usage(argc, argv);
		return (1);
	}

	if ((rule = calloc(1, sizeof(secadm_rule_t))) == NULL) {
		perror("calloc");

		return (errno);
	}

	rule_type = argv[2];

	if (!strncmp(rule_type, "pax", 3)) {
		if (argc < 5) {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		if ((rule->sr_pax_data = calloc(1, sizeof(secadm_pax_data_t))) == NULL) {
			perror("calloc");
			secadm_free_rule(rule);

			return (errno);
		}

		rule->sr_pax_data->sp_path = (u_char *) argv[3];
		rule->sr_pax_data->sp_pathsz = strlen(argv[3]);
		rule->sr_pax_data->sp_pax = 0;

		rule->sr_active = 1;
		rule->sr_type = secadm_pax_rule;

		p = argv[4];
		do {
			switch (*p) {
			case 'a':
				printf("Disabling aslr\n");
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_ASLR;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_ASLR_SET;
				break;

			case 'A':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_ASLR;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_ASLR_SET;
				break;
			case 'b':
				rule->sr_pax_data->sp_pax &=
				    ~(SECADM_PAX_MAP32);
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MAP32_SET;
				break;

			case 'B':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_MAP32;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MAP32_SET;
				break;

			case 'l':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_SHLIBRANDOM;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_SHLIBRANDOM_SET;
				break;

			case 'L':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_SHLIBRANDOM;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_SHLIBRANDOM_SET;
				break;

			case 'm':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_MPROTECT;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MPROTECT_SET;
				break;

			case 'M':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_MPROTECT;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MPROTECT_SET;
				break;

			case 'p':
				/* mprotect requires pageexec */
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_MPROTECT;
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_PAGEEXEC;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MPROTECT_SET;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_PAGEEXEC_SET;
				break;

			case 'P':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_PAGEEXEC;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_PAGEEXEC_SET;
				break;

			case 's':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_SEGVGUARD;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_SEGVGUARD_SET;
				break;

			case 'S':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_SEGVGUARD;
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_SEGVGUARD_SET;
				break;

			default:
				fprintf(stderr, "Invalid pax flag '%c'\n", *p);
				secadm_free_rule(rule);

				return (1);
			}

			p++;
		} while (*p);
	} else if (!strncmp(rule_type, "integriforce", 12)) {
		if (argc < 6) {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		if ((rule->sr_integriforce_data =
		    calloc(1, sizeof(secadm_integriforce_data_t))) == NULL) {
			perror("calloc");
			secadm_free_rule(rule);

			return (errno);
		}

		rule->sr_integriforce_data->si_path = (u_char *) argv[3];
		rule->sr_integriforce_data->si_pathsz = strlen(argv[3]);

		rule->sr_type = secadm_integriforce_rule;

		if (!strncmp(argv[4], "sha1", 4)) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha1;
		} else if (!strncmp(argv[4], "sha256", 6)) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha256;
		} else {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		if (!strncmp(argv[5], "soft", 4)) {
			rule->sr_integriforce_data->si_mode = 0;
		} else if (!strncmp(argv[5], "hard", 4)) {
			rule->sr_integriforce_data->si_mode = 1;
		} else {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		switch (rule->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			if ((rule->sr_integriforce_data->si_hash =
			    calloc(1, SECADM_SHA1_DIGEST_LEN)) == NULL) {
				perror("calloc");
				secadm_free_rule(rule);

				return (1);
			}

			if (strlen(argv[6]) != SECADM_SHA1_DIGEST_LEN * 2) {
				fprintf(stderr, "Invalid hash.\n");
				secadm_free_rule(rule);

				return (1);
			}

			for (i = 0; i < 40; i += 2) {
				if (sscanf(&argv[6][i], "%02x", &val) == 0) {
					fprintf(stderr, "Invalid hash.\n");
					secadm_free_rule(rule);

					return (1);
				}

				rule->sr_integriforce_data->si_hash[i / 2] =
				    (val & 0xff);
			}

			break;

		case secadm_hash_sha256:
			if ((rule->sr_integriforce_data->si_hash =
			    calloc(1, SECADM_SHA256_DIGEST_LEN)) == NULL) {
				perror("calloc");
				secadm_free_rule(rule);

				return (1);
			}

			if (strlen(argv[6]) != SECADM_SHA256_DIGEST_LEN * 2) {
				fprintf(stderr, "Invalid hash.\n");
				secadm_free_rule(rule);

				return (1);
			}

			for (i = 0; i < 64; i += 2) {
				if (sscanf(&argv[6][i], "%02x", &val) == 0) {
					fprintf(stderr, "Invalid hash.\n");
					secadm_free_rule(rule);

					return (1);
				}

				rule->sr_integriforce_data->si_hash[i / 2] =
				    (val & 0xff);
			}
		}
	} else if (!strncmp(rule_type, "extended", 8)) {
		printf("extended not finished yet!\n");
		rule->sr_type = secadm_extended_rule;
	} else {
		secadm_free_rule(rule);
		usage(1, argv);

		return (1);
	}

	secadm_add_rule(rule);
	secadm_free_rule(rule);

	return (0);
}

int
delete_action(int argc, char **argv)
{
	int ruleid;

	if (argc < 3) {
		usage(1, argv);
		return (1);
	}

	ruleid = strtol(argv[2], (char **)NULL, 10);

	secadm_del_rule(ruleid);

	return (0);
}

int
enable_action(int argc, char **argv)
{
	int ruleid;

	if (argc < 3) {
		usage(1, argv);
		return (1);
	}

	ruleid = strtol(argv[2], (char **)NULL, 10);

	secadm_enable_rule(ruleid);

	return (0);
}

int
disable_action(int argc, char **argv)
{
	int ruleid;

	if (argc < 3) {
		usage(1, argv);
		return (1);
	}

	ruleid = strtol(argv[2], (char **)NULL, 10);

	secadm_disable_rule(ruleid);

	return (0);
}

int
version_action(int argc, char **argv)
{
	printf("%s\n", SECADM_PRETTY_VERSION);
	return (0);
}

void
emit_rules_xo(secadm_rule_t **ruleset, size_t num_rules, int style)
{
	char hash[SECADM_SHA256_DIGEST_LEN * 2 + 1];
	int i, j;

	xo_set_style(NULL, style);
	xo_set_flags(NULL, XOF_DTRT | XOF_FLUSH | XOF_PRETTY);

	xo_open_container("secadm");
	xo_open_list("pax");

	for (i = 0; i < num_rules; i++) {
		if (ruleset[i]->sr_type == secadm_pax_rule) {
			xo_open_instance("pax");
			xo_emit( "{:path/%s}/",
			    ruleset[i]->sr_pax_data->sp_path);

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_ASLR_SET) {
				xo_emit("{:aslr/%d}/",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_ASLR ? 1 : 0));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MAP32_SET) {
				xo_emit("{:disallow_map32bit/%d/}",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MAP32 ? 1 : 0));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MPROTECT_SET) {
				xo_emit("{:mprotect/%d}/",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MPROTECT ? 1 : 0));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_PAGEEXEC_SET) {
				xo_emit("{:pageexec/%d}/",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_PAGEEXEC ? 1 : 0));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SEGVGUARD_SET) {
				xo_emit("{:segvguard/%d}/",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SEGVGUARD ? 1 : 0 ));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SHLIBRANDOM_SET) {
				xo_emit("{:shlibrandom/%d/",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SHLIBRANDOM ? 1 : 0));
			}

			xo_close_instance_d();
		}
	}

	xo_close_list_d();

	for (i = 0; i < num_rules; i++) {
		if (ruleset[i]->sr_type == secadm_integriforce_rule) {
			for (j = 0;
			     j < (ruleset[i]->sr_integriforce_data->si_type ==
			     secadm_hash_sha1 ?
			     SECADM_SHA1_DIGEST_LEN :
			     SECADM_SHA256_DIGEST_LEN); j++) {
				snprintf(&hash[j * 2], 3, "%02x",
				    ruleset[i]->sr_integriforce_data->si_hash[j]);
			}

			xo_open_instance("integriforce");
			xo_emit(
			    "{:path/%s}"
			    "{:hash/%s}"
			    "{:type/%s}"
			    "{:mode/%s}",
			    ruleset[i]->sr_integriforce_data->si_path,
			    hash,
			    (ruleset[i]->sr_integriforce_data->si_type ==
			     0 ? "sha1" : "sha256"),
			    (ruleset[i]->sr_integriforce_data->si_mode ==
			     secadm_hash_sha1 ? "soft" : "hard"));
			xo_close_instance_d();
		}
	}

	xo_close_list_d();
	xo_close_container_d();
	xo_finish();
}

void
emit_rules_ucl(secadm_rule_t **ruleset, size_t num_rules)
{
	char hash[SECADM_SHA256_DIGEST_LEN * 2 + 1];
	size_t i, j;

	printf("secadm {\n");

	for (i = 0; i < num_rules; i++) {
		if (ruleset[i]->sr_type == secadm_pax_rule) {
			printf("    pax = {\n"
			    "        path = \"%s\";\n",
			    ruleset[i]->sr_pax_data->sp_path);

			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_ASLR_SET) {
				printf( "        aslr = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_ASLR ? "true" : "false"));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MAP32_SET) {
				printf("        disallow_map32bit = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MAP32 ? "true" : "false"));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_MPROTECT_SET) {
				printf("        mprotect = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_MPROTECT ? "true" : "false"));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_PAGEEXEC_SET) {
				printf("        pageexec = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_PAGEEXEC ? "true" : "false"));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SEGVGUARD_SET) {
				printf("        segvguard = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SEGVGUARD ? "true" : "false"));
			}
			if (ruleset[i]->sr_pax_data->sp_pax_set &
			    SECADM_PAX_SHLIBRANDOM_SET) {
				printf("        shlibrandom = %s;\n",
				    (ruleset[i]->sr_pax_data->sp_pax &
				    SECADM_PAX_SHLIBRANDOM ? "true" : "false"));
			}

			printf("    }\n");
		}
	}

	for (i = 0; i < num_rules; i++) {
		if (ruleset[i]->sr_type == secadm_integriforce_rule) {
			for (j = 0;
			     j < (ruleset[i]->sr_integriforce_data->si_type ==
			     secadm_hash_sha1 ?
			     SECADM_SHA1_DIGEST_LEN :
			     SECADM_SHA256_DIGEST_LEN); j++) {
				snprintf(&hash[j * 2], 3, "%02x",
				    ruleset[i]->sr_integriforce_data->si_hash[j]);
			}

			printf(
			    "    integriforce = {\n"
			    "        path = \"%s\";\n"
			    "        hash = \"%s\";\n"
			    "        type = \"%s\";\n"
			    "        mode = \"%s\";\n    }\n",
			    ruleset[i]->sr_integriforce_data->si_path,
			    hash,
			    (ruleset[i]->sr_integriforce_data->si_type ==
			     0 ? "sha1" : "sha256"),
			    (ruleset[i]->sr_integriforce_data->si_mode ==
			     secadm_hash_sha1 ? "soft" : "hard"));
		}
	}

	printf("}\n");
}

void
free_ruleset(secadm_rule_t *ruleset)
{
	secadm_rule_t *rule, *next;

	if (ruleset == NULL)
		return;

	rule = next = ruleset;

	do {
		next = rule->sr_next;
		secadm_free_rule(rule);
		rule = next;
	} while (rule != NULL);
}

int
parse_pax_object(const ucl_object_t *obj, secadm_rule_t *rule)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	const char *key;
	struct stat sb;

	if ((rule->sr_pax_data = calloc(1, sizeof(secadm_pax_data_t))) == NULL) {
		perror("calloc");
		return (1);
	}

	while ((cur = ucl_iterate_object(obj, &it, true))) {
		key = ucl_object_key(cur);

		if (!strncmp(key, "path", 4)) {
			rule->sr_pax_data->sp_path =
			    (u_char *)ucl_object_tostring(cur);
		} else if (!strncmp(key, "aslr", 4)) {
			rule->sr_pax_data->sp_pax_set |=
			    SECADM_PAX_ASLR_SET;
			if (ucl_object_toboolean(cur))
				rule->sr_pax_data->sp_pax |= SECADM_PAX_ASLR;
		} else if (!strncmp(key, "mprotect", 8)) {
			rule->sr_pax_data->sp_pax_set |=
			    SECADM_PAX_MPROTECT_SET;
			if (ucl_object_toboolean(cur))
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_MPROTECT;
		} else if (!strncmp(key, "pageexec", 8)) {
			rule->sr_pax_data->sp_pax_set |=
			    (SECADM_PAX_MPROTECT_SET |
			    SECADM_PAX_PAGEEXEC_SET);
			if (ucl_object_toboolean(cur)) {
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_PAGEEXEC;
			} else {
				/* PaX mprotect requires pagexec */
				rule->sr_pax_data->sp_pax_set |=
				    SECADM_PAX_MPROTECT_SET;
				rule->sr_pax_data->sp_pax &=
				    ~(SECADM_PAX_MPROTECT);
				rule->sr_pax_data->sp_pax &=
				    ~(SECADM_PAX_PAGEEXEC);
			}
		} else if (!strncmp(key, "segvguard", 9)) {
			rule->sr_pax_data->sp_pax_set |=
			    SECADM_PAX_SEGVGUARD_SET;
			if (ucl_object_toboolean(cur))
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_SEGVGUARD;
		} else if (!strncmp(key, "shlibrandom", 11)) {
			rule->sr_pax_data->sp_pax_set |=
			    SECADM_PAX_SHLIBRANDOM_SET;
			if (ucl_object_toboolean(cur))
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_SHLIBRANDOM;
		} else if (!strncmp(key, "disallow_map32bit", 17)) {
			rule->sr_pax_data->sp_pax_set |=
			    SECADM_PAX_MAP32_SET;
			if (ucl_object_toboolean(cur))
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_MAP32;
		} else {
			fprintf(stderr,
			    "Unknown attribute '%s' of PaX rule.\n", key);
			return (1);
		}
	}

	return (0);
}

int parse_integriforce_object(const ucl_object_t *obj, secadm_rule_t *rule)
{
	const char *mode, *type, *hash;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;
	const char *key;
	struct stat sb;
	u_int val;
	int i;

	if ((rule->sr_integriforce_data =
	    calloc(1, sizeof(secadm_integriforce_data_t))) == NULL) {
		perror("calloc");
		return (1);
	}

	memset(rule->sr_integriforce_data, 0, sizeof(secadm_integriforce_data_t));

	while ((cur = ucl_iterate_object(obj, &it, true))) {
		key = ucl_object_key(cur);

		if (!strncmp(key, "path", 4)) {
			rule->sr_integriforce_data->si_path =
			    (u_char *)ucl_object_tostring(cur);
		} else if (!strncmp(key, "hash", 4)) {
			hash = ucl_object_tostring(cur);
		} else if (!strncmp(key, "type", 4)) {
			type = ucl_object_tostring(cur);
		} else if (!strncmp(key, "mode", 4)) {
			mode = ucl_object_tostring(cur);
		} else {
			fprintf(stderr,
			    "Unknown attribute '%s' of Integriforce rule.\n", key);
			return (1);
		}
	}

	if (!strncmp(type, "sha1", 4)) {
		rule->sr_integriforce_data->si_type = secadm_hash_sha1;
	} else if (!strncmp(type, "sha256", 6)) {
		rule->sr_integriforce_data->si_type = secadm_hash_sha256;
	} else {
		fprintf(stderr, "Integriforce rule has invalid hash type.\n");
		return (1);
	}

	if (!strncmp(mode, "soft", 4)) {
		rule->sr_integriforce_data->si_mode = 0;
	} else if (!strncmp(mode, "hard", 4)) {
		rule->sr_integriforce_data->si_mode = 1;
	} else {
		fprintf(stderr, "Integriforce rule has invalid mode.\n");
		return (1);
	}

	switch (rule->sr_integriforce_data->si_type) {
	case secadm_hash_sha1:
		if ((rule->sr_integriforce_data->si_hash =
		    calloc(1, SECADM_SHA1_DIGEST_LEN)) == NULL) {
			perror("calloc");
			secadm_free_rule(rule);

			return (1);
		}

		if (strlen(hash) != SECADM_SHA1_DIGEST_LEN * 2) {
			fprintf(stderr,
			    "Integriforce rule has invalid hash: %s\n",
			    rule->sr_integriforce_data->si_path);
			secadm_free_rule(rule);

			return (1);
		}

		for (i = 0; i < 40; i += 2) {
			if (sscanf(&hash[i], "%02x", &val) == 0) {
				fprintf(stderr, "Invalid hash.\n");
				return (1);
			}

			rule->sr_integriforce_data->si_hash[i / 2] =
			    (val & 0xff);
		}

		break;

	case secadm_hash_sha256:
		if ((rule->sr_integriforce_data->si_hash =
		     calloc(1, SECADM_SHA256_DIGEST_LEN)) == NULL) {
			perror("calloc");
			return (1);
		}

		if (strlen(hash) != SECADM_SHA256_DIGEST_LEN * 2) {
			fprintf(stderr,
			    "Integriforce rule has invalid hash: %s\n",
			    rule->sr_integriforce_data->si_path);
			secadm_free_rule(rule);

			return (1);
		}

		for (i = 0; i < 64; i += 2) {
			if (sscanf(&hash[i], "%02x", &val) == 0) {
				fprintf(stderr, "Invalid hash.\n");
				return (1);
			}

			rule->sr_integriforce_data->si_hash[i / 2] =
			    (val & 0xff);
		}
	}

	return (0);
}
