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

#include <libxo/xo.h>

#include "secadm.h"

int show_action(int, char **);
int load_action(int, char **);
int flush_action(int, char **);
int add_action(int, char **);
int delete_action(int, char **);
int enable_action(int, char **);
int disable_action(int, char **);

void emit_rules_xo(secadm_rule_t **, int, int);
void emit_rules_ucl(secadm_rule_t **, int);

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
		"load",
		"<file>",
		"load ruleset",
		load_action
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
			printf("    secadm %-8s%-30s- %s\n",
			       commands[i].command,
			       commands[i].options,
			       commands[i].help);
		}
	} else if (argc >= 2 && !strcmp(argv[1], "add")) {
		if (argc == 2)
			usage(1, argv);

		if (argc == 3 && !strcmp(argv[2], "extended")) {
			printf("usage: secadm add extended <args>\n");
		} else if (argc == 3 && !strcmp(argv[2], "integriforce")) {
			printf(
			    "usage: secadm add integriforce "
			    "<path> <type> <mode> <hash>\n");
		} else if (argc == 3 && !strcmp(argv[2], "pax")) {
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
		if (!strcmp(argv[1], commands[i].command))
			return (commands[i].op(argc, argv));
	}

	usage(argc, argv);

	return (1);
}

int
show_action(int argc, char **argv)
{
	int ch, f = 0, num_rules, i, j, rn;
	secadm_rule_t **ruleset;
	char format[5];

	optind = 2;
	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		case 'f':
			strncpy(format, optarg, sizeof(format) - 1);
			f = 1;
			break;

		case '?':
		default:
			usage(1, argv);
			return (1);
		}
	}

	if ((num_rules = secadm_get_num_rules()) == -1)
		return (1);

	if (num_rules == 0)
		return (0);

	if ((ruleset = calloc(num_rules, sizeof(secadm_rule_t))) == NULL) {
		perror("calloc");
		return (1);
	}

	for (i = 0, rn = 0; i < num_rules; i++) {
		if ((ruleset[i] = secadm_get_rule(rn)) == NULL) {
			for (j = 0; j < i; j++)
				secadm_free_rule(ruleset[j]);

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

		for (i = 0; i < num_rules; i++)
			secadm_free_rule(ruleset[i]);

		free(ruleset);
		return (0);
	}

	for (i = 0; i < num_rules; i++) {
		printf("%c%d: ",
		    (ruleset[i]->sr_active ? '+' : '-'), ruleset[i]->sr_id);

		switch (ruleset[i]->sr_type) {
		case secadm_pax_rule:
			printf("pax %s %c%c%c%c\n",
			    ruleset[i]->sr_pax_data->sp_path,
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_ASLR ? 'A' : 'a'),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_MPROTECT ? 'M' : 'm'),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_PAGEEXEC ? 'P' : 'p'),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_SEGVGUARD ? 'S' : 's'));

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
	secadm_rule_t ruleset;
	int ch, jid = 0;

	if (argc < 3) {
		usage(1, argv);
		return (1);
	}

	secadm_load_ruleset(&ruleset);

	return (0);
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

	if ((rule = malloc(sizeof(secadm_rule_t))) == NULL) {
		perror("malloc");

		return (errno);
	}

	memset(rule, 0, sizeof(secadm_rule_t));

	rule_type = argv[2];

	if (!strcmp(rule_type, "pax")) {
		if ((rule->sr_pax_data = malloc(sizeof(secadm_pax_data_t))) == NULL) {
			perror("malloc");
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
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_ASLR;
				break;

			case 'A':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_ASLR;
				break;

			case 'm':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_MPROTECT;
				break;

			case 'M':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_MPROTECT;
				break;

			case 'p':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_PAGEEXEC;
				break;

			case 'P':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_PAGEEXEC;
				break;

			case 's':
				rule->sr_pax_data->sp_pax &=
				    ~SECADM_PAX_SEGVGUARD;
				break;

			case 'S':
				rule->sr_pax_data->sp_pax |=
				    SECADM_PAX_SEGVGUARD;
				break;

			default:
				fprintf(stderr, "Invalid pax flag '%c'\n", *p);
				secadm_free_rule(rule);

				return (1);
			}

			p++;
		} while (*p);
	} else if (!strcmp(rule_type, "integriforce")) {
		if (argc < 6) {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		if ((rule->sr_integriforce_data =
		     malloc(sizeof(secadm_integriforce_data_t))) == NULL) {
			perror("malloc");
			secadm_free_rule(rule);

			return (errno);
		}

		rule->sr_integriforce_data->si_path = (u_char *) argv[3];
		rule->sr_integriforce_data->si_pathsz = strlen(argv[3]);

		rule->sr_type = secadm_integriforce_rule;

		if (!strcmp(argv[4], "sha1")) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha1;
		} else if (!strcmp(argv[4], "sha256")) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha256;
		} else {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		if (!strcmp(argv[5], "soft")) {
			rule->sr_integriforce_data->si_mode = 0;
		} else if (!strcmp(argv[5], "hard")) {
			rule->sr_integriforce_data->si_mode = 1;
		} else {
			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
		}

		switch (rule->sr_integriforce_data->si_type) {
		case secadm_hash_sha1:
			if ((rule->sr_integriforce_data->si_hash =
			     malloc(SECADM_SHA1_DIGEST_LEN)) == NULL) {
				perror("malloc");
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
			     malloc(SECADM_SHA256_DIGEST_LEN)) == NULL) {
				perror("malloc");
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
	} else if (!strcmp(rule_type, "mac")) {
		printf("mac not finished yet!\n");
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

void
emit_rules_xo(secadm_rule_t **ruleset, int num_rules, int style)
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
			xo_emit(
			    "{:path/%s}/"
			    "{:aslr/%d}/"
			    "{:mprotect/%d}/"
			    "{:pageexec/%d}/"
			    "{:segvguard/%d}/",
			    ruleset[i]->sr_pax_data->sp_path,
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_ASLR ? 1 : 0),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_MPROTECT ? 1 : 0),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_PAGEEXEC ? 1 : 0),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_SEGVGUARD ? 1 : 0 ));
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
emit_rules_ucl(secadm_rule_t **ruleset, int num_rules)
{
	char hash[SECADM_SHA256_DIGEST_LEN * 2 + 1];
	int i, j;

	printf("secadm {\n");

	for (i = 0; i < num_rules; i++) {
		if (ruleset[i]->sr_type == secadm_pax_rule) {
			printf(
			    "    pax = {\n"
			    "        path = \"%s\";\n"
			    "        aslr = %s;\n"
			    "        mprotect = %s;\n"
			    "        pageexec = %s;\n"
			    "        segvguard = %s;\n    }\n",
			    ruleset[i]->sr_pax_data->sp_path,
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_ASLR ? "true" : "false"),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_MPROTECT ? "true" : "false"),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_PAGEEXEC ? "true" : "false"),
			    (ruleset[i]->sr_pax_data->sp_pax &
			     SECADM_PAX_SEGVGUARD ? "true" : "false"));
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
