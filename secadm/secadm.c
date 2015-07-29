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

#include "secadm.h"

int show_action(int, char **);
int load_action(int, char **);
int flush_action(int, char **);
int add_action(int, char **);
int delete_action(int, char **);
int enable_action(int, char **);
int disable_action(int, char **);

typedef int (*command_t)(int, char **);

struct secadm_commands {
	const char	*subcommand;
	const char	*options;
	const char	*help;
	command_t	 op;
} commands[] = {
	{
		"show",
		"[-f json|xml]",
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
			       commands[i].subcommand,
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
		if (!strcmp(argv[1], commands[i].subcommand))
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

	for (i = 0; i < num_rules; i++) {
		printf("Jail #%d Rule #%d\n", ruleset[i]->sr_jid, ruleset[i]->sr_id);
		printf("\tEnabled: %s\n", ruleset[i]->sr_active ? "Yes" : "No");

		switch (ruleset[i]->sr_type) {
		case secadm_pax_rule:
			printf("\tType: Feature\n");
			break;

		case secadm_integriforce_rule:
			printf("\tType: Integriforce\n");
			break;

		case secadm_extended_rule:
			printf("\tType: MAC\n");
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
		if ((rule->sr_integriforce_data =
		     malloc(sizeof(secadm_integriforce_data_t))) == NULL) {
			perror("malloc");
			secadm_free_rule(rule);

			return (errno);
		}

		rule->sr_integriforce_data->si_path = (u_char *) argv[1];
		rule->sr_integriforce_data->si_pathsz = strlen(argv[1]);

		rule->sr_type = secadm_integriforce_rule;

		if (!strcmp(argv[2], "sha1")) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha1;
			rule->sr_integriforce_data->si_hash = (u_char *) argv[3];
		} else if (!strcmp(argv[2], "sha256")) {
			rule->sr_integriforce_data->si_type = secadm_hash_sha256;
			rule->sr_integriforce_data->si_hash = (u_char *) argv[3];
		} else {
			argv -= optind;

			usage(3, argv);
			secadm_free_rule(rule);

			return (1);
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
