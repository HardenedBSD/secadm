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
			xo_set_style(NULL, XO_STYLE_JSON);
		} else if (!strncmp(format, "xml", sizeof(format))) {
			xo_set_style(NULL, XO_STYLE_XML);
		} else if (!strncmp(format, "ucl", sizeof(format))) {
			printf("nope :)\n");
			return (0);
		}

		xo_set_flags(NULL, XOF_DTRT | XOF_PRETTY | XOF_FLUSH);

		xo_open_container("secadm");
		xo_open_list("pax");
		for (i = 0; i < num_rules; i++) {
			if (ruleset[i]->sr_type ==
			    secadm_pax_rule) {
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
			if (ruleset[i]->sr_type ==
			    secadm_integriforce_rule) {
				xo_open_instance("integriforce");
				xo_emit(
				    "{:path/%s}"
				    "{:hash/%s}"
				    "{:mode/%s}"
				    "{:type/%s}",
				    ruleset[i]->sr_integriforce_data->si_path,
				    ruleset[i]->sr_integriforce_data->si_hash,
				    (ruleset[i]->sr_integriforce_data->si_type
				     == 0 ? "soft" : "hard"),
				    (ruleset[i]->sr_integriforce_data->si_mode
				     == secadm_hash_sha1 ? "sha1" : "sha256"));
				xo_close_instance_d();
			}
		}
		xo_close_list_d();
		xo_close_container_d();
		xo_finish();

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
			printf("integriforce %s %s %s %s\n",
			    ruleset[i]->sr_integriforce_data->si_path,
			    (ruleset[i]->sr_integriforce_data->si_type ==
			     secadm_hash_sha1 ? "sha1" : "sha256"),
			    (ruleset[i]->sr_integriforce_data->si_mode ==
			     0 ? "soft" : "hard"),
			    ruleset[i]->sr_integriforce_data->si_hash);

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
