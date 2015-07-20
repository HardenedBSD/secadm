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
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/pax.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include "ucl.h"
#include "libsecadm.h"
#include "secadm_internal.h"

typedef int (*action_t)(int, char **);

static void usage(const char *);
static void check_bsd(void);

static int listact(int, char **);
static int loadact(int, char **);
static int flushact(int, char **);
static int validateact(int, char **);
static int featuresact(int, char **);
static int enabledisableact(int, char **, int);
static int enableact(int, char **);
static int disableact(int, char **);
static int versionact(int, char **);

const char *rulesetpath=NULL;
const char *name;

struct _action {
	const char *action;
	const char *help;
	int needkld;
	action_t op;
} actions[] = {
	{
		"list",
		"\t\t- list loaded rule(s)",
		0,
		listact
	},
	{
		"load",
		"<file>\t\t- load ruleset from file",
		1,
		loadact
	},
	{
		"flush",
		"\t\t- flush ruleset",
		1,
		flushact
	},
	{
		"validate",
		"[-v] <file>\t- validate ruleset",
		0,
		validateact
	},
	{
		"features",
		"\t\t- list enabled HardenedBSD features",
		1,
		featuresact
	},
	{
		"enable",
		"<feature>\t- enable HardenedBSD feature",
		1,
		enableact
	},
	{
		"disable",
		"<feature>\t- disable HardenedDBSD feature",
		1,
		disableact
	},
	{
		"version",
		"\t\t- print secadm version",
		1,
		versionact
	}
};

static void
usage(const char *name)
{
	size_t i;

	fprintf(stderr, "usage: %s <subcommand> <args> ...\n", name);

	for (i=0; i < sizeof(actions)/sizeof(struct _action); i++)
		fprintf(stderr, "    %s %s %s\n", name, actions[i].action, actions[i].help);
}

static void
check_bsd(void)
{
	int version;
	size_t sz = sizeof(int);

	if (sysctlbyname("hardening.version", &version, &sz, NULL, 0)) {
		if (errno == ENOENT) {
			fprintf(stderr, "[-] HardenedBSD required. FreeBSD not supported.\n");
			exit(1);
		}
	}
}

static int
featuresact(int argc, char *argv[])
{
	char *features[5] = { "aslr", "mprotect", "pageexec", "segvguard", NULL };
	size_t sz = sizeof(int);
	int value, i = 0, j;
	char name[40];

	printf("[+] available features:");
	if (feature_present(FEATURE_PAX_ASLR))
		printf(" ASLR");
	if (feature_present(FEATURE_PAX_MPROTECT))
		printf(" MPROTECT");
	if (feature_present(FEATURE_PAX_PAGEEXEC))
		printf(" PAGEEXEC");
	if (feature_present(FEATURE_PAX_SEGVGUARD))
		printf(" SEGVGUARD");

	putchar('\n');

	printf("[+] enabled features:");
	do {
		snprintf(name, sizeof(name) - 1, "hardening.pax.%s.status", features[i]);

		if (sysctlbyname(name, &value, &sz, NULL, 0))
			continue;

		if (value) {
			printf(" ");
			for (j = 0; features[i][j]; j++)
				printf("%c", toupper(features[i][j]));
		}
	} while (features[++i]);

	putchar('\n');

	return (0);
}

static int
enabledisableact(int argc, char *argv[], int enable)
{
	char *what = enable ? "enable" : "disable";
	int value = enable ? 2 : 0;

	if (argc == 3) {
		if (!strcmp(argv[2], "aslr")) {
			if (sysctlbyname("hardening.pax.aslr.status", NULL, 0, &value, sizeof(int))) {
				fprintf(stderr, "[-] unable to %s ASLR: %s\n", what, strerror(errno));
				return (1);
			}

			return (0);
		}

		if (!strcmp(argv[2], "mprotect")) {
			if (sysctlbyname("hardening.pax.mprotect.status", NULL, 0, &value, sizeof(int))) {
				fprintf(stderr, "[-] unable to %s MPROTECT: %s\n", what, strerror(errno));
				return (1);
			}

			return (0);
		}

		if (!strcmp(argv[2], "pageexec")) {
			if (sysctlbyname("hardening.pax.pageexec.status", NULL, 0, &value, sizeof(int))) {
				fprintf(stderr, "[-] unable to %s PAGEEXEC: %s\n", what, strerror(errno));
				return (1);
			}

			return (0);
		}

		if (!strcmp(argv[2], "segvguard")) {
			if (enable) value = 1;

			if (sysctlbyname("hardening.pax.segvguard.status", NULL, 0, &value, sizeof(int))) {
				fprintf(stderr, "[-] unable to %s SEGVGUARD: %s\n", what, strerror(errno));
				return (1);
			}

			return (0);
		}
	}

	fprintf(stderr, "usage: %s %s <feature>\n"
			"    aslr\t- Address Space Layout Randomization\n"
			"    mprotect\t- mprotect() hardening\n"
			"    pageexec\t- memory W^X enforcement\n"
			"    segvguard\t- SEGVGUARD\n", name, what);

	return (1);
}

static int
enableact(int argc, char *argv[])
{
	return (enabledisableact(argc, argv, 1));
}

static int
disableact(int argc, char *argv[])
{
	return (enabledisableact(argc, argv, 0));
}

static int
versionact(int argc, char *argv[])
{
	unsigned long version;

	fprintf(stderr, "[+] secadm version: %s\n",
	    SECADM_PRETTY_VERSION);

	version = secadm_kernel_version();
	if (version)
		fprintf(stderr, "[+] secadm kernel module version: %lu\n",
		    version);

	return (0);
}

static int
listact(int argc, char *argv[])
{
	secadm_rule_t *rule;
	size_t nrules, i;

	if (kldfind(SECADM_KLDNAME) == -1) {
		fprintf(stderr, "[-] secadm module not loaded\n");
		return (1);
	}

	nrules = secadm_get_num_kernel_rules();
	for (i=0; i < nrules; i++) {
		rule = secadm_get_kernel_rule(i);
		if (!(rule)) {
			fprintf(stderr, "[-] could not get rule %zu from the kernel.\n", i);
			free(rule);
			return (1);
		}

		secadm_debug_print_rule(rule);
		free(rule);
	}

	return (0);
}

static int
loadact(int argc, char *argv[])
{
	secadm_rule_t *rules;
	struct stat sb;

	if (argc < 3) {
		usage(name);
		return (1);
	}

	rulesetpath = argv[2];

	if (!(rulesetpath))
		rulesetpath = DEFCONFIG;

	if (stat(rulesetpath, &sb)) {
		fprintf(stderr, "[-] could not open the ruleset file: %s\n", strerror(errno));
		return (1);
	}

	rules = load_config(rulesetpath);
	if (rules == NULL) {
		fprintf(stderr, "[-] could not load the ruleset file\n");
		return (1);
	}

	if (secadm_add_rules(rules)) {
		fprintf(stderr, "[-] could not load the rules\n");
		return (1);
	}

	free(rules);

	return (0);
}

static int
validateact(int argc, char *argv[])
{
	secadm_rule_t *rules;
	struct stat sb;
	int ch, res, verbose = 0;

	if (argc < 3) {
		usage(name);
		return (1);
	}

	if (!strcmp(argv[2], "-v")) {
		if (argc != 4) {
			usage(name);
			return (1);
		}

		rulesetpath = argv[3];
		verbose = 1;
	} else rulesetpath = argv[2];

	if (!(rulesetpath))
		rulesetpath = DEFCONFIG;

	if (stat(rulesetpath, &sb)) {
		fprintf(stderr, "[-] could not open the ruleset file: %s\n", strerror(errno));
		usage(name);
		return (1);
	}

	rules = load_config(rulesetpath);
	if (rules == NULL) {
		fprintf(stderr, "[-] could not load the ruleset file\n");
		return (1);
	}

	if (verbose) secadm_debug_print_rules(rules);

	res = secadm_validate_ruleset(rules);
	secadm_free_ruleset(rules);

	return (res);
}

static int
flushact(int argc, char *argv[])
{
	return ((int)secadm_flush_all_rules());
}

int
main(int argc, char *argv[])
{
	secadm_rule_t *rules, *rule;
	size_t nrules, rulesize, i;
	int ch;

	name=argv[0];

	check_bsd();

	if (argc < 2) {
		usage(name);
		return (1);
	}

	for (i=0; i < sizeof(actions)/sizeof(struct _action); i++) {
		if (!strcmp(argv[1], actions[i].action)) {
			if (actions[i].needkld && kldfind(SECADM_KLDNAME) == -1) {
			       	if (kldload(SECADM_KLDNAME) == -1) {
					fprintf(stderr, "[-] secadm module not loaded\n");
					return (1);
				}
			}

			return (actions[i].op(argc, argv));
		}
	}

	usage(name);

	return (1);
}
