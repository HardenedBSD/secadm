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
static int setact(int, char **);
static int flushact(int, char **);
static int validateact(int, char **);
static int versionact(int, char **);

const char *configpath=NULL;
const char *name;

struct _action {
	const char *action;
	int needkld;
	action_t op;
} actions[] = {
	{
		"list",
		0,
		listact
	},
	{
		"set",
		1,
		setact
	},
	{
		"flush",
		1,
		flushact
	},
	{
		"validate",
		0,
		validateact
	},
	{
		"version",
		1,
		versionact
	}
};

static void
usage(const char *name)
{
	size_t i;

	fprintf(stderr, "USAGE: %s <-c config> <action> <options>\n", name);
	fprintf(stderr, "Available Actions:\n");

	for (i=0; i < sizeof(actions)/sizeof(struct _action); i++)
		fprintf(stderr, "    %s\n", actions[i].action);

	exit(1);
}

static void
check_bsd(void)
{
	int version;
	size_t sz=sizeof(int);

	if (sysctlbyname("hardening.version", &version, &sz, NULL, 0)) {
		if (errno == ENOENT) {
			fprintf(stderr, "[-] HardenedBSD required. FreeBSD not supported.\n");
			exit(1);
		}
	}
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

	exit(0);
}

static int
listact(int argc, char *argv[])
{
	secadm_rule_t *rule;
	size_t nrules, i;

	if (argc == 1 || !strcmp(argv[1], "rules")) {
		if (kldfind(SECADM_KLDNAME) == -1) {
			fprintf(stderr, "[-] secadm module not loaded\n");
			return (1);
		}

		nrules = secadm_get_num_kernel_rules();
		for (i=0; i < nrules; i++) {
			rule = secadm_get_kernel_rule(i);
			if (!(rule)) {
				fprintf(stderr, "[-] Could not get rule %zu from the kernel.\n", i);
				free(rule);
				return 1;
			}

			secadm_debug_print_rule(rule);
			free(rule);
		}

		return (0);
	}

	if (argc == 1)
		return (1);

	if (!strcmp(argv[1], "features")) {
		printf("Available features\n");
		if (feature_present(FEATURE_PAX_ASLR))
			printf("    aslr:\t(bool) - Opt an application in to or out of ASLR\n");
		if (feature_present(FEATURE_PAX_MPROTECT))
			printf("    mprotect:\t(bool) - Opt an application in to or out of MPROTECT restrictions\n");
		if (feature_present(FEATURE_PAX_PAGEEXEC))
			printf("    pageexec:\t(bool) - Opt an application in to or out of PAGEEXEC\n");
		if (feature_present(FEATURE_PAX_SEGVGUARD))
			printf("    segvguard:\t(bool) - Opt an application in to or out of SEGVGUARD\n");
#if __HardenedBSD_version == 30
		if (feature_present(FEATURE_PAX_HARDENING))
			printf("    map32_protect:\t(bool) - Opt an application in to or out of MAP_32BIT protection\n");
#endif
#if __HardenedBSD_version > 30
		if (feature_present(FEATURE_PAX_DISALLOWMAP32BIT))
			printf("    disallow_map32bit:\t(bool) - Opt an application in to or out of MAP_32BIT mode mmap(2) restriction\n");
#endif
	}

	return (0);
}

static int
setact(int argc, char *argv[])
{
	secadm_rule_t *rules;
	struct stat sb;

	if (!(configpath))
		configpath = DEFCONFIG;

	if (stat(configpath, &sb))
		usage(name);

	rules = load_config(configpath);
	if (rules == NULL) {
		fprintf(stderr, "[-] Could not load the config file\n");
		return 1;
	}

	if (secadm_add_rules(rules)) {
		fprintf(stderr, "[-] Could not load the rules\n");
		return 1;
	}

	free(rules);
	return (0);
}

static int
validateact(int argc, char *argv[])
{
	secadm_rule_t *rules;
	struct stat sb;
	int ch, res;

	if (!(configpath))
		configpath = DEFCONFIG;

	if (stat(configpath, &sb))
		usage(name);

	rules = load_config(configpath);
	if (rules == NULL) {
		fprintf(stderr, "[-] Could not load the config file\n");
		return 1;
	}

	while ((ch = getopt(argc-1, argv+1, "v")) != -1) {
		switch (ch) {
		case 'v':
			secadm_debug_print_rules(rules);
			break;
		}
	}

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

	while ((ch = getopt(argc, argv, "c:h?")) != -1) {
		switch (ch) {
		case 'c':
			configpath = (const char *)optarg;
			break;
		default:
			usage(name);
		}
	}

	argc -= optind;
	argv += optind;
	optind=0;

	if (argc < 1)
		usage(name);

	for (i=0; i < sizeof(actions)/sizeof(struct _action); i++) {
		if (!strcmp(argv[0], actions[i].action)) {
			if (actions[i].needkld && kldfind(SECADM_KLDNAME) == -1) {
			       	if (kldload(SECADM_KLDNAME) == -1) {
					fprintf(stderr, "[-] secadm module not loaded\n");
					return 1;
				}
			}

			return (actions[i].op(argc, argv));
		}
	}

	usage(name);

	return (1);
}
