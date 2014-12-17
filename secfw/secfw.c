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
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include "ucl.h"
#include "libsecfw.h"
#include "secfw_internal.h"

typedef int (*action_t)(int, char **);

static void usage(const char *);
static void check_bsd(void);
static void get_version(void);

static int listact(int, char **);
static int setact(int, char **);
static int flushact(int, char **);

const char *configpath=NULL;
const char *name;

struct _action {
	const char *action;
	action_t op;
} actions[] = {
	{
		"list",
		listact
	},
	{
		"set",
		setact
	},
	{
		"flush",
		flushact
	},
};

static void
usage(const char *name)
{
	fprintf(stderr, "USAGE: %s <-c config> <action> <options>\n", name);
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

static void
get_version(void)
{
	unsigned long version;

	version = secfw_kernel_version();
	if (version)
		fprintf(stderr, "[+] secfw kernel module version: %lu\n",
		    version);

	exit(0);
}

static int
listact(int argc, char *argv[])
{
	secfw_rule_t *rule;
	size_t nrules, i;

	nrules = secfw_get_num_kernel_rules();
	for (i=0; i < nrules; i++) {
		rule = secfw_get_kernel_rule(i);
		if (!(rule)) {
			fprintf(stderr, "[-] Could not get rule %zu from the kernel.\n", i);
			free(rule);
			return 1;
		}

		secfw_debug_print_rule(rule);
		free(rule);
	}

	return 0;
}

static int
setact(int argc, char *argv[])
{
	secfw_rule_t *rules;

	if (!(configpath))
		usage(name);

	rules = load_config(configpath);
	if (rules == NULL) {
		fprintf(stderr, "[-] Could not load the config file\n");
		return 1;
	}

	if (secfw_add_rules(rules)) {
		fprintf(stderr, "[-] Could not load the rules\n");
		return 1;
	}

	free(rules);
	return (0);
}

static int
flushact(int argc, char *argv[])
{

	return ((int)secfw_flush_all_rules());
}

int
main(int argc, char *argv[])
{
	secfw_rule_t *rules, *rule;
	size_t nrules, rulesize, i;
	int ch;

	name=argv[0];

	check_bsd();

	if (kldcheck()) {
		fprintf(stderr, "[-] secfw module not loaded\n");
		return 1;
	}

	while ((ch = getopt(argc, argv, "c:hv?")) != -1) {
		switch (ch) {
		case 'c':
			configpath = (const char *)optarg;
			break;
		case 'v':
			get_version();
		default:
			usage(name);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage(name);

	for (i=0; i < sizeof(actions)/sizeof(struct _action); i++)
		if (!strcmp(argv[0], actions[i].action))
			return (actions[i].op(argc, argv));

	usage(name);

	return 1;
}
