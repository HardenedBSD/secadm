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

static void usage(char *);
static void check_bsd(void);
static void get_version(void);

static void
usage(char *name)
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

static void get_version(void)
{
	unsigned long version;

	version = secfw_kernel_version();
	if (version)
		fprintf(stderr, "[+] secfw kernel module version: %lu\n", version);

	exit(0);
}

int
main(int argc, char *argv[])
{
	secfw_rule_t *rules;
	const char *config=NULL;
	size_t nrules, rulesize, i;
	int ch;

	check_bsd();

	if (kldcheck()) {
		fprintf(stderr, "[-] secfw module not loaded\n");
		return 1;
	}

	while ((ch = getopt(argc, argv, "c:hv?")) != -1) {
		switch (ch) {
		case 'c':
			config = (const char *)optarg;
			break;
		case 'v':
			get_version();
		default:
			usage(argv[0]);
		}
	}

	if (!(config)) {
		usage(argv[0]);
	}

	rules = load_config(config);
	secfw_debug_print_rules(rules);
	secfw_add_rules(rules);

	nrules = secfw_get_num_kernel_rules();
	fprintf(stderr, "[*] Number of kernel rules: %zu\n", nrules);

	for (i=0; i < nrules; i++) {
		rulesize = secfw_get_kernel_rule_size(i);
		fprintf(stderr, "[*] Rule %zu size: %zu\n", i, rulesize);
	}

	return 0;
}
