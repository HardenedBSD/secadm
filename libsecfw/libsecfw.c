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

#include "secfw.h"

int
secfw_sysctl(secfw_command_t *cmd, secfw_reply_t *reply)
{
	int err;
	size_t cmdsz, replysz;

	cmdsz = sizeof(secfw_command_t);
	replysz = sizeof(secfw_reply_t);

	err = sysctlbyname("hardening.secfw.control", reply, &replysz, cmd, cmdsz);

	if (err)
		return (err);

	if (reply->sr_code)
		return (reply->sr_code);

	return (0);
}

unsigned long
secfw_kernel_version(void)
{
	secfw_command_t cmd;
	secfw_reply_t reply;
	int err;
	unsigned long version=0;

	memset(&cmd, 0x00, sizeof(secfw_command_t));
	cmd.sc_version = SECFW_VERSION;
	cmd.sc_type = secfw_get_version;
	cmd.sc_buf = calloc(1, sizeof(unsigned long));
	if (!(cmd.sc_buf))
		return 0;

	cmd.sc_bufsize = sizeof(unsigned long);

	err = secfw_sysctl(&cmd, &reply);
	if (err == 0) {
		version = *((unsigned long *)(reply.sr_metadata));
	} else {
		fprintf(stderr, "[-] Could not get version: %s\n", strerror(errno));
		goto error;
	}

error:
	if (cmd.sc_buf != NULL)
		free(cmd.sc_buf);

	return version;
}

unsigned int
secfw_insert_rules(secfw_rule_t *rule)
{
	secfw_command_t cmd;
	secfw_reply_t reply;
	int err=0;

	memset(&cmd, 0x00, sizeof(secfw_command_t));
	memset(&reply, 0x00, sizeof(secfw_rule_t));

	cmd.sc_version = SECFW_VERSION;
	cmd.sc_type = secfw_insert_rule;
	cmd.sc_metadata = rule;
	cmd.sc_size = sizeof(secfw_rule_t);

	if ((err = secfw_sysctl(&cmd, &reply))) {
		fprintf(stderr, "[-] Control channel received an error code: %d\n", err);
	}

	return (unsigned int)err;
}
