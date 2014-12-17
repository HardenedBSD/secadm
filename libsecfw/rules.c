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

#include <fcntl.h>

#include "secfw.h"

int
secfw_parse_path(secfw_rule_t *rule, const char *path)
{
	struct stat sb;
	struct statfs fsb;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[-] Cannot open %s for stat. Skipping.\n", path);
		return -1;
	}

	if (fstat(fd, &sb)) {
		perror("fstat");
		close(fd);
		return -1;
	}

	memset(&fsb, 0x00, sizeof(struct statfs));
	if (fstatfs(fd, &fsb)) {
		perror("fstatfs");
		close(fd);
		return -1;
	}

	close(fd);

	strlcpy(rule->sr_mount, fsb.f_mntonname, MNAMELEN);
	rule->sr_inode = sb.st_ino;
	rule->sr_path = strdup(path);
	if (rule->sr_path)
		rule->sr_pathlen = strlen(path);
	else
		rule->sr_pathlen = 0;

	return 0;
}
