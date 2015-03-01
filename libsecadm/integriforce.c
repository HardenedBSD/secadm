/*-
 * Copyright (c) 2015 Shawn Webb <shawn.webb@hardenedbsd.org>
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
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <sha.h>
#include <sha256.h>

#include "secadm.h"
#include "libsecadm.h"

int
secadm_verify_file(secadm_hash_type_t type, const char *path,
    const unsigned char *digest)
{
	struct stat sb;
	SHA256_CTX sha256ctx;
	unsigned char *hash;
	void *mapping;
	size_t hashsz;
	int fd, res;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (1);

	if (fstat(fd, &sb)) {
		close(fd);
		return (1);
	}

	mapping = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mapping == NULL) {
		close(fd);
		return (1);
	}

	res = 0;
	switch (type) {
	case si_hash_md5:
		return (1);
	case si_hash_sha1:
		return (1);
	case si_hash_sha256:
		hash = malloc(32);
		if (hash == NULL) {
			close(fd);
			munmap(mapping, sb.st_size);
			return (1);
		}

		SHA256_Init(&sha256ctx);
		SHA256_Update(&sha256ctx, mapping, sb.st_size);
		SHA256_Final(hash, &sha256ctx);

		hashsz=32;
		break;
	default:
		return (1);
	}

	res = (memcmp(hash, digest, hashsz) != 0);
	free(hash);

	return (res);
}

secadm_integriforce_mode_t
convert_to_integriforce_mode(const char *mode)
{
	if (!strcasecmp(mode, "soft"))
		return (si_mode_soft);

	return (si_mode_hard);
}

secadm_hash_type_t
convert_to_hash_type(const char *type)
{
	if (!strcasecmp(type, "md5"))
		return (si_hash_md5);
	if (!strcasecmp(type, "sha1"))
		return (si_hash_sha1);
	if (!strcasecmp(type, "sha256"))
		return (si_hash_sha256);

	return (invalid_hash);
}

const char *
convert_from_integriforce_mode(secadm_integriforce_mode_t mode)
{
	switch (mode) {
	case si_mode_soft:
		return ("soft");
	case si_mode_hard:
		return ("hard");
	default:
		return ("unknown");
	}
}
