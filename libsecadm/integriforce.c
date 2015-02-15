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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <sha.h>
#include <sha256.h>

#include "secadm.h"
#include "libsecadm.h"

int
secadm_verify_file(secadm_hash_type_t type, const char *path, char *digest)
{
	char *hash;
	size_t hashsz;
	int res;

	res = 0;
	switch (type) {
	case md5:
		return (1);
	case sha1:
		hashsz=20;
		hash = SHA1_File(path, NULL);
		if (hash == NULL)
			return (1);
		break;
	case sha256:
		hashsz=32;
		hash = SHA256_File(path, NULL);
		if (hash == NULL)
			return (1);
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
		return (soft);

	return (hard);
}

secadm_hash_type_t
convert_to_hash_type(const char *type)
{
	if (!strcasecmp(type, "md5"))
		return (md5);
	if (!strcasecmp(type, "sha1"))
		return (sha1);
	if (!strcasecmp(type, "sha256"))
		return (sha256);

	return (invalid_hash);
}

const char *
convert_from_integriforce_mode(secadm_integriforce_mode_t mode)
{
	switch (mode) {
	case soft:
		return ("soft");
	case hard:
		return ("hard");
	default:
		return ("unknown");
	}
}
