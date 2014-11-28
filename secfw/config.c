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

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/queue.h>

#include "ucl.h"
#include "secfw.h"
#include "secfw_internal.h"

secfw_rule_t *load_config(const char *config)
{
	struct ucl_parser *parser=NULL;
	secfw_rule_t *rules;
	unsigned char *map;
	size_t sz;
	int fd;
	struct stat sb;

	parser = ucl_parser_new(UCL_PARSER_KEY_LOWERCASE);
	if (!(parser))
		return NULL;

	fd = open(config, O_RDONLY);
	if (fd < 0) {
		ucl_parser_free(parser);
		return NULL;
	}

	if (fstat(fd, &sb)) {
		close(fd);
		ucl_parser_free(parser);
		return NULL;
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == (unsigned char *)MAP_FAILED) {
		close(fd);
		ucl_parser_free(parser);
		return NULL;
	}

	ucl_parser_add_chunk(parser, map, sb.st_size);

	munmap(map, sb.st_size);

	close(fd);
	return rules;
}
