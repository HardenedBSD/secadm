/*-
 * Copyright (c) 2014 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/pax.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secfw.h"

int
secfw_open(struct cdev *dev, int flag, int otyp, struct thread *td)
{
	return (0);
}

int
secfw_close(struct cdev *dev, int flag, int otyp, struct thread *td)
{
	return (0);
}

int
secfw_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	secfw_rule_t *rule;
	secfw_command_t cmd;
	int error = 0;

	if (uio->uio_iov->iov_len != sizeof(secfw_command_t))
		return (EINVAL);

	error = copyin(uio->uio_iov->iov_base, &cmd, uio->uio_iov->iov_len);
	if (error != 0)
		return (error);

	switch (cmd.sc_type) {
		case secfw_insert_rule:
			rule = read_rule_from_userland(curthread,
			    cmd.sc_metadata, cmd.sc_size);
			if (rule == NULL)
				return (EINVAL);

			break;
		default:
			return (EINVAL);
	}

	return (0);
}

int
secfw_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	return (0);
}

struct cdevsw secfw_devsw = {
	.d_version	= D_VERSION,
	.d_open		= secfw_open,
	.d_close	= secfw_close,
	.d_read		= secfw_read,
	.d_write	= secfw_write,
	.d_name		= "secfw"
};

struct cdev *sdev=NULL;
