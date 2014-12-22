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
#include <sys/rmlock.h>
#include <sys/uio.h>

#include <security/mac/mac_policy.h>

#include "secfw.h"

static void
secfw_init(struct mac_policy_conf *mpc)
{

	memset(&kernel_data, 0x00, sizeof(secfw_kernel_t));

	rm_init(&(kernel_data.skd_prisons_lock), "Main secfw lock");
}

static void
secfw_destroy(struct mac_policy_conf *mpc)
{

	rm_wlock(&(kernel_data.skd_prisons_lock));


	while (kernel_data.skd_prisons != NULL)
		cleanup_jail_rules(kernel_data.skd_prisons);

	rm_wunlock(&(kernel_data.skd_prisons_lock));

	rm_destroy(&(kernel_data.skd_prisons_lock));
}

static void
secfw_jail_destroy(struct prison *pr)
{
	secfw_prison_list_t *list;

	list = get_prison_list_entry(pr->pr_name, 0);

	if (list != NULL) {
		rm_wlock(&(kernel_data.skd_prisons_lock));
		cleanup_jail_rules(list);
		rm_wunlock(&(kernel_data.skd_prisons_lock));
	}
}

static struct mac_policy_ops secfw_ops =
{
	.mpo_destroy		= secfw_destroy,
	.mpo_init		= secfw_init,
	.mpo_vnode_check_exec	= secfw_vnode_check_exec,
	.mpo_vnode_check_unlink	= secfw_vnode_check_unlink,
	.mpo_prison_destroy	= secfw_jail_destroy
};

MAC_POLICY_SET(&secfw_ops, secfw, "HardenedBSD Security Firewall",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
