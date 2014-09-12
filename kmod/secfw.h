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

#ifndef _SYS_SECURITY_SECFW_H
#define _SYS_SECURITY_SECFW_H

#define SECFW_VERSION		20140911001UL
#define SECFW_DEV_VERSION	1

#define SECFW_RULE_FLAGS_NONE 0x00000000
#define SECFW_RULE_FLAGS_UID_DEFINED 0x00000001
#define SECFW_RULE_FLAGS_GID_DEFINED 0x00000002
#define SECFW_RULE_FLAGS_INODE_DEFINED 0x00000004

typedef enum secfw_feature_type {
	secfw_invalid=0,
	aslr_disabled,
	aslr_enabled,
	segvgaurd_disabled,
	segvguard_enabled
} secfw_feature_type_t;

typedef enum secfw_command_type {
	secfw_get_version=0,
	secfw_get_rules,
	secfw_set_rules,
	secfw_flush_rules,
	secfw_delete_rule,
	secfw_insert_rule
} secfw_command_type_t;

typedef struct secfw_feature {
	secfw_feature_type_t	type;
	void			*metadata;
} secfw_feature_t;

typedef struct secfw_rule {
	size_t			sr_id;
	unsigned int		sr_flags;
	ino_t			sr_inode;
	struct fsid		sr_fsid;
	char 			*sr_path;
	uid_t			sr_minuid;
	uid_t			sr_maxuid;
	gid_t			sr_mingid;
	gid_t			sr_maxgid;
	size_t			sr_nfeatures;
	secfw_feature_t		*sr_features;
} secfw_rule_t;

typedef struct secfw_rule_list {
	secfw_rule_t			srl_rule;
	LIST_ENTRY(secfw_rule_list)	srl_entry;
} secfw_rules_t;

typedef struct secfw_command {
	unsigned long		sc_version;
	size_t			sc_id;
	secfw_command_type_t	sc_type;
	void			*sc_metadata;
} secfw_command_t;

typedef struct secfw_reply {
	unsigned long		sr_version;
	size_t			sr_id;
	unsigned int		sr_code;
	void			*sr_metadata;
} secfw_reply_t;

#ifdef _KERNEL

extern struct cdevsw secfw_devsw;
extern struct cdev *sdev;

typedef struct secfw_kernel_data {
	secfw_rule_t *sk_rules;
	struct prison *sk_prison;
} secfw_kernel_t;

void secfw_lock(void);
void secfw_unlock(void);

int secfw_vnode_check_exec(struct ucred *ucred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel);

int secfw_vnode_check_unlink(struct ucred *ucred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);

int secfw_open(struct cdev *dev, int flag, int otyp, struct thread *td);
int secfw_close(struct cdev *dev, int flag, int otyp, struct thread *td);
int secfw_write(struct cdev *dev, struct uio *uio, int ioflag);
int secfw_read(struct cdev *dev, struct uio *uio, int ioflag);

#endif /* _KERNEL */

#endif /* _SECFW_H */
