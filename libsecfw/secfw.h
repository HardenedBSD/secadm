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

#define SECFW_VERSION		20141213001UL

#define SECFW_RULE_FLAGS_NONE 0x00000000
#define SECFW_RULE_FLAGS_UID_DEFINED 0x00000001
#define SECFW_RULE_FLAGS_GID_DEFINED 0x00000002
#define SECFW_RULE_FLAGS_INODE_DEFINED 0x00000004

typedef enum secfw_feature_type {
	secfw_invalid=0,
	aslr_disabled,
	aslr_enabled,
	segvguard_disabled,
	segvguard_enabled
} secfw_feature_type_t;

typedef enum secfw_command_type {
	secfw_get_version=0,
	secfw_get_rules,
	secfw_set_rules,
	secfw_flush_rules,
	secfw_get_admins,
	secfw_get_views,
	secfw_set_admins,
	secfw_set_views,
	secfw_get_rule_size,
	secfw_get_num_rules
} secfw_command_type_t;

typedef struct secfw_feature {
	secfw_feature_type_t	 type;
	size_t			 metadatasz;
	void			*metadata;
} secfw_feature_t;

typedef struct secfw_rule {
	size_t			 sr_id;
	unsigned int		 sr_flags;
	ino_t			 sr_inode;
	struct fsid		 sr_fsid;
	size_t			 sr_pathlen;
	char 			*sr_path;
	size_t			 sr_nfeatures;
	secfw_feature_t		*sr_features;
	char			**sr_prisonnames;
	size_t			 sr_nprisons;
	struct secfw_rule	*sr_next;
} secfw_rule_t;

#define SPS_FLAG_VIEW	0x1
#define SPS_FLAG_ADMIN	0x2

typedef struct secfw_prison_spec {
	char		*sps_name;
	unsigned long	 sps_flags;
} secfw_prison_spec_t;

typedef struct secfw_command {
	unsigned long		 sc_version;
	size_t			 sc_id;
	secfw_command_type_t	 sc_type;
	void			*sc_metadata;
	size_t			 sc_size;
	void			*sc_buf;
	size_t			 sc_bufsize;
} secfw_command_t;

typedef struct secfw_reply {
	unsigned long		 sr_version;
	size_t			 sr_id;
	unsigned int		 sr_code;
	void			*sr_metadata;
	size_t			 sr_size;
} secfw_reply_t;

#ifdef _KERNEL

MALLOC_DECLARE(M_SECFW);

typedef struct secfw_kernel_data {
	secfw_rule_t	 	*rules;
	secfw_prison_spec_t	*admins;
	secfw_prison_spec_t	*views;

	size_t			 nadmins;
	size_t			 nviews;

	struct rmlock		 rules_lock;
	struct rmlock		 admins_lock;
	struct rmlock		 views_lock;
	struct rm_priotracker	 rules_tracker;
	struct rm_priotracker	 admins_tracker;
	struct rm_priotracker	 views_tracker;
} secfw_kernel_t;

extern secfw_kernel_t rules;

void secfw_lock_init(void);
void secfw_lock_destroy(void);
void secfw_rules_lock_read(void);
void secfw_rules_unlock_read(void);
void secfw_rules_lock_write(void);
void secfw_rules_unlock_write(void);
void secfw_admins_lock_read(void);
void secfw_admins_unlock_read(void);
void secfw_admins_lock_write(void);
void secfw_admins_unlock_write(void);
void secfw_views_lock_read(void);
void secfw_views_unlock_read(void);
void secfw_views_lock_write(void);
void secfw_views_unlock_write(void);

int secfw_check_prison(secfw_rule_t *rule, struct prison *pr);

int secfw_vnode_check_exec(struct ucred *ucred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel);

int secfw_vnode_check_unlink(struct ucred *ucred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp);

int validate_rule(struct thread *td, secfw_rule_t *rule);
void free_rule(secfw_rule_t *, int);
void flush_rules(void);
int read_rule_from_userland(struct thread *td, secfw_rule_t *rule);
secfw_rule_t *get_rule_by_id(size_t);
int get_rule_size(secfw_command_t *, secfw_reply_t *);
int get_num_rules(secfw_command_t *, secfw_reply_t *);

#endif /* _KERNEL */

#endif /* _SECFW_H */
