/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
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

#ifndef _SYS_SECURITY_SECADM_H
#define _SYS_SECURITY_SECADM_H

#include <sys/param.h>

#define SECADM_VERSION			2015060401UL
#define SECADM_PRETTY_VERSION		"0.2.3"

#define SECADM_KLDNAME			"secadm"

#define	FEATURE_PAX_PAGEEXEC		"pax_pageexec"
#define	FEATURE_PAX_MPROTECT		"pax_mprotect"
#define	FEATURE_PAX_SEGVGUARD		"segvguard"
#define	FEATURE_PAX_ASLR		"aslr"
#define	FEATURE_PAX_SHLIBRANDOM		"aslr"

/* These flags are unused right now */
#define SECADM_RULE_FLAGS_NONE		0x00000000
#define SECADM_RULE_FLAGS_UID_DEFINED	0x00000001
#define SECADM_RULE_FLAGS_GID_DEFINED	0x00000002
#define SECADM_RULE_FLAGS_INODE_DEFINED	0x00000004

#define SECADM_MAX_FEATURES	5

#define SHA1_DIGESTLEN		20
#define SHA256_DIGESTLEN	32

typedef enum secadm_feature_type {
	secadm_invalid=0,
	pageexec_enabled,
	pageexec_disabled,
	mprotect_enabled,
	mprotect_disabled,
	segvguard_disabled,
	segvguard_enabled,
	aslr_disabled,
	aslr_enabled,
	integriforce,
	shlibrandom_disabled,
	shlibrandom_enabled
} secadm_feature_type_t;

typedef enum secadm_hash_type {
	invalid_hash=0,
	si_hash_sha1,
	si_hash_sha256
} secadm_hash_type_t;

typedef enum secadm_integriforce_mode {
	si_mode_soft=0,
	si_mode_hard
} secadm_integriforce_mode_t;

typedef enum secadm_integriforce_cache {
	si_unchecked=0,
	si_success,
	si_fail
} secadm_integriforce_check_t;

#define DEFAULT_MODE	si_mode_hard

typedef enum secadm_command_type {
	secadm_get_version=0,
	secadm_get_rules,
	secadm_set_rules,
	secadm_flush_rules,
	secadm_get_admins,
	secadm_get_views,
	secadm_set_admins,
	secadm_set_views,
	secadm_get_rule_size,
	secadm_get_num_rules,
	secadm_get_rule
} secadm_command_type_t;

typedef struct secadm_feature {
	secadm_feature_type_t	 sf_type;
	size_t			 sf_metadatasz;
	void			*sf_metadata;
} secadm_feature_t;

typedef struct secadm_integriforce {
	secadm_integriforce_mode_t	 si_mode;
	secadm_integriforce_check_t	 si_cache;
	secadm_hash_type_t		 si_hashtype;
	unsigned char			*si_hash;
} secadm_integriforce_t;

typedef struct secadm_rule {
	size_t			 sr_id;
	unsigned int		 sr_flags;
	char			 sr_mount[MNAMELEN];
	ino_t			 sr_inode;
	size_t			 sr_pathlen;
	char 			*sr_path;
	size_t			 sr_nfeatures;
	secadm_feature_t	*sr_features;
	char			*sr_prison;
	void			*sr_kernel;
	struct secadm_rule	*sr_next;
} secadm_rule_t;

#define SPS_FLAG_VIEW	0x1
#define SPS_FLAG_ADMIN	0x2

typedef struct secadm_prison_spec {
	char		*sps_name;
	unsigned long	 sps_flags;
} secadm_prison_spec_t;

typedef struct secadm_command {
	unsigned long		 sc_version;
	size_t			 sc_id;
	secadm_command_type_t	 sc_type;
	void			*sc_metadata;
	size_t			 sc_size;
	void			*sc_buf;
	size_t			 sc_bufsize;
} secadm_command_t;

typedef enum secadm_error {
	secadm_success = 0,
	secadm_fail = 1
} secadm_error_t;

typedef struct secadm_reply {
	unsigned long		 sr_version;
	size_t			 sr_id;
	secadm_error_t		 sr_code;
	int			 sr_errno;
	void			*sr_metadata;
	size_t			 sr_size;
} secadm_reply_t;

typedef struct integriforce_so_check {
	char	 isc_path[MAXPATHLEN];
	int	 isc_result;
} integriforce_so_check_t;

#ifdef _KERNEL

MALLOC_DECLARE(M_SECADM);

#define	SPL_INIT(L, T)		rm_init(&((L)->spl_lock), T)
#define	SPL_RLOCK(L, T)		rm_rlock(&((L)->spl_lock), &(T))
#define	SPL_RUNLOCK(L, T)	rm_runlock(&((L)->spl_lock), &(T))
#define	SPL_WLOCK(L)		rm_wlock(&((L)->spl_lock))
#define	SPL_WUNLOCK(L)		rm_wunlock(&((L)->spl_lock))
#define	SPL_DESTROY(L)		rm_destroy(&((L)->spl_lock))

struct secadm_prison_entry {
	struct rmlock			 spl_lock;
	secadm_rule_t			*spl_rules;
	char				*spl_prison;
	size_t				 spl_max_id;
	SLIST_ENTRY(secadm_prison_entry) spl_entries;
};

#define SKD_ASSERT(W)	rm_assert(&(kernel_data.skd_prisons_lock), W)
#define SKD_INIT(T)	rm_init(&(kernel_data.skd_prisons_lock), T)
#define SKD_RLOCK(T)	rm_rlock(&(kernel_data.skd_prisons_lock), &(T))
#define SKD_RUNLOCK(T)	rm_runlock(&(kernel_data.skd_prisons_lock), &(T))
#define SKD_WLOCK()	rm_wlock(&(kernel_data.skd_prisons_lock))
#define SKD_WUNLOCK()	rm_wunlock(&(kernel_data.skd_prisons_lock))
#define SKD_DESTROY()	rm_destroy(&(kernel_data.skd_prisons_lock))

typedef struct secadm_kernel_data {
	SLIST_HEAD(secadm_prison_list, secadm_prison_entry)	 skd_prisons;
	struct rmlock		 		 skd_prisons_lock;

#if 0
	/* These are planned, but not currently used */
	secadm_prison_spec_t	*skd_admins;
	secadm_prison_spec_t	*skd_views;
	struct rmlock		 skd_admins_lock;
	struct rmlock		 skd_views_lock;
	struct rm_priotracker	 skd_admins_tracker;
	struct rm_priotracker	 skd_views_tracker;

	size_t			 skd_nadmins;
	size_t			 skd_nviews;
#endif
} secadm_kernel_t;

typedef struct secadm_kernel_metadata {
	struct prison			*skm_owner;
	struct secadm_prison_list	*skm_parent;
} secadm_kernel_metadata_t;

extern secadm_kernel_t kernel_data;

void secadm_lock_init(void);
void secadm_lock_destroy(void);
void secadm_rules_lock_read(void);
void secadm_rules_unlock_read(void);
void secadm_rules_lock_write(void);
void secadm_rules_unlock_write(void);
void secadm_admins_lock_read(void);
void secadm_admins_unlock_read(void);
void secadm_admins_lock_write(void);
void secadm_admins_unlock_write(void);
void secadm_views_lock_read(void);
void secadm_views_unlock_read(void);
void secadm_views_lock_write(void);
void secadm_views_unlock_write(void);

int secadm_vnode_check_exec(struct ucred *, struct vnode *,
    struct label *, struct image_params *,
    struct label *);

int secadm_vnode_check_unlink(struct ucred *, struct vnode *,
    struct label *, struct vnode *, struct label *,
    struct componentname *);

int secadm_vnode_check_open(struct ucred *, struct vnode *,
    struct label *, accmode_t);

int pre_validate_rule(struct thread *, secadm_rule_t *);
int validate_ruleset(struct thread *, secadm_rule_t *);
void free_rule(secadm_rule_t *, int);
struct secadm_prison_entry *get_prison_list_entry(const char *, int);
secadm_rule_t *get_first_rule(struct thread *);
secadm_rule_t *get_first_prison_rule(struct prison *);
void flush_rules(struct thread *);
int read_rule_from_userland(struct thread *, secadm_rule_t *);
secadm_rule_t *get_rule_by_id(struct thread *, size_t);
size_t get_rule_size(struct thread *, size_t);
int handle_get_rule_size(struct thread *, secadm_command_t *, secadm_reply_t *);
int get_num_rules(struct thread *, secadm_command_t *, secadm_reply_t *);
int handle_get_rule(struct thread *, secadm_command_t *, secadm_reply_t *);
void cleanup_jail_rules(struct secadm_prison_entry *);
void log_location(const char *, int);

int do_integriforce_check(secadm_rule_t *, struct vattr *,
    struct vnode *, struct ucred *);
secadm_feature_t *lookup_integriforce_feature(secadm_rule_t *);

#endif /* _KERNEL */

#endif /* _SECADM_H */
