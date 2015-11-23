/*-
 * Copyright (c) 2014,2015 Shawn Webb <shawn.webb@hardenedbsd.org>
 * Copyright (c) 2015 Brian Salcedo <brian.salcedo@hardenedbsd.org>
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
 */

#ifndef _SYS_SECURITY_SECADM_H_
#define _SYS_SECURITY_SECADM_H_

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/tree.h>

#ifndef _SYS_FNV_HASH_H_
#include <sys/fnv_hash.h>
#endif /* !_SYS_FNV_HASH_H_ */

#ifndef _SYS_PAX_H
#include <sys/pax.h>
#endif /* !_SYS_PAX_H */

#define SECADM_VERSION			2015112201UL
#define SECADM_PRETTY_VERSION		"0.3.0-beta-01"

#define SECADM_EXT_TYPE_ANY		0x0000007f
#define SECADM_EXT_TYPE_REGULAR		0x00000001
#define SECADM_EXT_TYPE_DIRECTORY	0x00000002
#define SECADM_EXT_TYPE_BLOCKDEV	0x00000004
#define SECADM_EXT_TYPE_CHARDEV		0x00000008
#define SECADM_EXT_TYPE_SYMLINK		0x00000010
#define SECADM_EXT_TYPE_SOCKET		0x00000020
#define SECADM_EXT_TYPE_FIFO		0x00000040

#define SECADM_EXT_MODE_NONE		0x00000000
#define SECADM_EXT_MODE_ADMIN		0x00000001
#define SECADM_EXT_MODE_READ		0x00000002
#define SECADM_EXT_MODE_ATTR		0x00000004
#define SECADM_EXT_MODE_WRITE		0x00000008
#define SECADM_EXT_MODE_EXEC		0x00000010

#define	SECADM_PAX_ASLR_SET		0x00000001
#define SECADM_PAX_PAGEEXEC_SET		0x00000002
#define SECADM_PAX_MPROTECT_SET		0x00000004
#define SECADM_PAX_SEGVGUARD_SET	0x00000008
#define SECADM_PAX_SHLIBRANDOM_SET	0x00000010
#define SECADM_PAX_MAP32_SET		0x00000020

#define SECADM_PAX_PAGEEXEC		0x00000001
#define SECADM_PAX_MPROTECT		0x00000002
#define SECADM_PAX_ASLR			0x00000004
#define SECADM_PAX_SEGVGUARD		0x00000008
#define SECADM_PAX_SHLIBRANDOM		0x00000010
#define SECADM_PAX_MAP32		0x00000020

#define SECADM_SHA1_DIGEST_LEN		20
#define SECADM_SHA256_DIGEST_LEN	32

typedef enum secadm_rule_type {
	secadm_pax_rule = 0,
	secadm_integriforce_rule,
	secadm_extended_rule
} secadm_rule_type_t;

typedef enum secadm_command_type {
	secadm_cmd_flush_ruleset = 0,
	secadm_cmd_load_ruleset,
	secadm_cmd_add_rule,
	secadm_cmd_del_rule,
	secadm_cmd_enable_rule,
	secadm_cmd_disable_rule,
	secadm_cmd_get_rule,
	secadm_cmd_get_rule_data,
	secadm_cmd_get_rule_path,
	secadm_cmd_get_rule_hash,
	secadm_cmd_get_num_rules
} secadm_command_type_t;

typedef struct secadm_command {
	int			 sc_version;
	secadm_command_type_t	 sc_type;
	void			*sc_data;
} secadm_command_t;

typedef enum secadm_reply_code {
	secadm_reply_success = 0,
	secadm_reply_fail
} secadm_reply_code_t;

typedef struct secadm_reply {
	int			 sr_version;
	secadm_reply_code_t	 sr_code;
	void			*sr_data;
} secadm_reply_t;

typedef uint32_t secadm_pax_t;

typedef struct secadm_pax_data {
	u_char		*sp_path;
	size_t		 sp_pathsz;
	char		 sp_mntonname[MNAMELEN];
	long		 sp_fileid;
	uint32_t	 sp_pax_set; 
	secadm_pax_t	 sp_pax;
} secadm_pax_data_t;

typedef enum secadm_hash_type {
	secadm_hash_sha1 = 0,
	secadm_hash_sha256
} secadm_hash_type_t;

typedef struct secadm_integriforce_data {
	u_char			*si_path;
	size_t			 si_pathsz;
	char			 si_mntonname[MNAMELEN];
	long			 si_fileid;
	secadm_hash_type_t	 si_type;
	u_char			*si_hash;
	int			 si_cache;
	int			 si_mode;
} secadm_integriforce_data_t;

typedef struct integriforce_so_check {
	char	 isc_path[MAXPATHLEN];
	int	 isc_result;
} integriforce_so_check_t;

typedef struct secadm_extended_subject {
	int	 ms_not_uid;
	uid_t	 ms_min_uid;
	uid_t	 ms_max_uid;
	int	 ms_not_gid;
	gid_t	 ms_min_gid;
	gid_t	 ms_max_gid;
	int	 ms_not_jid;
	int	 ms_jid;
} secadm_extended_subject_t;

typedef struct secadm_extended_object {
	int			 mo_not_uid;
	uid_t			 mo_min_uid;
	uid_t			 mo_max_uid;
	int			 mo_not_gid;
	gid_t			 mo_min_gid;
	gid_t			 mo_max_gid;
	int			 mo_not_path;
	u_char			*mo_path;
	size_t			 mo_pathsz;
	int			 mo_not_suid;
	int			 mo_suid;
	int			 mo_not_sgid;
	int			 mo_sgid;
	int			 mo_not_uid_subject;
	int			 mo_uid_subject;
	int			 mo_not_gid_subject;
	int			 mo_gid_subject;
} secadm_extended_object_t;

typedef unsigned int secadm_extended_type_t;
typedef unsigned int secadm_extended_mode_t;


typedef struct secadm_extended_data {
	secadm_extended_subject_t	 sm_subject;
	secadm_extended_object_t	 sm_object;
	int				 sm_not_type;
	secadm_extended_type_t		 sm_type;
	secadm_extended_mode_t		 sm_mode;
} secadm_extended_data_t;

typedef struct secadm_rule {
	int					 sr_id;
	int					 sr_jid;
	secadm_rule_type_t			 sr_type;
	union {
		secadm_integriforce_data_t	*sr_integriforce_data;
		secadm_pax_data_t		*sr_pax_data;
		secadm_extended_data_t		*sr_extended_data;
	};
	int					 sr_active;
	Fnv32_t					 sr_key;
	struct secadm_rule			*sr_next;	/* XXX for loading only */
	RB_ENTRY(secadm_rule)			 sr_tree;
} secadm_rule_t;

int secadm_flush_ruleset(void);
int secadm_load_ruleset(secadm_rule_t *);
int secadm_add_rule(secadm_rule_t *);
int secadm_del_rule(int);
int secadm_enable_rule(int);
int secadm_disable_rule(int);
secadm_rule_t *secadm_get_rule(int);
size_t secadm_get_num_rules(void);
void secadm_free_rule(secadm_rule_t *);
int secadm_validate_rule(secadm_rule_t *);

#ifdef _KERNEL

int get_mntonname_vattr(struct thread *, u_char *, char *, struct vattr *);
void kernel_free_rule(secadm_rule_t *);
void kernel_flush_ruleset(int);
int kernel_finalize_rule(struct thread *, secadm_rule_t *, int);
int kernel_load_ruleset(struct thread *, secadm_rule_t *);
int kernel_add_rule(struct thread *, secadm_rule_t *, int);
void kernel_del_rule(struct thread *, secadm_rule_t *);
void kernel_active_rule(struct thread *, secadm_rule_t *, int);
secadm_rule_t *kernel_get_rule(struct thread *, secadm_rule_t *);

int secadm_sysctl_handler(SYSCTL_HANDLER_ARGS);

int secadm_vnode_check_exec(struct ucred *, struct vnode *, struct label *,
    struct image_params *, struct label *);
int secadm_vnode_check_open(struct ucred *, struct vnode *, struct label *,
    accmode_t);
int secadm_vnode_check_unlink(struct ucred *, struct vnode *, struct label *,
    struct vnode *, struct label *,
    struct componentname *);

int secadm_rule_cmp(secadm_rule_t *, secadm_rule_t *);

int do_integriforce_check(secadm_rule_t *, struct vattr *, struct vnode *,
    struct ucred *);

MALLOC_DECLARE(M_SECADM);
RB_HEAD(secadm_rules_tree, secadm_rule);
RB_PROTOTYPE(secadm_rules_tree, secadm_rule, sr_tree, secadm_rule_cmp);

#define RM_PE_INIT(l)		rm_init(&(l)->sp_lock, "secadm prison rmlock");
#define RM_PE_RLOCK(l, t)	rm_rlock(&(l)->sp_lock, &(t));
#define RM_PE_RUNLOCK(l, t)	rm_runlock(&(l)->sp_lock, &(t));
#define RM_PE_WLOCK(l)		rm_wlock(&(l)->sp_lock);
#define RM_PE_WUNLOCK(l)	rm_wunlock(&(l)->sp_lock);
#define RM_PE_DESTROY(l)	rm_destroy(&(l)->sp_lock);

#define RM_PL_INIT()		rm_init(&(secadm_prisons_list.sp_lock), "secadm prison list rmlock");
#define RM_PL_RLOCK(t)		rm_rlock(&(secadm_prisons_list.sp_lock), &(t));
#define RM_PL_RUNLOCK(t)	rm_runlock(&(secadm_prisons_list.sp_lock), &(t));
#define RM_PL_WLOCK()		rm_wlock(&(secadm_prisons_list.sp_lock));
#define RM_PL_WUNLOCK()		rm_wunlock(&(secadm_prisons_list.sp_lock));
#define RM_PL_DESTROY()		rm_destroy(&(secadm_prisons_list.sp_lock));

typedef struct secadm_key {
	int			 sk_jid;
	secadm_rule_type_t	 sk_type;
	long			 sk_fileid;
	char			 sk_mntonname[MNAMELEN];
} secadm_key_t;

typedef struct secadm_prison_entry {
	struct secadm_rules_tree		 sp_rules;
	struct secadm_rules_tree		 sp_staging;
	size_t					 sp_num_rules;
	size_t					 sp_last_id;
	size_t					 sp_num_integriforce_rules;
	size_t					 sp_num_pax_rules;
	size_t					 sp_num_extended_rules;
	int					 sp_loaded;
	int					 sp_id;
	struct rmlock				 sp_lock;
	SLIST_ENTRY(secadm_prison_entry)	 sp_entries;
} secadm_prison_entry_t;

secadm_prison_entry_t *get_prison_list_entry(int);

typedef struct secadm_prisons {
	SLIST_HEAD(secadm_prison_list, secadm_prison_entry)	 sp_prison;
	struct rmlock                                            sp_lock;
} secadm_prisons_t;

extern secadm_prisons_t secadm_prisons_list;

#endif /* _KERNEL */
#endif /* !_SYS_SECURITY_SECADM_H_ */
