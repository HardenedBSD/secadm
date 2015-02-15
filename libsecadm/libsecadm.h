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

#ifndef _LIBSECADM_H
#define _LIBSECADM_H

#include "secadm.h"

int secadm_sysctl(secadm_command_t *, secadm_reply_t *);
unsigned long secadm_kernel_version(void);
unsigned int secadm_add_rules(secadm_rule_t *);
int secadm_parse_path(secadm_rule_t *, const char *);
void secadm_debug_print_rule(secadm_rule_t *rule);
void secadm_debug_print_rules(secadm_rule_t *rules);
size_t secadm_get_kernel_rule_size(size_t id);
size_t secadm_get_num_kernel_rules(void);
secadm_rule_t *secadm_get_kernel_rule(size_t id);
unsigned int secadm_flush_all_rules(void);
int secadm_validate_rule(secadm_rule_t *rule);
int secadm_validate_ruleset(secadm_rule_t *rules);
void secadm_free_rule(secadm_rule_t *rule, int freerule);
void secadm_free_ruleset(secadm_rule_t *rules);

int secadm_verify_file(secadm_hash_type_t type, const char *path,
    char *digest);
secadm_integriforce_mode_t convert_to_integriforce_mode(const char *mode);
secadm_hash_type_t convert_to_hash_type(const char *type);
const char *convert_from_integriforce_mode(secadm_integriforce_mode_t mode);

#endif
