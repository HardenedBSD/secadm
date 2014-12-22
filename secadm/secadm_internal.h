#ifndef _SECADM_INTERNAL_H
#define _SECADM_INTERNAL_H

int kldcheck(void);
secadm_rule_t *load_config(const char *);
secadm_rule_t *parse_object(struct ucl_parser *);
void add_feature(secadm_rule_t *, const ucl_object_t *, secadm_feature_type_t);
secadm_rule_t *parse_applications_object(const ucl_object_t *);

#endif
