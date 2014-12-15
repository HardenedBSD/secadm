#ifndef _SECFW_INTERNAL_H
#define _SECFW_INTERNAL_H

int kldcheck(void);
secfw_rule_t *load_config(const char *);
secfw_rule_t *parse_object(struct ucl_parser *);
void add_feature(secfw_rule_t *, const ucl_object_t *, secfw_feature_type_t);
secfw_rule_t *parse_applications_object(const ucl_object_t *);

#endif
