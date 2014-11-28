#ifndef _SECFW_INTERNAL_H
#define _SECFW_INTERNAL_H

int kldcheck(void);
secfw_rule_t *load_config(const char *config);
secfw_rule_t *parse_object(struct ucl_parser *parser);
secfw_rule_t *parse_applications_object(const ucl_object_t *obj);

#endif
