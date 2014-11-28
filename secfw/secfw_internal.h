#ifndef _SECFW_INTERNAL_H
#define _SECFW_INTERNAL_H

int kldcheck(void);
secfw_rule_t *load_config(const char *config);

#endif
