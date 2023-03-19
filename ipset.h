#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(void);

bool ipset_ip_exists(const void *noalias ip, bool is_ipv4);

/* add to cache */
void ipset_ip_add(const void *noalias ip, bool is_ipv4);

/* commit to kernel */
void ipset_ip_add_commit(void);
