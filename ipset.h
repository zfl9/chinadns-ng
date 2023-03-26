#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(void);

bool ipset_test(const void *noalias ip, bool v4);

/* add to cache */
void ipset_add(const void *noalias ip, bool v4);

/* commit to kernel */
void ipset_end_add(void);
