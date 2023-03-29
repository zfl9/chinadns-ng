#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(void);

bool ipset_test_ip(const void *noalias ip, bool v4);

void ipset_add_ip(const void *noalias ip, bool v4);

void ipset_end_add_ip(void);
