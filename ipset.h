#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(void);

bool ipset_addr_exists(const void *noalias addr, bool is_ipv4);

void ipset_addr_add(const void *noalias addr, bool is_ipv4);
