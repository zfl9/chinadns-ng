#pragma once

#include "misc.h"
#include <stdbool.h>

/* init netlink socket for ipset query */
void ipset_init_nlsocket(void);

/* check given ipaddr is exists in ipset */
bool ipset_addr_is_exists(const void *noalias addr_ptr, bool is_ipv4);
