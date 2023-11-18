#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(void);

/* tag:none */
bool ipset_test_ip(const void *noalias ip, bool v4);

/* tag:chn | tag:gfw */
void ipset_add_ip(const void *noalias ip, bool v4, bool chn);

/* tag:chn | tag:gfw */
void ipset_end_add_ip(bool chn);
