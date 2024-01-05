#pragma once

#include "misc.h"
#include <stdbool.h>

void ipset_init(const char *noalias tagnone_setname4,
                const char *noalias tagnone_setname6,
                const char *noalias tagchn_setname46,
                const char *noalias taggfw_setname46,
                u8 default_tag);

/* tag:none */
bool ipset_test_ip(const void *noalias ip, bool v4);

/* tag:chn | tag:gfw */
void ipset_add_ip(const void *noalias ip, bool v4, bool chn);

/* tag:chn | tag:gfw */
void ipset_end_add_ip(bool chn);
