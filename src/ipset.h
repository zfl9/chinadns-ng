#pragma once

#include "misc.h"
#include <stdbool.h>

extern bool ipset_blacklist;

struct ipset_testctx;
struct ipset_addctx;

const struct ipset_testctx *ipset_new_testctx(const char *noalias name46);

struct ipset_addctx *ipset_new_addctx(const char *noalias name46);

/* `ip` exists in the set ? */
bool ipset_test_ip(const struct ipset_testctx *noalias ctx, const void *noalias ip, bool v4);

void ipset_add_ip(struct ipset_addctx *noalias ctx, const void *noalias ip, bool v4);

void ipset_end_add_ip(struct ipset_addctx *noalias ctx);
