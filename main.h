#pragma once

#include <stdbool.h>

/* ipset setname max len */
#define IPSET_MAXNAMELEN 32 /* including '\0' */

/* global variable declaration */
extern bool g_noip_as_chnip; /* used by dns.h */
extern char g_ipset_setname4[IPSET_MAXNAMELEN]; /* used by net.h */
extern char g_ipset_setname6[IPSET_MAXNAMELEN]; /* used by net.h */
