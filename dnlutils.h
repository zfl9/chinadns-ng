#ifndef CHINADNS_NG_DNLUTILS_H
#define CHINADNS_NG_DNLUTILS_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdbool.h>
#undef _GNU_SOURCE

/* initialize domain-name-list from file */
size_t dnl_init(const char *filename);

/* check if the given domain name matches */
bool dnl_ismatch(char *domainname);

#endif
