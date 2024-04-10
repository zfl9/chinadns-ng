#pragma once

#include "misc.h"
#include "tag.h"
#include <stdbool.h>

/* {"a.txt", "b.txt", NULL} */
typedef const char **filenames_t;

/* initialize domain-name-list from file */
void dnl_init(const filenames_t tag_to_filenames[TAG__MAX + 1], bool gfwlist_first);

bool dnl_is_empty(void);

/* check `dnl_is_empty()` before calling */
u8 dnl_get_tag(const char *noalias name, int namelen, u8 default_tag);
