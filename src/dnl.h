#pragma once

#include "misc.h"
#include <stdbool.h>

// see the `tag` field of `struct name`
#define NAME_TAG_GFW 0 // hit the gfwlist
#define NAME_TAG_CHN 1 // hit the chnlist
#define NAME_TAG_NONE 2 // did not match any list

/* initialize domain-name-list from file */
void dnl_init(const char *noalias gfwlist[noalias], const char *noalias chnlist[noalias], bool gfwlist_first);

bool dnl_is_empty(void);

/* check `dnl_is_empty()` before calling */
u8 get_name_tag(const char *noalias name, int namelen, u8 default_tag);

/* string literal: "gfw", "chn", "none" */
const char *get_tag_desc(u8 tag);
