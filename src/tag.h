#pragma once

#include "misc.h"
#include <stdbool.h>

/* see the `tag` field of `struct name` */
#define TAG_CHN 0 /* tag:chn => chnlist.txt */
#define TAG_GFW 1 /* tag:gfw => gfwlist.txt */
#define TAG__USER 2 /* 2 ~ 7 reserved for users */
#define TAG__MAX 7 /* 2 ~ 7 reserved for users */
#define TAG_NONE (TAG__MAX + 1) /* did not match any list */

/* return `tag` (-1 if failed), `name` will be copied */
u8 tag_register(const char *noalias name, bool *noalias p_overflow);

bool tag_is_valid(u8 tag);

/* "gfw", "chn", "none", "<user-defined>", "(null)" */
const char *tag_to_name(u8 tag);

/* find tag by name, -1 if not found */
u8 tag_from_name(const char *noalias name);
