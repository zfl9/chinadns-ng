#pragma once

#include <stdint.h>
#include "misc.h"

#define NAME_TAG_GFW 0 // hit the gfwlist
#define NAME_TAG_CHN 1 // hit the chnlist
#define NAME_TAG_NONE 2 // did not match any list

#define nametag_val2name(tag) ({ \
    const char *name_; \
    switch (tag) { \
        case NAME_TAG_GFW: \
            name_ = "gfw"; \
            break; \
        case NAME_TAG_CHN: \
            name_ = "chn"; \
            break; \
        case NAME_TAG_NONE: \
            name_ = "none"; \
            break; \
        default: \
            name_ = "(null)"; \
            break; \
    } \
    name_; \
})

extern u32 g_dnl_nitems;

/* initialize domain-name-list from file */
void dnl_init(void);

/* get name tag (check `g_dnl_nitems` before calling) */
u8 get_name_tag(const char *noalias name, int namelen);
