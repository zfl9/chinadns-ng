#pragma once

#include <stdint.h>
#include "misc.h"

#define NAME_TAG_GFW 0 // hit the gfwlist
#define NAME_TAG_CHN 1 // hit the chnlist
#define NAME_TAG_NONE 2 // did not match any list

extern uint32_t g_dnl_nitems;

/* initialize domain-name-list from file */
void dnl_init(void);

/* get name tag by dnl match */
uint8_t get_name_tag(const char *noalias name, int namelen);
