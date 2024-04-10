#define _GNU_SOURCE
#include "tag.h"
#include <stddef.h>
#include <string.h>

static const char *s_tag_to_name[] = {
    [TAG_CHN] = "chn",
    [TAG_GFW] = "gfw",
    [TAG__USER ... TAG__MAX] = NULL,
    [TAG_NONE] = "none",
};

u8 tag_register(const char *noalias name, bool *noalias p_overflow) {
    /* reason for failure */
    bool overflow = false;

    /* already registered ? */
    u8 tag = tag_from_name(name);
    if (tag != (u8)-1) {
        if (tag == TAG_CHN || tag == TAG_GFW || tag == TAG_NONE)
            goto err;
        return tag;
    }

    for (int i = 0; name[i]; ++i) {
        char c = name[i];
        bool ok = ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_';
        if (!ok) goto err;
    }

    /* alloc new tag value */
    for (u8 tag = TAG__USER; tag <= TAG__MAX; ++tag) {
        if (!s_tag_to_name[tag]) {
            s_tag_to_name[tag] = strdup(name);
            return tag;
        }
    }
    /* all tag values are used up */
    overflow = true;

err:
    if (p_overflow)
        *p_overflow = overflow;
    return -1;
}

bool tag_is_valid(u8 tag) {
    return tag < array_n(s_tag_to_name) && s_tag_to_name[tag];
}

const char *tag_to_name(u8 tag) {
    if (tag < array_n(s_tag_to_name))
        return s_tag_to_name[tag] ?: "(null)";
    return "(null)";
}

u8 tag_from_name(const char *noalias name) {
    for (u8 tag = 0; tag <= TAG_NONE; ++tag) {
        if (s_tag_to_name[tag] && strcmp(s_tag_to_name[tag], name) == 0)
            return tag;
    }
    return -1;
}
