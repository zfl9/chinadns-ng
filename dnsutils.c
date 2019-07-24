#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#undef _GNU_SOURCE

/* check if a dns query packet is valid */
bool dns_query_is_valid(const void *data, size_t len) {
    // TODO
    return false;
}

/* check if a dns reply packet is valid */
bool dns_reply_is_valid(const void *data, size_t len) {
    // TODO
    return false;
}
