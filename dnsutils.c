#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#undef _GNU_SOURCE

static inline bool dns_length_is_valid(size_t len) {
    if (len <= sizeof(dns_header_t)) {
        LOGERR("[dns_length_is_valid] the dns packet is too small: %zu", len);
        return false;
    }
    if (len > DNS_PACKET_MAXSIZE) {
        LOGERR("[dns_length_is_valid] the dns packet is too large: %zu", len);
        return false;
    }
    return true;
}

static inline bool dns_header_is_valid(const void *data, size_t len) {
    // TODO
}

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
