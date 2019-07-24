#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#include <netinet/in.h>
#undef _GNU_SOURCE

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0

static inline bool dns_packet_length_check(size_t len) {
    if (len < sizeof(dns_header_t) + sizeof(dns_query_t) + 1) {
        LOGERR("[dns_length_is_valid] the dns packet is too small: %zu", len);
        return false;
    }
    if (len > DNS_PACKET_MAXSIZE) {
        LOGERR("[dns_length_is_valid] the dns packet is too large: %zu", len);
        return false;
    }
    return true;
}

static inline bool dns_query_header_check(const void *data) {
    const dns_header_t *header = data;
    if (header->qr == 1) {
        LOGERR("[dns_query_header_check] this is a query packet, but header->qr == 1");
        return false;
    }
    if (header->opcode != DNS_OPCODE_QUERY) {
        LOGERR("[dns_query_header_check] this is not a standard query packet, opcode: %hhu", header->opcode);
        return false;
    }
    if (!header->rd) {
        LOGERR("[dns_query_header_check] non-recursive query is not supported");
        return false;
    }
    if (header->question_count == 0) {
        LOGERR("[dns_query_header_check] need at least one question section");
        return false;
    }
    return true;
}

static inline bool dns_reply_header_check(const void *data) {
    const dns_header_t *header = data;
    if (header->qr == 0) {
        LOGERR("[dns_reply_header_check] this is a reply packet, but header->qr == 0");
        return false;
    }
    if (!header->ra) {
        LOGERR("[dns_reply_header_check] non-recursive reply is not supported");
        return false;
    }
    return true;
}

/* check a dns query is valid, nameptr used to get relevant domain name */
bool dns_query_is_valid(const void *data, size_t len, const char **nameptr) {
    // TODO
    return false;
}

/* check a dns reply is valid, nameptr used to get relevant domain name */
bool dns_reply_is_valid(const void *data, size_t len, const char **nameptr) {
    // TODO
    return false;
}
