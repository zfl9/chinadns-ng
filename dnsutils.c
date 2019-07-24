#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#undef _GNU_SOURCE

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0

static inline bool dns_length_is_valid(size_t len) {
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

static inline bool dns_header_is_valid(const void *data, bool is_query) {
    const dns_header_t *header = data;
    if (is_query && header->qr == 1) {
        LOGERR("[dns_header_is_valid] this is a query packet, but header->qr == 1");
        return false;
    }
    if (!is_query && header->qr == 0) {
        LOGERR("[dns_header_is_valid] this is a reply packet, but header->qr == 0");
        return false;
    }
    if (header->opcode != DNS_OPCODE_QUERY) {
        LOGERR("[dns_header_is_valid] header->opcode != DNS_OPCODE_QUERY");
        return false;
    }
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
