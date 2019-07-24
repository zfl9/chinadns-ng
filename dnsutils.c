#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#include <string.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NOERROR 0
#define DNS_CLASS_INTERNET 1
#define DNS_RECORD_TYPE_A 1 /* ipv4 address */
#define DNS_RECORD_TYPE_AAAA 28 /* ipv6 address */
#define DNS_DNAME_LABEL_MAXLEN 63 /* domain-name label maxlen */
#define DNS_DNAME_COMPRESSION_MINVAL 192 /* domain-name compression minval */

/* check query packet header */
static inline bool dns_qheader_check(const void *data) {
    const dns_header_t *header = data;
    if (header->qr != DNS_QR_QUERY) {
        LOGERR("[dns_qheader_check] this is a query packet, but header->qr != 0");
        return false;
    }
    if (header->opcode != DNS_OPCODE_QUERY) {
        LOGERR("[dns_qheader_check] this is not a standard query, opcode: %hhu", header->opcode);
        return false;
    }
    if (!header->rd) {
        LOGERR("[dns_qheader_check] non-recursive query is not supported");
        return false;
    }
    if (ntohs(header->question_count) != 1) {
        LOGERR("[dns_qheader_check] there should be one and only one question section");
        return false;
    }
    return true;
}

/* check reply packet header */
static inline bool dns_rheader_check(const void *data) {
    const dns_header_t *header = data;
    if (header->qr != DNS_QR_REPLY) {
        LOGERR("[dns_rheader_check] this is a reply packet, but header->qr != 1");
        return false;
    }
    if (header->tc) {
        LOGERR("[dns_rheader_check] dns reply message has been truncated");
        return false;
    }
    if (!header->ra) {
        LOGERR("[dns_rheader_check] non-recursive reply is not supported");
        return false;
    }
    if (ntohs(header->question_count) != 1) {
        LOGERR("[dns_rheader_check] there should be one and only one question section");
        return false;
    }
    return true;
}

/* check dns packet */
static bool dns_packet_check(const void *data, size_t len, char *name_buf, bool is_query, const void **answer_ptr) {
    /* check packet length */ 
    if (len < sizeof(dns_header_t) + sizeof(dns_query_t) + 1) {
        LOGERR("[dns_packet_check] the dns packet is too small: %zu", len);
        return false;
    }
    if (len > DNS_PACKET_MAXSIZE) {
        LOGERR("[dns_packet_check] the dns packet is too large: %zu", len);
        return false;
    }

    /* check packet header */
    if (is_query) if (!dns_qheader_check(data)) return false;
    if (!is_query) if (!dns_rheader_check(data)) return false;

    /* check question section */
    const uint8_t *ptr = data + sizeof(dns_header_t);
    len -= sizeof(dns_header_t);
    if (*ptr == 0) {
        LOGERR("[dns_get_domain_name] the length of the domain name is zero");
        return false;
    }
    if (*ptr >= DNS_DNAME_COMPRESSION_MINVAL) {
        LOGERR("[dns_get_domain_name] the first domain name should not use compression");
        return false;
    }
    if (*ptr > DNS_DNAME_LABEL_MAXLEN) {
        LOGERR("[dns_get_domain_name] the length of the domain name label is too long");
        return false;
    }
    const uint8_t *dptr = ptr;
    bool is_valid = false;
    while (true) {
        if (*dptr == 0) {
            is_valid = true;
            break;
        }
        dptr += *dptr + 1;
        len -= *dptr + 1;
        if (len <= 0) {
            break;
        }
    }
    if (!is_valid) {
        LOGERR("[dns_get_domain_name] the format of the dns packet is incorrect");
        return false;
    }
    if (!name_buf) return true;
    strcpy(name_buf, (char *)ptr + 1);
    name_buf += *ptr;
    while (*name_buf != 0) {
        uint8_t step = *name_buf;
        *name_buf = '.';
        name_buf += step + 1;
    }
    return true;
}

/* check the ipaddr of the first A/AAAA record is in `chnroute` ipset */
static bool dns_ipset_check(const void *data, size_t len) {
    // TODO
    return true;
}

/* check a dns query is valid, `name_buf` used to get relevant domain name */
bool dns_query_is_valid(const void *data, size_t len, char *name_buf) {
    return dns_packet_check(data, len, name_buf, true, NULL);
}

/* check a dns reply is valid, `name_buf` used to get relevant domain name */
bool dns_reply_is_valid(const void *data, size_t len, char *name_buf, bool is_trusted) {
    const void *answer_ptr = NULL;
    if (!dns_packet_check(data, len, name_buf, false, &answer_ptr)) return false;
    return is_trusted ? true : dns_ipset_check(answer_ptr, len - (answer_ptr - data));
}
