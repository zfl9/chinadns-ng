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
static bool dns_packet_check(const void *data, ssize_t len, char *name_buf, bool is_query, const void **answer_ptr) {
    /* check packet length */ 
    if (len < (ssize_t)sizeof(dns_header_t) + (ssize_t)sizeof(dns_query_t) + 1) {
        LOGERR("[dns_packet_check] the dns packet is too small: %zd", len);
        return false;
    }
    if (len > DNS_PACKET_MAXSIZE) {
        LOGERR("[dns_packet_check] the dns packet is too large: %zd", len);
        return false;
    }

    /* check packet header */
    if (is_query) if (!dns_qheader_check(data)) return false;
    if (!is_query) if (!dns_rheader_check(data)) return false;

    /* check question section */
    data += sizeof(dns_header_t);
    len -= sizeof(dns_header_t);
    const uint8_t *q_ptr = data;
    ssize_t q_len = len;
    if (*q_ptr == 0) {
        LOGERR("[dns_packet_check] the length of the domain name is zero");
        return false;
    }
    if (*q_ptr >= DNS_DNAME_COMPRESSION_MINVAL) {
        LOGERR("[dns_packet_check] the first domain name should not use compression");
        return false;
    }
    if (*q_ptr > DNS_DNAME_LABEL_MAXLEN) {
        LOGERR("[dns_packet_check] the length of the domain name label is too long");
        return false;
    }

    /* check domain name */
    bool is_valid = false;
    while (true) {
        if (*q_ptr == 0) {
            is_valid = true;
            ++q_ptr;
            --q_len;
            break;
        }
        q_ptr += *q_ptr + 1;
        q_len -= *q_ptr + 1;
        if (q_len <= 0) {
            break;
        }
    }
    if (!is_valid) {
        LOGERR("[dns_packet_check] the format of the dns packet is incorrect");
        return false;
    }

    /* get domain name */
    if (name_buf) {
        strcpy(name_buf, (char *)data + 1);
        name_buf += *(uint8_t *)data;
        while (*name_buf != 0) {
            uint8_t step = *name_buf;
            *name_buf = '.';
            name_buf += step + 1;
        }
    }

    /* check query class */
    data += len - q_len;
    len -= len - q_len;
    if (len < (ssize_t)sizeof(dns_query_t)) {
        LOGERR("[dns_packet_check] the format of the dns packet is incorrect");
        return false;
    }
    const dns_query_t *query_ptr = data;
    if (ntohs(query_ptr->qclass) != DNS_CLASS_INTERNET) {
        LOGERR("[dns_packet_check] only supports standard internet query class");
        return false;
    }

    /* save answer section ptr */
    if (answer_ptr) *answer_ptr = data + sizeof(dns_query_t);

    return true;
}

/* check the ipaddr of the first A/AAAA record is in `chnroute` ipset */
static bool dns_ipset_check(const void *base_ptr, const void *ans_ptr, ssize_t ans_len) {
    /* check header and length */
    const dns_header_t *header_ptr = base_ptr;
    uint16_t answer_count = ntohs(header_ptr->answer_count);
    if (answer_count == 0) return false;
    if (ans_len <= answer_count * ((ssize_t)sizeof(dns_record_t) + 2)) {
        LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
        return false;
    }
    if (header_ptr->rcode != DNS_RCODE_NOERROR) return false;

    /* only filter A/AAAA reply */
    uint16_t qtype = ntohs(((dns_query_t *)(ans_ptr - sizeof(dns_query_t)))->qtype);
    if (qtype != DNS_RECORD_TYPE_A && qtype != DNS_RECORD_TYPE_AAAA) return true;

    /* find the first A/AAAA record */
    const ipv4_addr_t *addr4bin_ptr = NULL;
    const ipv6_addr_t *addr6bin_ptr = NULL;
    for (uint16_t i = 0; i < answer_count; ++i) {
        if (*(uint8_t *)ans_ptr >= DNS_DNAME_COMPRESSION_MINVAL) {
            ans_ptr += 2;
            ans_len -= 2;
            if (ans_len < (ssize_t)sizeof(dns_record_t)) {
                LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                return false;
            }
        } else {
            while (true) {
                uint8_t step = *(uint8_t *)ans_ptr;
                if (step == 0) {
                    ++ans_ptr;
                    --ans_len;
                    break;
                }
                ans_ptr += step + 1;
                ans_len -= step + 1;
                if (ans_len < (ssize_t)sizeof(dns_record_t) + 1) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
            }
        }
        const dns_record_t *record_ptr = ans_ptr;
        if (ntohs(record_ptr->rclass) != DNS_CLASS_INTERNET) {
            LOGERR("[dns_ipset_check] only supports standard internet query class");
            return false;
        }
        switch (ntohs(record_ptr->rtype)) {
            case DNS_RECORD_TYPE_A:
                if (ntohs(record_ptr->rdatalen) != sizeof(ipv4_addr_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                if (ans_len < (ssize_t)sizeof(dns_record_t) + (ssize_t)sizeof(ipv4_addr_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                return ipset_addr4_is_exists(*(ipv4_addr_t *)((void *)&record_ptr->rdatalen + sizeof(record_ptr->rdatalen)));
            case DNS_RECORD_TYPE_AAAA:
                if (ntohs(record_ptr->rdatalen) != sizeof(ipv6_addr_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                if (ans_len < (ssize_t)sizeof(dns_record_t) + (ssize_t)sizeof(ipv6_addr_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                return ipset_addr6_is_exists((void *)&record_ptr->rdatalen + sizeof(record_ptr->rdatalen));
        }
    }
    return true; /* unachievable */
}

/* check a dns query is valid, `name_buf` used to get relevant domain name */
bool dns_query_is_valid(const void *data, ssize_t len, char *name_buf) {
    return dns_packet_check(data, len, name_buf, true, NULL);
}

/* check a dns reply is valid, `name_buf` used to get relevant domain name */
bool dns_reply_is_valid(const void *data, ssize_t len, char *name_buf, bool is_trusted) {
    const void *answer_ptr = NULL;
    if (!dns_packet_check(data, len, name_buf, false, &answer_ptr)) return false;
    return is_trusted ? true : dns_ipset_check(data, answer_ptr, len - (answer_ptr - data));
}
