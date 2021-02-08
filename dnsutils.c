#define _GNU_SOURCE
#include "dnsutils.h"
#include "netutils.h"
#include "logutils.h"
#include "chinadns.h"
#include <string.h>
#include <netinet/in.h>
#undef _GNU_SOURCE


/* check dns packet */
static bool dns_packet_check(const void *packet_buf, ssize_t packet_len, char *name_buf, bool is_query, const void **answer_ptr) {
    /* check packet length */
    if (packet_len < (ssize_t)sizeof(dns_header_t) + (ssize_t)sizeof(dns_query_t) + 1) {
        LOGERR("[dns_packet_check] the dns packet is too small: %zd", packet_len);
        return false;
    }
    if (packet_len > DNS_PACKET_MAXSIZE) {
        LOGERR("[dns_packet_check] the dns packet is too large: %zd", packet_len);
        return false;
    }

    /* check packet header */
    const dns_header_t *header = packet_buf;
    if (header->qr != (is_query ? DNS_QR_QUERY : DNS_QR_REPLY)) {
        LOGERR("[dns_packet_check] this is a %s packet, but header->qr != %d", is_query ? "query" : "reply", is_query ? DNS_QR_QUERY : DNS_QR_REPLY);
        return false;
    }
    if (header->opcode != DNS_OPCODE_QUERY) {
        LOGERR("[dns_packet_check] this is not a standard query, opcode: %hhu", header->opcode);
        return false;
    }
    if (ntohs(header->question_count) != 1) {
        LOGERR("[dns_packet_check] there should be one and only one question section");
        return false;
    }

    /* move ptr to question section */
    packet_buf += sizeof(dns_header_t);
    packet_len -= sizeof(dns_header_t);

    /* search the queried domain name */
    const void *dname_endptr = memchr(packet_buf, 0, (size_t)packet_len);
    if (!dname_endptr) {
        LOGERR("[dns_packet_check] did not find the domain name to be queried");
        return false;
    }
    if (dname_endptr - packet_buf > DNS_DOMAIN_NAME_MAXLEN) {
        LOGERR("[dns_packet_check] the length of the domain name is too long");
        return false;
    }

    /* get and convert the domain name */
    if (name_buf) {
        if (dname_endptr == packet_buf) {
            strcpy(name_buf, ".");
        } else {
            uint8_t label_len = *(uint8_t *)packet_buf;
            if (label_len > DNS_DNAME_LABEL_MAXLEN || label_len + 1 > dname_endptr - packet_buf) {
                LOGERR("[dns_packet_check] the length of the domain name label is too long");
                return false;
            }
            strcpy(name_buf, packet_buf + 1); /* name_buf: "www\6google\3com\0" */
            name_buf += label_len; /* move to '\6' pos */
            label_len = *(uint8_t *)name_buf; /* label length is 6 */
            size_t remain_len = strlen(name_buf); /* remaining length include '\6' */
            while (label_len != 0) {
                if (label_len > DNS_DNAME_LABEL_MAXLEN || label_len + 1 > (ssize_t)remain_len) {
                    LOGERR("[dns_packet_check] the length of the domain name label is too long");
                    return false;
                }
                *name_buf = '.'; /* change '\6' to '.' */
                name_buf += label_len + 1; /* move to next '\len' pos */
                remain_len -= label_len + 1; /* reduce the remaining len */
                label_len = *(uint8_t *)name_buf; /* update current label len */
            }
        }
    }

    /* check query class */
    packet_buf += dname_endptr - packet_buf + 1;
    packet_len -= dname_endptr - packet_buf + 1;
    if (packet_len < (ssize_t)sizeof(dns_query_t)) {
        LOGERR("[dns_packet_check] the format of the dns packet is incorrect");
        return false;
    }
    const dns_query_t *query_ptr = packet_buf;
    if (ntohs(query_ptr->qclass) != DNS_CLASS_INTERNET) {
        LOGERR("[dns_packet_check] only supports standard internet query class");
        return false;
    }

    /* save answer section ptr (used for reply) */
    if (answer_ptr) *answer_ptr = packet_buf + sizeof(dns_query_t);

    return true;
}

/* check the ipaddr of the first A/AAAA record is in `chnroute` ipset */
static bool dns_ipset_check(const void *packet_ptr, const void *ans_ptr, ssize_t ans_len) {
    const dns_header_t *header = packet_ptr;

    /* count number of answers */
    uint16_t answer_count = ntohs(header->answer_count);

    /* check dns packet length */
    if (ans_len < answer_count * ((ssize_t)sizeof(dns_record_t) + 1)) {
        LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
        return false;
    }

    /* only filter A/AAAA reply */
    uint16_t qtype = ntohs(((dns_query_t *)(ans_ptr - sizeof(dns_query_t)))->qtype);
    if (qtype != DNS_RECORD_TYPE_A && qtype != DNS_RECORD_TYPE_AAAA) return true;

    /* find the first A/AAAA record */
    for (uint16_t i = 0; i < answer_count; ++i) {
        while (true) {
            uint8_t label_len = *(uint8_t *)ans_ptr;
            if (label_len >= DNS_DNAME_COMPRESSION_MINVAL) {
                ans_ptr += 2;
                ans_len -= 2;
                if (ans_len < (ssize_t)sizeof(dns_record_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                break;
            }
            if (label_len > DNS_DNAME_LABEL_MAXLEN) {
                LOGERR("[dns_ipset_check] the length of the domain name label is too long");
                return false;
            }
            if (label_len == 0) {
                ++ans_ptr;
                --ans_len;
                if (ans_len < (ssize_t)sizeof(dns_record_t)) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                break;
            }
            ans_ptr += label_len + 1;
            ans_len -= label_len + 1;
            if (ans_len < (ssize_t)sizeof(dns_record_t) + 1) {
                LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                return false;
            }
        }
        const dns_record_t *record = ans_ptr;
        if (ntohs(record->rclass) != DNS_CLASS_INTERNET) {
            LOGERR("[dns_ipset_check] only supports standard internet query class");
            return false;
        }
        uint16_t rdatalen = ntohs(record->rdatalen);
        if (ans_len < (ssize_t)sizeof(dns_record_t) + rdatalen) {
            LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
            return false;
        }
        switch (ntohs(record->rtype)) {
            case DNS_RECORD_TYPE_A:
                if (rdatalen != IPV4_BINADDR_LEN) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                return ipset_addr_is_exists(record->rdataptr, true); /* in chnroute? */
            case DNS_RECORD_TYPE_AAAA:
                if (rdatalen != IPV6_BINADDR_LEN) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
                return ipset_addr_is_exists(record->rdataptr, false); /* in chnroute6? */
            default:
                ans_ptr += sizeof(dns_record_t) + rdatalen;
                ans_len -= sizeof(dns_record_t) + rdatalen;
                if (i != answer_count - 1 && ans_len < (ssize_t)sizeof(dns_record_t) + 1) {
                    LOGERR("[dns_ipset_check] the format of the dns packet is incorrect");
                    return false;
                }
        }
    }
    return g_noip_as_chnip; /* not found A/AAAA record */
}

/* check dns query, `name_buf` used to get domain name, return true if valid */
bool dns_query_check(const void *packet_buf, ssize_t packet_len, char *name_buf, const void **answer_ptr) {
    return dns_packet_check(packet_buf, packet_len, name_buf, true, answer_ptr);
}

/* check dns reply, `name_buf` used to get domain name, return true if accept */
bool dns_reply_check(const void *packet_buf, ssize_t packet_len, char *name_buf, bool chk_ipset) {
    const void *answer_ptr = NULL;
    if (!dns_packet_check(packet_buf, packet_len, name_buf, false, &answer_ptr)) return false;
    return chk_ipset ? dns_ipset_check(packet_buf, answer_ptr, packet_len - (answer_ptr - packet_buf)) : true;
}
