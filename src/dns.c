#define _GNU_SOURCE
#include "dns.h"
#include "net.h"
#include "ipset.h"
#include "log.h"
#include <string.h>

/* "\3www\6google\3com\0" => "www.google.com" */
static bool decode_name(char *noalias out, const char *noalias src, int len) {
    /* root domain ? */
    if (len <= DNS_NAME_ENC_MINLEN) {
        out[0] = '.';
        out[1] = '\0';
        return true;
    }

    /* ignore last byte: src="\3www\6google\3com" */
    /* ignore first byte: out="www\6google\3com\0" */
    memcpy(out, src + 1, --len);

    /* foreach label (len:1byte | label) */
    for (int first = 1; len >= 2;) {
        if (first) first = 0; else *out++ = '.';
        int label_len = *(const ubyte *)src++; --len;
        unlikely_if (label_len < 1) {
            log_error("label length is too short: %d", label_len);
            return false;
        }
        unlikely_if (label_len > DNS_NAME_LABEL_MAXLEN) {
            log_error("label length is too long: %d", label_len);
            return false;
        }
        unlikely_if (label_len > len) {
            log_error("label length is greater than remaining length: %d > %d", label_len, len);
            return false;
        }
        src += label_len;
        len -= label_len;
        out += label_len;
    }

    unlikely_if (len != 0) {
        log_error("name format error, remaining length: %d", len);
        return false;
    }

    return true;
}

/* check dns packet */
static bool check_packet(bool is_query,
    const void *noalias packet_buf, ssize_t packet_len,
    char *noalias name_buf, int *noalias p_namelen)
{
    /* check packet length */
    unlikely_if (packet_len < (ssize_t)DNS_PACKET_MINSIZE) {
        log_error("dns packet is too short: %zd", packet_len);
        return false;
    }
    unlikely_if (packet_len > DNS_PACKET_MAXSIZE) {
        log_error("dns packet is too long: %zd", packet_len);
        return false;
    }

    /* check header */
    const struct dns_header *header = packet_buf;
    unlikely_if (header->qr != (is_query ? DNS_QR_QUERY : DNS_QR_REPLY)) {
        log_error("this is a %s packet, but header->qr is %u", is_query ? "query" : "reply", (uint)header->qr);
        return false;
    }
    unlikely_if (header->opcode != DNS_OPCODE_QUERY) {
        log_error("this is not a standard query, opcode: %u", (uint)header->opcode);
        return false;
    }
    unlikely_if (ntohs(header->question_count) != 1) {
        log_error("there should be one and only one question section: %u", (uint)ntohs(header->question_count));
        return false;
    }

    /* move to question section (name + struct dns_query) */
    packet_buf += sizeof(struct dns_header);
    packet_len -= sizeof(struct dns_header);

    /* search the queried domain name */
    /* encoded name: "\3www\6google\3com\0" */
    const void *p = memchr(packet_buf, 0, packet_len);
    unlikely_if (!p) {
        log_error("format error: domain name end byte not found");
        return false;
    }

    /* check name length */
    const int namelen = p + 1 - packet_buf;
    unlikely_if (namelen < DNS_NAME_ENC_MINLEN) {
        log_error("encoded domain name is too short: %d", namelen);
        return false;
    }
    unlikely_if (namelen > DNS_NAME_ENC_MAXLEN) {
        log_error("encoded domain name is too long: %d", namelen);
        return false;
    }

    /* decode to ASCII format */
    if (name_buf) {
        unlikely_if (!decode_name(name_buf, packet_buf, namelen))
            return false;
    }
    if (p_namelen)
        *p_namelen = namelen;

    /* move to struct dns_query pos */
    packet_buf += namelen;
    packet_len -= namelen;

    /* check remaining length */
    unlikely_if (packet_len < (ssize_t)sizeof(struct dns_query)) {
        log_error("remaining length is less than sizeof(dns_query): %zd < %zu", packet_len, sizeof(struct dns_query));
        return false;
    }

    /* check query class */
    const struct dns_query *query_ptr = packet_buf;
    unlikely_if (ntohs(query_ptr->qclass) != DNS_CLASS_INTERNET) {
        log_error("only supports standard internet query class: %u", (uint)ntohs(query_ptr->qclass));
        return false;
    }

    return true;
}

/*          \0 => root domain */
/*      \2cn\0 => normal domain */
/*     [ptr:2] => fully compress */
/* \2cn[ptr:2] => partial compress */
static bool skip_name(const void *noalias *noalias p_ptr, ssize_t *noalias p_len) {
    const void *noalias ptr = *p_ptr;
    ssize_t len = *p_len;

    while (len > 0) {
        int label_len = *(const ubyte *)ptr;
        if (label_len == 0) {
            ++ptr;
            --len;
            break;
        } else if (label_len >= DNS_NAME_PTR_MINVAL) {
            ptr += 2;
            len -= 2;
            break;
        } else if (label_len <= DNS_NAME_LABEL_MAXLEN) {
            ptr += 1 + label_len;
            len -= 1 + label_len;
        } else {
            log_error("label length is too long: %d", label_len);
            return false;
        }
    }

    unlikely_if (len < (ssize_t)sizeof(struct dns_record)) {
        log_error("remaining length is less than sizeof(dns_record): %zd < %zu", len, sizeof(struct dns_record));
        return false;
    }

    *p_ptr = ptr;
    *p_len = len;
    return true;
}

/* return false if packet is bad, if `f()` return true then break foreach */
static bool foreach_ip(const void *noalias packet_buf, ssize_t packet_len, int namelen,
    bool (*f)(const void *noalias ip, bool v4, void *ud), void *ud)
{
    const struct dns_header *h = packet_buf;
    u16 answer_count = ntohs(h->answer_count);

    /* move to answer section */
    packet_buf += sizeof(struct dns_header) + namelen + sizeof(struct dns_query);
    packet_len -= sizeof(struct dns_header) + namelen + sizeof(struct dns_query);

    /* foreach `A/AAAA` record */
    for (u16 i = 0; i < answer_count; ++i) {
        unlikely_if (!skip_name(&packet_buf, &packet_len))
            return false;

        const struct dns_record *record = packet_buf;
        unlikely_if (ntohs(record->rclass) != DNS_CLASS_INTERNET) {
            log_error("only supports standard internet query class: %u", (uint)ntohs(record->rclass));
            return false;
        }

        u16 rdatalen = ntohs(record->rdatalen);
        ssize_t recordlen = sizeof(struct dns_record) + rdatalen;
        unlikely_if (packet_len < recordlen) {
            log_error("remaining length is less than sizeof(record): %zd < %zd", packet_len, recordlen);
            return false;
        }

        switch (ntohs(record->rtype)) {
            case DNS_RECORD_TYPE_A:
                unlikely_if (rdatalen != IPV4_BINADDR_LEN) {
                    log_error("rdatalen is not equal to sizeof(ipv4): %u != %d", (uint)rdatalen, IPV4_BINADDR_LEN);
                    return false;
                }
                if (f(record->rdata, true, ud)) return true; /* break foreach */
                break;
            case DNS_RECORD_TYPE_AAAA:
                unlikely_if (rdatalen != IPV6_BINADDR_LEN) {
                    log_error("rdatalen is not equal to sizeof(ipv6): %u != %d", (uint)rdatalen, IPV6_BINADDR_LEN);
                    return false;
                }
                if (f(record->rdata, false, ud)) return true; /* break foreach */
                break;
        }

        packet_buf += recordlen;
        packet_len -= recordlen;
    }

    return true;
}

bool dns_check_query(const void *noalias packet_buf, ssize_t packet_len, char *noalias name_buf, int *noalias p_namelen) {
    return check_packet(true, packet_buf, packet_len, name_buf, p_namelen);
}

bool dns_check_reply(const void *noalias packet_buf, ssize_t packet_len, char *noalias name_buf, int *noalias p_namelen) {
    return check_packet(false, packet_buf, packet_len, name_buf, p_namelen);
}

static bool test_ip(const void *noalias ip, bool v4, void *ud) {
    int *res = ud;
    *res = ipset_test_ip(ip, v4) ? DNS_IPCHK_IS_CHNIP : DNS_IPCHK_NOT_CHNIP;
    return true; // break foreach
}

int dns_test_ip(const void *noalias packet_buf, ssize_t packet_len, int namelen) {
    int res = DNS_IPCHK_NOT_FOUND;
    unlikely_if (!foreach_ip(packet_buf, packet_len, namelen, test_ip, &res))
        return DNS_IPCHK_BAD_PACKET;
    return res;
}

static bool add_ip(const void *noalias ip, bool v4, void *ud) {
    ipset_add_ip(ip, v4, (uintptr_t)ud);
    return false; // not break foreach
}

void dns_add_ip(const void *noalias packet_buf, ssize_t packet_len, int namelen, bool chn) {
    foreach_ip(packet_buf, packet_len, namelen, add_ip, (void *)(uintptr_t)chn);
    ipset_end_add_ip(chn);
}
