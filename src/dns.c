#define _GNU_SOURCE
#include "dns.h"
#include "net.h"
#include "ipset.h"
#include "log.h"
#include <string.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>

struct dns_header {
    u16 id; // id of message
#if defined(__BIG_ENDIAN_BITFIELD)
    u8  qr:1; // query=0; response=1
    u8  opcode:4; // standard-query=0, etc.
    u8  aa:1; // is authoritative answer, set by server
    u8  tc:1; // message is truncated, set by server
    u8  rd:1; // is recursion desired, set by client
    u8  ra:1; // is recursion available, set by server
    u8  z:3; // reserved bits set to zero
    u8  rcode:4; // response code: no-error=0, etc.
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    u8  rd:1; // is recursion desired, set by client
    u8  tc:1; // message is truncated, set by server
    u8  aa:1; // is authoritative answer, set by server
    u8  opcode:4; // standard-query=0, etc.
    u8  qr:1; // query=0; response=1
    u8  rcode:4; // response code: no-error=0, etc.
    u8  z:3; // reserved bits set to zero
    u8  ra:1; // is recursion available, set by server
#else
    #error "please fix <asm/byteorder.h>"
#endif
    u16 question_count; // question count
    u16 answer_count; // answer record count
    u16 authority_count; // authority record count
    u16 additional_count; // additional record count
} __attribute__((packed));

struct dns_question {
    // field qname; variable length
    u16 qtype; // query type: A/AAAA/CNAME/MX, etc.
    u16 qclass; // query class: internet=0x0001
} __attribute__((packed));

struct dns_record {
    // field rname; variable length
    u16 rtype; // record type: A/AAAA/CNAME/MX, etc.
    u16 rclass; // record class: internet=0x0001
    u32 rttl; // record ttl value (in seconds)
    u16 rdatalen; // record data length
    char rdata[]; // record data pointer (sizeof=0)
} __attribute__((packed));

/* "\3www\6google\3com\0" => "www.google.com" */
static bool decode_name(char *noalias out, const char *noalias src, int len) {
    /* root domain ? */
    if (len <= DNS_NAME_WIRE_MINLEN) {
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
        unlikely_if (label_len < 1 || label_len > DNS_NAME_LABEL_MAXLEN) {
            log_error("label length is out of range: %d [1, %d]", label_len, DNS_NAME_LABEL_MAXLEN);
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

/* check dns msg */
static bool check_msg(bool is_query,
    const void *noalias msg, ssize_t len,
    char *noalias ascii_name, int *noalias p_wire_namelen)
{
    /* check msg length */
    unlikely_if (len < (ssize_t)DNS_MSG_MINSIZE || len > DNS_MSG_MAXSIZE) {
        log_error("msg length is out of range: %zd [%d, %d]", len, DNS_MSG_MINSIZE, DNS_MSG_MAXSIZE);
        return false;
    }

    /* check header */
    const struct dns_header *header = msg;
    unlikely_if (header->qr != (is_query ? DNS_QR_QUERY : DNS_QR_REPLY)) {
        log_error("this is a %s msg, but header->qr = %u", is_query ? "query" : "reply", (uint)header->qr);
        return false;
    }
    unlikely_if (ntohs(header->question_count) != 1) {
        log_error("there should be one and only one question: %u", (uint)ntohs(header->question_count));
        return false;
    }
    unlikely_if (is_query && header->tc) {
        log_error("query msg should not have the TC flag set");
        return false;
    }

    /* move to question section (name + struct dns_question) */
    msg += sizeof(struct dns_header);
    len -= sizeof(struct dns_header);

    /* search the queried domain name */
    /* encoded name: "\3www\6google\3com\0" */
    const void *p = memchr(msg, 0, len);
    unlikely_if (!p) {
        log_error("format error: domain name end byte not found");
        return false;
    }

    /* check name length */
    const int wire_namelen = p + 1 - msg;
    unlikely_if (wire_namelen < DNS_NAME_WIRE_MINLEN || wire_namelen > DNS_NAME_WIRE_MAXLEN) {
        log_error("encoded domain namelen is out of range: %d [%d, %d]", wire_namelen, DNS_NAME_WIRE_MINLEN, DNS_NAME_WIRE_MAXLEN);
        return false;
    }

    /* decode to ASCII format */
    if (ascii_name) {
        unlikely_if (!decode_name(ascii_name, msg, wire_namelen))
            return false;
    }
    if (p_wire_namelen)
        *p_wire_namelen = wire_namelen;

    /* move to `struct dns_question` */
    msg += wire_namelen;
    len -= wire_namelen;

    /* check remaining length */
    unlikely_if (len < (ssize_t)sizeof(struct dns_question)) {
        log_error("remaining length is less than sizeof(dns_question): %zd < %zu", len, sizeof(struct dns_question));
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

#define skip_record(p_ptr, p_len, count) \
    foreach_record(p_ptr, p_len, count, NULL, NULL)

static bool foreach_record(const void *noalias *noalias p_ptr, ssize_t *noalias p_len, int count, 
    bool (*f)(const struct dns_record *noalias record, ssize_t rdatalen, void *ud, bool *noalias is_break), void *ud) 
{
    if (count <= 0)
        return true;

    const void *ptr = *p_ptr;
    ssize_t len = *p_len;

    for (int i = 0; i < count; ++i) {
        unlikely_if (!skip_name(&ptr, &len))
            return false;

        const struct dns_record *record = ptr;
        ssize_t rdatalen = ntohs(record->rdatalen);
        ssize_t recordlen = sizeof(struct dns_record) + rdatalen;

        unlikely_if (len < recordlen) {
            log_error("remaining length is less than sizeof(record): %zd < %zd", len, recordlen);
            return false;
        }

        if (f) {
            bool is_break = false;
            unlikely_if (!f(record, rdatalen, ud, &is_break)) return false;
            if (is_break) break;
        }

        ptr += recordlen;
        len -= recordlen;
    }

    *p_ptr = ptr;
    *p_len = len;

    return true;
}

/* header + question */
#define msg_minlen(wire_namelen) \
    (sizeof(struct dns_header) + (wire_namelen) + sizeof(struct dns_question))

/* move to answer section */
#define move_to_answer(ptr, len, wire_namelen) ({ \
    (ptr) += msg_minlen(wire_namelen); \
    (len) -= msg_minlen(wire_namelen); \
})

u16 dns_get_id(const void *noalias msg) {
    return cast(const struct dns_header *, msg)->id;
}

void dns_set_id(void *noalias msg, u16 id) {
    cast(struct dns_header *, msg)->id = id;
}

u16 dns_get_qtype(const void *noalias msg, int wire_namelen) {
    const struct dns_question *q = msg + sizeof(struct dns_header) + wire_namelen;
    return ntohs(q->qtype);
}

static bool get_bufsz(const struct dns_record *noalias record, ssize_t rdatalen, void *ud, bool *noalias is_break) {
    (void)rdatalen;
    if (ntohs(record->rtype) == DNS_RECORD_TYPE_OPT) {
        u16 *bufsz = ud;
        *bufsz = ntohs(record->rclass);
        *is_break = true;
    }
    return true;
}

u16 dns_get_bufsz(const void *noalias msg, ssize_t len, int wire_namelen) {
    u16 bufsz = DNS_EDNS_MINSIZE;
    const struct dns_header *h = msg;

    if (ntohs(h->additional_count) <= 0)
        return bufsz;

    /* move to answer section */
    move_to_answer(msg, len, wire_namelen);

    /* skip answer && authority section */
    unlikely_if (!skip_record(&msg, &len, ntohs(h->answer_count)) || !skip_record(&msg, &len, ntohs(h->authority_count)))
        return bufsz;

    foreach_record(&msg, &len, ntohs(h->additional_count), get_bufsz, &bufsz);
    return bufsz;
}

bool dns_is_tc(const void *noalias msg) {
    return cast(const struct dns_header *, msg)->tc;
}

static int get_wire_namelen(const void *noalias msg, ssize_t len) {
    msg += sizeof(struct dns_header);
    len -= sizeof(struct dns_header);
    assert(len > 0);
    const void *p = memchr(msg, 0, len);
    assert(p);
    return p + 1 - msg;
}

u16 dns_truncate(void *noalias msg, ssize_t len) {
    cast(struct dns_header *, msg)->tc = 1;
    return dns_empty_reply(msg, get_wire_namelen(msg, len));
}

u16 dns_empty_reply(void *noalias msg, int wire_namelen) {
    struct dns_header *h = msg;
    h->qr = DNS_QR_REPLY;
    h->rcode = DNS_RCODE_NOERROR;
    h->answer_count = 0;
    h->authority_count = 0;
    h->additional_count = 0;
    return msg_minlen(wire_namelen);
}

bool dns_check_query(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen) {
    return check_msg(true, msg, len, ascii_name, p_wire_namelen);
}

bool dns_check_reply(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen) {
    return check_msg(false, msg, len, ascii_name, p_wire_namelen);
}

static bool check_ip_datalen(u16 rtype, ssize_t rdatalen) {
    int expect_len = (rtype == DNS_RECORD_TYPE_A) ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;
    unlikely_if (rdatalen != expect_len) {
        char ipver = (rtype == DNS_RECORD_TYPE_A) ? '4' : '6';
        log_error("rdatalen:%zd != sizeof(ipv%c):%d", rdatalen, ipver, expect_len);
        return false;
    }
    return true;
}

static bool test_ip(const struct dns_record *noalias record, ssize_t rdatalen, void *ud, bool *noalias is_break) {
    u16 rtype = ntohs(record->rtype);

    if (rtype == DNS_RECORD_TYPE_A || rtype == DNS_RECORD_TYPE_AAAA) {
        unlikely_if (!check_ip_datalen(rtype, rdatalen))
            return false;

        int *res = ud;
        bool v4 = rtype == DNS_RECORD_TYPE_A;
        *res = ipset_test_ip(record->rdata, v4) ? DNS_TEST_IP_IS_CHNIP : DNS_TEST_IP_NOT_CHNIP;

        *is_break = true;
    }

    return true;
}

static bool add_ip(const struct dns_record *noalias record, ssize_t rdatalen, void *ud, bool *noalias is_break) {
    (void)is_break;

    u16 rtype = ntohs(record->rtype);

    if (rtype == DNS_RECORD_TYPE_A || rtype == DNS_RECORD_TYPE_AAAA) {
        unlikely_if (!check_ip_datalen(rtype, rdatalen))
            return false;

        bool v4 = rtype == DNS_RECORD_TYPE_A;
        bool chn = (uintptr_t)ud;
        ipset_add_ip(record->rdata, v4, chn);
    }

    return true;
}

#define answer_count(msg) \
    ntohs(cast(const struct dns_header *, msg)->answer_count)

int dns_test_ip(const void *noalias msg, ssize_t len, int wire_namelen) {
    int count = answer_count(msg);
    move_to_answer(msg, len, wire_namelen);

    int res = DNS_TEST_IP_NOT_FOUND;
    unlikely_if (!foreach_record(&msg, &len, count, test_ip, &res))
        res = DNS_TEST_IP_BAD_MSG;
    return res;
}

void dns_add_ip(const void *noalias msg, ssize_t len, int wire_namelen, bool chn) {
    int count = answer_count(msg);
    move_to_answer(msg, len, wire_namelen);

    foreach_record(&msg, &len, count, add_ip, (void *)(uintptr_t)chn);
    ipset_end_add_ip(chn);
}
