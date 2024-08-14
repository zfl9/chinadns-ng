#define _GNU_SOURCE
#include "dns.h"
#include "net.h"
#include "ipset.h"
#include "log.h"
#include <string.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <limits.h>

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
            // log_error("label length is out of range: %d [1, %d]", label_len, DNS_NAME_LABEL_MAXLEN);
            return false;
        }
        unlikely_if (label_len > len) {
            // log_error("label length is greater than remaining length: %d > %d", label_len, len);
            return false;
        }
        src += label_len;
        len -= label_len;
        out += label_len;
    }

    unlikely_if (len != 0) {
        // log_error("name format error, remaining length: %d", len);
        return false;
    }

    return true;
}

/* check dns msg */
static bool check_msg(bool is_query,
    void *noalias msg, ssize_t len,
    char *noalias ascii_name, int *noalias p_qnamelen)
{
    /* check msg length */
    unlikely_if (len < (ssize_t)DNS_MSG_MINSIZE || len > DNS_MSG_MAXSIZE) {
        // log_error("msg length is out of range: %zd [%d, %d]", len, DNS_MSG_MINSIZE, DNS_MSG_MAXSIZE);
        return false;
    }

    /* check header */
    struct dns_header *header = msg;
    unlikely_if (header->qr != (is_query ? DNS_QR_QUERY : DNS_QR_REPLY)) {
        // log_error("this is a %s msg, but header->qr = %u", is_query ? "query" : "reply", (uint)header->qr);
        return false;
    }
    unlikely_if (ntohs(header->question_count) != 1) {
        // log_error("there should be one and only one question: %u", (uint)ntohs(header->question_count));
        return false;
    }
    unlikely_if (is_query && header->tc)
        header->tc = 0;

    /* move to question section (name + struct dns_question) */
    msg += sizeof(struct dns_header);
    len -= sizeof(struct dns_header);

    /* search the queried domain name */
    /* encoded name: "\3www\6google\3com\0" */
    const void *p = memchr(msg, 0, len);
    unlikely_if (!p) {
        // log_error("format error: domain name end byte not found");
        return false;
    }

    /* check name length */
    const int qnamelen = p + 1 - msg;
    unlikely_if (qnamelen < DNS_NAME_WIRE_MINLEN || qnamelen > DNS_NAME_WIRE_MAXLEN) {
        // log_error("encoded domain namelen is out of range: %d [%d, %d]", qnamelen, DNS_NAME_WIRE_MINLEN, DNS_NAME_WIRE_MAXLEN);
        return false;
    }

    /* decode to ASCII format */
    if (ascii_name) {
        unlikely_if (!decode_name(ascii_name, msg, qnamelen))
            return false;
    }
    *p_qnamelen = qnamelen;

    /* move to `struct dns_question` */
    msg += qnamelen;
    len -= qnamelen;

    /* check remaining length */
    unlikely_if (len < (ssize_t)sizeof(struct dns_question)) {
        // log_error("remaining length is less than sizeof(dns_question): %zd < %zu", len, sizeof(struct dns_question));
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
            // log_error("label length is too long: %d", label_len);
            return false;
        }
    }

    unlikely_if (len < (ssize_t)sizeof(struct dns_record)) {
        // log_error("remaining length is less than sizeof(dns_record): %zd < %zu", len, sizeof(struct dns_record));
        return false;
    }

    *p_ptr = ptr;
    *p_len = len;
    return true;
}

#define skip_record(p_ptr, p_len, count) \
    foreach_record(p_ptr, p_len, count, NULL, NULL)

static bool foreach_record(void *noalias *noalias p_ptr, ssize_t *noalias p_len, int count,
    bool (*f)(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break), void *ud)
{
    if (count <= 0)
        return true;

    void *ptr = *p_ptr;
    ssize_t len = *p_len;

    for (int i = 0; i < count; ++i) {
        ssize_t old_len = len;

        unlikely_if (!skip_name((const void **)&ptr, &len))
            return false;

        int rnamelen = old_len - len;
        struct dns_record *record = ptr;
        ssize_t recordlen = sizeof(struct dns_record) + ntohs(record->rdatalen);

        unlikely_if (len < recordlen) {
            // log_error("remaining length is less than sizeof(record): %zd < %zd", len, recordlen);
            return false;
        }

        ptr += recordlen;
        len -= recordlen;

        if (f) {
            bool is_break = false;
            unlikely_if (!f(record, rnamelen, ud, &is_break)) return false;
            if (is_break) break;
        }
    }

    *p_ptr = ptr;
    *p_len = len;

    return true;
}

#define is_normal_msg(msg) \
    (!dns_is_tc(msg) && dns_get_rcode(msg) == DNS_RCODE_NOERROR)

#define get_answer_count(msg) \
    ntohs(cast(const struct dns_header *, msg)->answer_count)

#define get_authority_count(msg) \
    ntohs(cast(const struct dns_header *, msg)->authority_count)

#define get_additional_count(msg) \
    ntohs(cast(const struct dns_header *, msg)->additional_count)

#define get_records_count(msg) \
    (get_answer_count(msg) + get_authority_count(msg) + get_additional_count(msg))

/* header + question */
#define msg_minlen(qnamelen) \
    (sizeof(struct dns_header) + (qnamelen) + sizeof(struct dns_question))

/* move to answer section */
#define move_to_records(msg, len, qnamelen) ({ \
    (msg) += msg_minlen(qnamelen); \
    (len) -= msg_minlen(qnamelen); \
})

u16 dns_header_len(void) {
    return sizeof(struct dns_header);
}

u16 dns_question_len(int qnamelen) {
    return qnamelen + sizeof(struct dns_question);
}

u16 dns_get_id(const void *noalias msg) {
    return cast(const struct dns_header *, msg)->id;
}

void dns_set_id(void *noalias msg, u16 id) {
    cast(struct dns_header *, msg)->id = id;
}

u16 dns_get_qtype(const void *noalias msg, int qnamelen) {
    const struct dns_question *q = msg + sizeof(struct dns_header) + qnamelen;
    return ntohs(q->qtype);
}

static bool get_bufsz(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break) {
    (void)rnamelen;

    if (ntohs(record->rtype) == DNS_TYPE_OPT) {
        u16 sz = ntohs(record->rclass);

        if (sz < DNS_EDNS_MINSIZE)
            sz = DNS_EDNS_MINSIZE;
        else if (sz > DNS_EDNS_MAXSIZE)
            sz = DNS_EDNS_MAXSIZE;

        u16 *bufsz = ud;
        *bufsz = sz;

        *is_break = true;
    }

    return true;
}

u16 dns_get_bufsz(const void *noalias msg, ssize_t len, int qnamelen) {
    u16 bufsz = DNS_EDNS_MINSIZE;

    int additional_count = get_additional_count(msg);
    if (additional_count <= 0)
        return bufsz;

    int answer_count = get_answer_count(msg);
    int authority_count = get_authority_count(msg);

    /* move to answer section */
    move_to_records(msg, len, qnamelen);

    /* skip answer && authority section */
    unlikely_if (!skip_record((void **)&msg, &len, answer_count + authority_count))
        return bufsz;

    /* search the OPT RR */
    foreach_record((void **)&msg, &len, additional_count, get_bufsz, &bufsz);

    return bufsz;
}

u8 dns_get_rcode(const void *noalias msg) {
    return cast(const struct dns_header *, msg)->rcode;
}

bool dns_is_tc(const void *noalias msg) {
    return cast(const struct dns_header *, msg)->tc;
}

static int get_qnamelen(const void *noalias msg, ssize_t len) {
    msg += sizeof(struct dns_header);
    len -= sizeof(struct dns_header);
    assert(len > 0);
    const void *p = memchr(msg, 0, len);
    assert(p);
    return p + 1 - msg;
}

u16 dns_truncate(const void *noalias msg, ssize_t len, void *noalias out) {
    int qnamelen = get_qnamelen(msg, len);
    memcpy(out, msg, msg_minlen(qnamelen));
    cast(struct dns_header *, out)->tc = 1;
    return dns_empty_reply(out, qnamelen);
}

u16 dns_empty_reply(void *noalias msg, int qnamelen) {
    struct dns_header *h = msg;
    h->qr = DNS_QR_REPLY;
    h->ra = 1;
    h->rcode = DNS_RCODE_NOERROR;
    h->answer_count = 0;
    h->authority_count = 0;
    h->additional_count = 0;
    return qnamelen > 0 ? msg_minlen(qnamelen) : sizeof(struct dns_header);
}

// return newlen (0 if failed)
static u16 rm_additional(void *noalias msg, ssize_t len, int qnamelen) {
    if (!is_normal_msg(msg))
        return len;

    void *start = msg;

    int answer_count = get_answer_count(msg);
    int authority_count = get_authority_count(msg);
    move_to_records(msg, len, qnamelen);

    unlikely_if (!skip_record(&msg, &len, answer_count + authority_count))
        return 0;

    struct dns_header *h = start;
    h->additional_count = 0;

    return msg - start;
}

bool dns_check_query(void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_qnamelen) {
    return check_msg(true, msg, len, ascii_name, p_qnamelen);
}

bool dns_check_reply(void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_qnamelen, u16 *noalias p_newlen) {
    unlikely_if (!check_msg(false, msg, len, ascii_name, p_qnamelen))
        return false;

    unlikely_if ((*p_newlen = rm_additional(msg, len, *p_qnamelen)) == 0)
        return false;

    struct dns_header *h = msg;
    h->ra = 1;

    return true;
}

static bool check_ip_datalen(u16 rtype, const struct dns_record *noalias record) {
    int rdatalen = ntohs(record->rdatalen);
    int expect_len = (rtype == DNS_TYPE_A) ? IPV4_LEN : IPV6_LEN;
    unlikely_if (rdatalen != expect_len) {
        // char ipver = (rtype == DNS_TYPE_A) ? '4' : '6';
        // log_error("rdatalen:%d != sizeof(ipv%c):%d", rdatalen, ipver, expect_len);
        return false;
    }
    return true;
}

struct test_ip_ud {
    const struct ipset_testctx *ctx;
    int res;
};

static bool test_ip(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break) {
    (void)rnamelen;

    u16 rtype = ntohs(record->rtype);

    if (rtype == DNS_TYPE_A || rtype == DNS_TYPE_AAAA) {
        unlikely_if (!check_ip_datalen(rtype, record))
            return false;

        struct test_ip_ud *u = ud;
        bool v4 = rtype == DNS_TYPE_A;
        u->res = ipset_test_ip(u->ctx, record->rdata, v4) ? DNS_TEST_IP_IS_CHINA_IP : DNS_TEST_IP_NON_CHINA_IP;

        *is_break = true;
    }

    return true;
}

static bool add_ip(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break) {
    (void)rnamelen;
    (void)is_break;

    u16 rtype = ntohs(record->rtype);

    if (rtype == DNS_TYPE_A || rtype == DNS_TYPE_AAAA) {
        unlikely_if (!check_ip_datalen(rtype, record))
            return false;

        struct ipset_addctx *ctx = ud;
        bool v4 = rtype == DNS_TYPE_A;
        ipset_add_ip(ctx, record->rdata, v4);
    }

    return true;
}

int dns_test_ip(const void *noalias msg, ssize_t len, int qnamelen, const struct ipset_testctx *noalias ctx) {
    if (!is_normal_msg(msg))
        return DNS_TEST_IP_OTHER_CASE;

    int count = get_answer_count(msg);
    move_to_records(msg, len, qnamelen);

    struct test_ip_ud ud = {
        .ctx = ctx,
        .res = DNS_TEST_IP_NO_IP_FOUND,
    };
    unlikely_if (!foreach_record((void **)&msg, &len, count, test_ip, &ud))
        ud.res = DNS_TEST_IP_OTHER_CASE;
    return ud.res;
}

void dns_add_ip(const void *noalias msg, ssize_t len, int qnamelen, struct ipset_addctx *noalias ctx) {
    if (!is_normal_msg(msg))
        return;

    int count = get_answer_count(msg);
    move_to_records(msg, len, qnamelen);

    foreach_record((void **)&msg, &len, count, add_ip, ctx);
    ipset_end_add_ip(ctx);
}

static bool get_ttl(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break) {
    (void)rnamelen;
    (void)is_break;

    if (ntohs(record->rtype) != DNS_TYPE_OPT) {
        /* it is hereby specified that a TTL value is an unsigned number,
            with a minimum value of 0, and a maximum value of 2147483647. */
        i32 ttl = ntohl(record->rttl);
        i32 *final_ttl = ud;
        if (ttl < *final_ttl)
            *final_ttl = ttl;
    }

    return true;
}

static bool update_ttl(struct dns_record *noalias record, int rnamelen, void *ud, bool *noalias is_break) {
    (void)rnamelen;
    (void)is_break;

    if (ntohs(record->rtype) != DNS_TYPE_OPT) {
        /* it is hereby specified that a TTL value is an unsigned number,
            with a minimum value of 0, and a maximum value of 2147483647. */
        i32 ttl = (i32)ntohl(record->rttl) + (intptr_t)ud;
        record->rttl = htonl(max(ttl, 1));
    }

    return true;
}

i32 dns_get_ttl(const void *noalias msg, ssize_t len, int qnamelen, i32 nodata_ttl) {
    if (!is_normal_msg(msg))
        return -1;

    int count = get_records_count(msg);
    move_to_records(msg, len, qnamelen);

    i32 ttl = INT32_MAX;

    unlikely_if (!foreach_record((void **)&msg, &len, count, get_ttl, &ttl))
        ttl = -1;

    if (ttl == INT32_MAX) /* nodata */
        ttl = nodata_ttl;

    return ttl;
}

void dns_update_ttl(void *noalias msg, ssize_t len, int qnamelen, i32 ttl_change) {
    int count = get_records_count(msg);
    move_to_records(msg, len, qnamelen);

    bool ok = foreach_record(&msg, &len, count, update_ttl, (void *)(intptr_t)ttl_change);
    assert(ok); (void)ok;
    assert(len == 0);
}

int dns_qname_domains(const void *noalias msg, int qnamelen, u8 interest_levels,
    const char *noalias domains[noalias], const char *noalias *noalias p_domain_end)
{
    const void *qname = msg + sizeof(struct dns_header);
    const void *qname_end = qname + qnamelen;

    const void *p_label = qname;
    int qname_level = 0;

    // level of qname
    bool ok = false;
    while (p_label < qname_end) {
        ubyte label_len = *(const ubyte *)p_label;
        if (label_len == 0) {
            // null label
            ok = true;
            break;
        } else if (label_len <= DNS_NAME_LABEL_MAXLEN) {
            p_label += 1 + label_len;
            ++qname_level;
        } else {
            return -1;
        }
    }
    unlikely_if (!ok) return -1;

    assert(interest_levels != 0);
    int min_interest_level = __builtin_ctz(interest_levels) + 1;
    if (qname_level < min_interest_level) return 0;

    int domains_n = 0;

    // domain ptr
    for (p_label = qname; qname_level > 0; --qname_level, p_label += 1 + *(const ubyte *)p_label) {
        if (qname_level <= 8 && interest_levels & (1 << (qname_level - 1)))
            domains[domains_n++] = p_label;
    }

    // domain end ptr
    *p_domain_end = qname_end - 1;

    return domains_n;
}

size_t dns_ascii_to_wire(const char *noalias ascii_name, size_t ascii_len, char buf[noalias DNS_NAME_WIRE_MAXLEN], u8 *noalias p_level) {
    u8 level = 0;
    int buf_n = 0;

    for (const char *start = ascii_name, *end, *ascii_end = ascii_name + ascii_len;
        (end = memchr(start, '.', ascii_end - start)) || (end = ascii_end);
        start = end + 1)
    {
        int len = end - start;
        unlikely_if (len < 1 || len > DNS_NAME_LABEL_MAXLEN) return 0;

        unlikely_if (buf_n + 1 + len > DNS_NAME_WIRE_MAXLEN) return 0;
        buf[buf_n] = len;
        memcpy(&buf[buf_n + 1], start, len);
        buf_n += 1 + len;

        ++level;

        if (end == ascii_end) break;
    }

    // null label
    if (buf_n + 1 > DNS_NAME_WIRE_MAXLEN) return 0;
    buf[buf_n++] = 0;

    if (p_level)
        *p_level = level;

    return buf_n;
}

bool dns_wire_to_ascii(const char *noalias wire_name, int wire_len, char buf[noalias DNS_NAME_MAXLEN + 1]) {
    assert(DNS_NAME_WIRE_MINLEN <= wire_len && wire_len <= DNS_NAME_WIRE_MAXLEN);
    return decode_name(buf, wire_name, wire_len);
}

void dns_make_reply(void *noalias rmsg, const void *noalias qmsg, int qnamelen, const void *noalias answer, size_t answerlen, u16 answer_n) {
    memcpy(rmsg, qmsg, msg_minlen(qnamelen));

    dns_empty_reply(rmsg, qnamelen);

    struct dns_header *h = rmsg;
    h->answer_count = htons(answer_n);
    h->aa = 1;

    memcpy(rmsg + msg_minlen(qnamelen), answer, answerlen);
}
