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

/* check dns msg */
static bool check_msg(bool is_query,
    const void *noalias msg, ssize_t len,
    char *noalias ascii_name, int *noalias p_wire_namelen)
{
    /* check msg length */
    unlikely_if (len < (ssize_t)DNS_MSG_MINSIZE) {
        log_error("dns msg is too short: %zd", len);
        return false;
    }
    unlikely_if (len > DNS_MSG_MAXSIZE) {
        log_error("dns msg is too long: %zd", len);
        return false;
    }

    /* check header */
    const struct dns_header *header = msg;
    unlikely_if (header->qr != (is_query ? DNS_QR_QUERY : DNS_QR_REPLY)) {
        log_error("this is a %s msg, but header->qr is %u", is_query ? "query" : "reply", (uint)header->qr);
        return false;
    }
    unlikely_if (header->opcode != DNS_OPCODE_QUERY) {
        log_error("this is not a standard query, opcode: %u", (uint)header->opcode);
        return false;
    }
    unlikely_if (ntohs(header->question_count) != 1) {
        log_error("there should be one and only one question: %u", (uint)ntohs(header->question_count));
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
    unlikely_if (wire_namelen < DNS_NAME_WIRE_MINLEN) {
        log_error("encoded domain name is too short: %d", wire_namelen);
        return false;
    }
    unlikely_if (wire_namelen > DNS_NAME_WIRE_MAXLEN) {
        log_error("encoded domain name is too long: %d", wire_namelen);
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

    /* check query class */
    const struct dns_question *question = msg;
    unlikely_if (ntohs(question->qclass) != DNS_CLASS_INTERNET) {
        log_error("only supports standard internet query class: %u", (uint)ntohs(question->qclass));
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

/* return false if msg is bad, if `f()` return true then break foreach */
static bool foreach_ip(const void *noalias msg, ssize_t len, int wire_namelen,
    bool (*f)(const void *noalias ip, bool v4, void *ud), void *ud)
{
    const struct dns_header *h = msg;
    u16 answer_count = ntohs(h->answer_count);

    /* move to answer section */
    msg += sizeof(struct dns_header) + wire_namelen + sizeof(struct dns_question);
    len -= sizeof(struct dns_header) + wire_namelen + sizeof(struct dns_question);

    /* foreach `A/AAAA` record */
    for (u16 i = 0; i < answer_count; ++i) {
        unlikely_if (!skip_name(&msg, &len))
            return false;

        const struct dns_record *record = msg;
        unlikely_if (ntohs(record->rclass) != DNS_CLASS_INTERNET) {
            log_error("only supports standard internet query class: %u", (uint)ntohs(record->rclass));
            return false;
        }

        u16 rdatalen = ntohs(record->rdatalen);
        ssize_t recordlen = sizeof(struct dns_record) + rdatalen;
        unlikely_if (len < recordlen) {
            log_error("remaining length is less than sizeof(record): %zd < %zd", len, recordlen);
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

        msg += recordlen;
        len -= recordlen;
    }

    return true;
}

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

size_t dns_remove_answer(void *noalias msg, int wire_namelen) {
    struct dns_header *h = msg;
    h->rcode = DNS_RCODE_NOERROR;
    h->answer_count = 0;
    h->authority_count = 0;
    h->additional_count = 0;
    return sizeof(struct dns_header) + wire_namelen + sizeof(struct dns_question);
}

void dns_to_reply_msg(void *noalias msg) {
    struct dns_header *h = msg;
    h->qr = DNS_QR_REPLY;
    h->rcode = DNS_RCODE_NOERROR;
}

bool dns_check_query(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen) {
    return check_msg(true, msg, len, ascii_name, p_wire_namelen);
}

bool dns_check_reply(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen) {
    return check_msg(false, msg, len, ascii_name, p_wire_namelen);
}

static bool test_ip(const void *noalias ip, bool v4, void *ud) {
    int *res = ud;
    *res = ipset_test_ip(ip, v4) ? DNS_TEST_IP_IS_CHNIP : DNS_TEST_IP_NOT_CHNIP;
    return true; // break foreach
}

int dns_test_ip(const void *noalias msg, ssize_t len, int wire_namelen) {
    int res = DNS_TEST_IP_NOT_FOUND;
    unlikely_if (!foreach_ip(msg, len, wire_namelen, test_ip, &res))
        return DNS_TEST_IP_BAD_MSG;
    return res;
}

static bool add_ip(const void *noalias ip, bool v4, void *ud) {
    ipset_add_ip(ip, v4, (uintptr_t)ud);
    return false; // not break foreach
}

void dns_add_ip(const void *noalias msg, ssize_t len, int wire_namelen, bool chn) {
    foreach_ip(msg, len, wire_namelen, add_ip, (void *)(uintptr_t)chn);
    ipset_end_add_ip(chn);
}
