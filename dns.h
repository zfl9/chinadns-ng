#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <sys/types.h>

#if !(defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN))
  #error "__BYTE_ORDER or __LITTLE_ENDIAN or __BIG_ENDIAN not defined"
#endif

/* dns packet max size (in bytes) */
#define DNS_PACKET_MAXSIZE 1472 /* compatible with edns */

#define DNS_PACKET_MINSIZE (sizeof(dns_header_t) + DNS_NAME_ENC_MINLEN + sizeof(dns_query_t))

/* name max len (ASCII name) */
/* "www.example.com" length:15 */
#define DNS_NAME_MAXLEN 253

/* encoded length range */
#define DNS_NAME_ENC_MINLEN 1 /* "\0" (root domain) */
#define DNS_NAME_ENC_MAXLEN 255 /* "\3www\7example\3com\0" */

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_REFUSED 5
#define DNS_CLASS_INTERNET 1
#define DNS_RECORD_TYPE_A 1 /* ipv4 address */
#define DNS_RECORD_TYPE_AAAA 28 /* ipv6 address */
#define DNS_DNAME_LABEL_MAXLEN 63 /* domain-name label maxlen */
#define DNS_DNAME_COMPRESSION_MINVAL 192 /* domain-name compression minval */

/* dns header structure (fixed length) */
typedef struct {
    uint16_t id; // id of message
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t  qr:1; // query=0; response=1
    uint8_t  opcode:4; // standard-query=0, etc.
    uint8_t  aa:1; // is authoritative answer, set by server
    uint8_t  tc:1; // message is truncated, set by server
    uint8_t  rd:1; // is recursion desired, set by client
    uint8_t  ra:1; // is recursion available, set by server
    uint8_t  z:3; // reserved bits set to zero
    uint8_t  rcode:4; // response code: no-error=0, etc.
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  rd:1; // is recursion desired, set by client
    uint8_t  tc:1; // message is truncated, set by server
    uint8_t  aa:1; // is authoritative answer, set by server
    uint8_t  opcode:4; // standard-query=0, etc.
    uint8_t  qr:1; // query=0; response=1
    uint8_t  rcode:4; // response code: no-error=0, etc.
    uint8_t  z:3; // reserved bits set to zero
    uint8_t  ra:1; // is recursion available, set by server
#else
    #error "only supports big endian and little endian"
#endif
    uint16_t question_count; // question count
    uint16_t answer_count; // answer record count
    uint16_t authority_count; // authority record count
    uint16_t additional_count; // additional record count
} __attribute__((packed)) dns_header_t;

/* fixed length of query structure */
typedef struct {
    // field qname; variable length
    uint16_t qtype; // query type: A/AAAA/CNAME/MX, etc.
    uint16_t qclass; // query class: internet=0x0001
} __attribute__((packed)) dns_query_t;

/* fixed length of record structure */
typedef struct {
    // field rname; variable length
    uint16_t rtype; // record type: A/AAAA/CNAME/MX, etc.
    uint16_t rclass; // record class: internet=0x0001
    uint32_t rttl; // record ttl value (in seconds)
    uint16_t rdatalen; // record data length
    uint8_t  rdata[]; // record data pointer (sizeof=0)
} __attribute__((packed)) dns_record_t;

/* check dns query, `name_buf` used to get domain name, return true if valid */
bool dns_query_check(const void *restrict packet_buf, ssize_t packet_len, char *restrict name_buf, size_t *restrict p_namelen);

/* check dns reply, `name_buf` used to get domain name, return true if accept */
bool dns_reply_check(const void *restrict packet_buf, ssize_t packet_len, char *restrict name_buf, size_t *restrict p_namelen);

/* result of dns_chnip_check() */
#define DNS_IPCHK_IS_CHNIP 0
#define DNS_IPCHK_NOT_CHNIP 1
#define DNS_IPCHK_NOT_FOUND 2
#define DNS_IPCHK_BAD_PACKET 3

/* check if the answer ip is in the chnroute ipset (check qtype before call) */
int dns_chnip_check(const void *restrict packet_buf, ssize_t packet_len, size_t namelen);

#define dns_qtype(buf, namelen) ({ \
    const dns_query_t *q = (buf) + sizeof(dns_header_t) + (namelen); \
    ntohs(q->qtype); \
})
