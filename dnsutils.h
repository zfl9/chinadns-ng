#ifndef CHINADNS_NG_DNSUTILS_H
#define CHINADNS_NG_DNSUTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <sys/types.h>
#undef _GNU_SOURCE

#if !(defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN))
  #error "__BYTE_ORDER or __LITTLE_ENDIAN or __BIG_ENDIAN not defined"
#endif

/* dns packet max size (in bytes) */
#define DNS_PACKET_MAXSIZE 1472 /* compatible with edns */

/* domain name max len (including separator '.' and '\0') */
/* example: "www.example.com", length = 16 (including '\0') */
#define DNS_DOMAIN_NAME_MAXLEN 254 /* eg: char namebuf[DNS_DOMAIN_NAME_MAXLEN] */

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NOERROR 0
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
    uint8_t  rdataptr[]; // record data pointer (sizeof=0)
} __attribute__((packed)) dns_record_t;

/* check dns query, `name_buf` used to get domain name, return true if valid */
bool dns_query_check(const void *packet_buf, ssize_t packet_len, char *name_buf, const void **answer_ptr);

/* check dns reply, `name_buf` used to get domain name, return true if accept */
bool dns_reply_check(const void *packet_buf, ssize_t packet_len, char *name_buf, bool chk_ipset);

#endif
