#ifndef CHINADNS_NG_DNSUTILS_H
#define CHINADNS_NG_DNSUTILS_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#undef _GNU_SOURCE

/* dns packet max size (in bytes) */
#define DNS_PACKET_MAXSIZE 512

/* dns header structure (fixed length) */
typedef struct __attribute__((packed)) {
    uint16_t id; // id of message
    uint8_t  qr:1; // query=0; response=1
    uint8_t  opcode:4; // standard-query=0, etc.
    uint8_t  aa:1; // is authoritative answer, set by server
    uint8_t  tc:1; // message is truncated, set by server
    uint8_t  rd:1; // is recursion desired, set by client
    uint8_t  ra:1; // is recursion available, set by server
    uint8_t  z:3; // reserved bits set to zero
    uint8_t  rcode:4; // response code: no-error=0, etc.
    uint16_t question_count; // question count
    uint16_t answer_count; // answer record count
    uint16_t authority_count; // authority record count
    uint16_t additional_count; // additional record count
} dns_header_t;

/* fixed length of query structure */
typedef struct __attribute__((packed)) {
    // field qname; variable length
    uint16_t qtype; // query type: A/AAAA/CNAME/MX, etc.
    uint16_t qclass; // query class: internet=0x0001
} dns_query_t;

/* fixed length of record structure */
typedef struct __attribute__((packed)) {
    // field rname; variable length
    uint16_t rtype; // record type: A/AAAA/CNAME/MX, etc.
    uint16_t rclass; // record class: internet=0x0001
    uint32_t rttl; // record ttl value (in seconds)
    uint16_t rdatalen; // record data length
    uint8_t  rdataptr[]; // record data pointer, sizeof=0
} dns_record_t;

/* check if a dns query packet is valid */
bool dns_query_is_valid(const void *data, size_t len, const char **nameptr);

/* check if a dns reply packet is valid */
bool dns_reply_is_valid(const void *data, size_t len, const char **nameptr);

#endif
