#pragma once

#include "misc.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>

/* dns packet max size (in bytes) */
#define DNS_PACKET_MAXSIZE 1472 /* compatible with edns */
#define DNS_PACKET_MINSIZE (sizeof(dns_header_t) + DNS_NAME_ENC_MINLEN + sizeof(dns_query_t))

/* name max len (ASCII name) */
#define DNS_NAME_MAXLEN 253 /* "www.example.com" length:15 */

/* encoded length range */
#define DNS_NAME_ENC_MINLEN 1 /* "\0" (root domain) */
#define DNS_NAME_ENC_MAXLEN 255 /* "\3www\7example\3com\0" */

#define DNS_NAME_LABEL_MAXLEN 63 /* 0011,1111 */
#define DNS_NAME_PTR_MINVAL 192 /* 1100,0000 */

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1
#define DNS_OPCODE_QUERY 0
#define DNS_RCODE_NOERROR 0
#define DNS_CLASS_INTERNET 1

/* qtype(rtype) */
#define DNS_RECORD_TYPE_A 1 /* ipv4 address */
#define DNS_RECORD_TYPE_AAAA 28 /* ipv6 address */

/* dns header structure (fixed length) */
typedef struct {
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
} __attribute__((packed)) dns_header_t;

/* fixed length of query structure */
typedef struct {
    // field qname; variable length
    u16 qtype; // query type: A/AAAA/CNAME/MX, etc.
    u16 qclass; // query class: internet=0x0001
} __attribute__((packed)) dns_query_t;

/* fixed length of record structure */
typedef struct {
    // field rname; variable length
    u16 rtype; // record type: A/AAAA/CNAME/MX, etc.
    u16 rclass; // record class: internet=0x0001
    u32 rttl; // record ttl value (in seconds)
    u16 rdatalen; // record data length
    char     rdata[]; // record data pointer (sizeof=0)
} __attribute__((packed)) dns_record_t;

/* check dns query, `name_buf` used to get domain name, return true if valid */
bool dns_check_query(const void *noalias packet_buf, ssize_t packet_len, char *noalias name_buf, int *noalias p_namelen);

/* check dns reply, `name_buf` used to get domain name, return true if valid */
bool dns_check_reply(const void *noalias packet_buf, ssize_t packet_len, char *noalias name_buf, int *noalias p_namelen);

/* result of dns_test_ip() */
#define DNS_IPCHK_IS_CHNIP 0
#define DNS_IPCHK_NOT_CHNIP 1
#define DNS_IPCHK_NOT_FOUND 2
#define DNS_IPCHK_BAD_PACKET 3

/* check if the answer ip is in the chnroute ipset (check qtype before call) */
int dns_test_ip(const void *noalias packet_buf, ssize_t packet_len, int namelen);

/* add the answer ip to ipset (chnroute/chnroute6) */
void dns_add_ip(const void *noalias packet_buf, ssize_t packet_len, int namelen);

#define dns_qtype(buf, namelen) ({ \
    const dns_query_t *q_ = (void *)(buf) + sizeof(dns_header_t) + (namelen); \
    ntohs(q_->qtype); \
})

/* "\0" => 0 */
/* "\1x\0" => 1 */
/* "\3foo\3com\0" => 7 */
#define dns_ascii_namelen(namelen) ({ \
    int n_ = (int)(namelen) - 2; \
    n_ > 0 ? n_ : 0; \
})
