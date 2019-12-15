#ifndef CHINADNS_NG_DNSUTILS_H
#define CHINADNS_NG_DNSUTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#undef _GNU_SOURCE

/* dns packet max size (in bytes) */
#define DNS_PACKET_MAXSIZE 1472 /* compatible with edns */

/* domain name max len (including separator '.' and '\0') */
/* example: "www.example.com", length = 16 (including '\0') */
#define DNS_DOMAIN_NAME_MAXLEN 254 /* eg: char namebuf[DNS_DOMAIN_NAME_MAXLEN] */


#ifndef __BYTE_ORDER
#	if defined(_BYTE_ORDER)
#		define __BYTE_ORDER _BYTE_ORDER
#		define __LITTLE_ENDIAN _LITTLE_ENDIAN
#		define __BIG_ENDIAN _BIG_ENDIAN
#	elif defined(BYTE_ORDER)
#		define __BYTE_ORDER BYTE_ORDER
#		define __LITTLE_ENDIAN LITTLE_ENDIAN
#		define __BIG_ENDIAN BIG_ENDIAN
#	elif defined(__BYTE_ORDER__)
#		define __BYTE_ORDER __BYTE_ORDER__
#		define __LITTLE_ENDIAN __LITTLE_ENDIAN__
#		define __BIG_ENDIAN __BIG_ENDIAN__
#	elif (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) || \
			defined(WORDS_LITTLEENDIAN)
#		define __BYTE_ORDER 1
#		define __LITTLE_ENDIAN 1
#		define __BIG_ENDIAN 0
#	elif (!defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)) || \
			defined(WORDS_BIGENDIAN)
#		define __BYTE_ORDER 0
#		define __LITTLE_ENDIAN 1
#		define __BIG_ENDIAN 0
#	else
#		error "__BYTE_ORDER is not defined."
#	endif
#endif


/* dns header structure (fixed length) */
typedef struct __attribute__((packed)) {
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
#   error "only supports big endian and little endian"
#endif
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
    uint8_t  rdataptr[]; // record data pointer (sizeof=0)
} dns_record_t;

/* check a dns query packet, `name_buf` used to get domain name */
bool dns_query_check(const void *packet_buf, ssize_t packet_len, char *name_buf);

/* check a dns reply packet, `name_buf` used to get domain name */
bool dns_reply_check(const void *packet_buf, ssize_t packet_len, char *name_buf);

#endif
