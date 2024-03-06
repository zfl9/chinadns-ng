#pragma once

#include "misc.h"
#include <stdbool.h>
#include <sys/types.h>

/* dns message size */
#define DNS_MSG_MINSIZE (12 /* sizeof(struct dns_header) */ + DNS_NAME_WIRE_MINLEN + 4 /* sizeof(struct dns_question) */)
#define DNS_MSG_MAXSIZE 65535

#define DNS_QMSG_MAXSIZE 512

#define DNS_EDNS_MINSIZE 512
#define DNS_EDNS_MAXSIZE 4096

/* ASCII name length (not included \0) */
#define DNS_NAME_MAXLEN 253 /* "www.example.com" n:15 */

/* wire name length */
#define DNS_NAME_WIRE_MINLEN 1 /* "\0" (root domain) */
#define DNS_NAME_WIRE_MAXLEN 255 /* "\3www\7example\3com\0" */

#define DNS_NAME_LABEL_MAXLEN 63 /* 0011,1111 */
#define DNS_NAME_PTR_MINVAL 192 /* 1100,0000 */

#define DNS_QR_QUERY 0
#define DNS_QR_REPLY 1

#define DNS_RCODE_NOERROR 0

/* qtype(rtype) */
#define DNS_RECORD_TYPE_A 1 /* ipv4 address */
#define DNS_RECORD_TYPE_AAAA 28 /* ipv6 address */
#define DNS_RECORD_TYPE_OPT 41 /* EDNS pseudo-RR */

u16 dns_get_id(const void *noalias msg);

void dns_set_id(void *noalias msg, u16 id);

u16 dns_get_qtype(const void *noalias msg, int wire_namelen);

/* get the peer's udp receive buffer size from the `OPT RR` */
u16 dns_get_bufsz(const void *noalias msg, ssize_t len, int wire_namelen);

bool dns_is_tc(const void *noalias msg);

/*
* the msg has been checked by `check_reply()`
* return the length of the truncated reply-msg
*/
u16 dns_truncate(void *noalias msg, ssize_t len);

/* keep only the HEADER and QUESTION section */
u16 dns_empty_reply(void *noalias msg, int wire_namelen);

/* "\0" => 0 */
/* "\1x\0" => 1 */
/* "\3foo\3com\0" => 7 */
static inline int dns_ascii_namelen(int wire_namelen) {
    int n = wire_namelen - 2;
    return n > 0 ? n : 0;
}

/* check query msg, `ascii_name` used to get domain name */
bool dns_check_query(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen);

/* check reply msg, `ascii_name` used to get domain name */
bool dns_check_reply(const void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_wire_namelen);

/* result of dns_test_ip() */
#define DNS_TEST_IP_IS_CHNIP 0
#define DNS_TEST_IP_NOT_CHNIP 1
#define DNS_TEST_IP_NOT_FOUND 2
#define DNS_TEST_IP_BAD_MSG 3

/* check if the answer ip is chnip (check qtype before call) */
int dns_test_ip(const void *noalias msg, ssize_t len, int wire_namelen);

/* add the answer ip to ipset/nftset (tag:chn, tag:gfw) */
void dns_add_ip(const void *noalias msg, ssize_t len, int wire_namelen, bool chn);
