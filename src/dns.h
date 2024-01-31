#pragma once

#include "misc.h"
#include <stdbool.h>
#include <sys/types.h>

/* dns message size */
#define DNS_MSG_MAXSIZE 4096
#define DNS_MSG_MINSIZE (12 /* sizeof(struct dns_header) */ + DNS_NAME_WIRE_MINLEN + 4 /* sizeof(struct dns_query) */)

/* ASCII name length (not included \0) */
#define DNS_NAME_MAXLEN 253 /* "www.example.com" n:15 */

/* wire name length */
#define DNS_NAME_WIRE_MINLEN 1 /* "\0" (root domain) */
#define DNS_NAME_WIRE_MAXLEN 255 /* "\3www\7example\3com\0" */

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

u16 dns_get_id(const void *noalias msg);

void dns_set_id(void *noalias msg, u16 id);

u16 dns_get_qtype(const void *noalias msg, int wire_namelen);

/* keep only the HEADER and QUESTION section */
size_t dns_remove_answer(void *noalias msg, int wire_namelen);

/* convert a query msg to a reply msg (rcode: NOERROR) */
void dns_to_reply_msg(void *noalias msg);

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
