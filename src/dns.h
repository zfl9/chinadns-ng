#pragma once

#include "misc.h"
#include "ipset.h"
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

#define DNS_CLASS_IN 1

/* qtype, rtype */
#define DNS_TYPE_A 1 /* ipv4 address */
#define DNS_TYPE_AAAA 28 /* ipv6 address */
#define DNS_TYPE_OPT 41 /* EDNS pseudo-RR */

/* "\0" => 0 */
/* "\1x\0" => 1 */
/* "\3foo\3com\0" => 7 */
static inline int dns_ascii_namelen(int qnamelen) {
    int n = qnamelen - 2;
    return n > 0 ? n : 0;
}

u16 dns_header_len(void);

u16 dns_question_len(int qnamelen);

u16 dns_get_id(const void *noalias msg);

void dns_set_id(void *noalias msg, u16 id);

u16 dns_get_qtype(const void *noalias msg, int qnamelen);

/* get the peer's udp receive buffer size from the `OPT RR` */
u16 dns_get_bufsz(const void *noalias msg, ssize_t len, int qnamelen);

u8 dns_get_rcode(const void *noalias msg);

bool dns_is_tc(const void *noalias msg);

/*
* the msg has been checked by `check_reply()`
* return the length of the truncated reply-msg
*/
u16 dns_truncate(const void *noalias msg, ssize_t len, void *noalias out);

/* keep only the HEADER and QUESTION section */
u16 dns_empty_reply(void *noalias msg, int qnamelen);

/* check query msg, `ascii_name` used to get domain name */
bool dns_check_query(void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_qnamelen);

/* check reply msg, `ascii_name` used to get domain name */
bool dns_check_reply(void *noalias msg, ssize_t len, char *noalias ascii_name, int *noalias p_qnamelen, u16 *noalias p_newlen);

/* result of dns_test_ip() */
#define DNS_TEST_IP_IS_CHINA_IP 0
#define DNS_TEST_IP_NON_CHINA_IP 1
#define DNS_TEST_IP_NO_IP_FOUND 2
#define DNS_TEST_IP_OTHER_CASE 3

/* check if the answer ip is chnip (check qtype before call) */
int dns_test_ip(const void *noalias msg, ssize_t len, int qnamelen, const struct ipset_testctx *noalias ctx);

/* add the answer ip to ipset/nftset (tag:chn, tag:gfw) */
void dns_add_ip(const void *noalias msg, ssize_t len, int qnamelen, struct ipset_addctx *noalias ctx);

/* return -1 if failed */
i32 dns_get_ttl(const void *noalias msg, ssize_t len, int qnamelen, i32 nodata_ttl);

/* it should not fail because it has been checked by `get_ttl` */
void dns_update_ttl(void *noalias msg, ssize_t len, int qnamelen, i32 ttl_change);

/*
* `levels`: the level of the domain to get (8 bools)
* `domains[8]`: store the domain names
* `p_domain_end`: store the domain end ptr 
* `return`: the number of domains (-1 means error)
*/
int dns_qname_domains(const void *noalias msg, int qnamelen, u8 interest_levels,
    const char *noalias domains[noalias], const char *noalias *noalias p_domain_end);

/* "google.com" => {6:google 3:com 0}, return 0 if failed */
size_t dns_ascii_to_wire(const char *noalias ascii_name, size_t ascii_len, char buf[noalias DNS_NAME_WIRE_MAXLEN], u8 *noalias p_level);

bool dns_wire_to_ascii(const char *noalias wire_name, int wire_len, char buf[noalias DNS_NAME_MAXLEN + 1]);

void dns_make_reply(void *noalias rmsg, const void *noalias qmsg, int qnamelen, const void *noalias answer, size_t answerlen, u16 answer_n);
