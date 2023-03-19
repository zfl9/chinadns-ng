#define _GNU_SOURCE
#include "ipset.h"
#include "opt.h"
#include "net.h"
#include "log.h"
#include "nl.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* data type */
#define NFNL_SUBSYS_IPSET 6
#define IPSET_CMD_TEST 11
#define IPSET_CMD_ADD 9

/* nlattr value */
#define IPSET_PROTOCOL 6

/* nlattr type */
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_LINENO 9
#define IPSET_ATTR_ADT 8
#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

/* ipset errcode */
#define IPSET_ERR_PROTOCOL (-4097)
#define IPSET_ERR_FIND_TYPE (-4098)
#define IPSET_ERR_MAX_SETS (-4099)
#define IPSET_ERR_BUSY (-4100)
#define IPSET_ERR_EXIST_SETNAME2 (-4101)
#define IPSET_ERR_TYPE_MISMATCH (-4102)
#define IPSET_ERR_EXIST (-4103)
#define IPSET_ERR_INVALID_CIDR (-4104)
#define IPSET_ERR_INVALID_NETMASK (-4105)
#define IPSET_ERR_INVALID_FAMILY (-4106)
#define IPSET_ERR_TIMEOUT (-4107)
#define IPSET_ERR_REFERENCED (-4108)
#define IPSET_ERR_IPADDR_IPV4 (-4109)
#define IPSET_ERR_IPADDR_IPV6 (-4110)
#define IPSET_ERR_COUNTER (-4111)
#define IPSET_ERR_COMMENT (-4112)
#define IPSET_ERR_INVALID_MARKMASK (-4113)
#define IPSET_ERR_SKBINFO (-4114)
#define IPSET_ERR_HASH_FULL (-4352)
#define IPSET_ERR_HASH_ELEM (-4353)
#define IPSET_ERR_INVALID_PROTO (-4354)
#define IPSET_ERR_MISSING_PROTO (-4355)
#define IPSET_ERR_HASH_RANGE_UNSUPPORTED (-4356)
#define IPSET_ERR_HASH_RANGE (-4357)

#define CASE_RET_NAME(MACRO) \
    case MACRO: return #MACRO

static inline const char *ipset_strerror(int errcode) {
    switch (errcode) {
        CASE_RET_NAME(IPSET_ERR_PROTOCOL);
        CASE_RET_NAME(IPSET_ERR_FIND_TYPE);
        CASE_RET_NAME(IPSET_ERR_MAX_SETS);
        CASE_RET_NAME(IPSET_ERR_BUSY);
        CASE_RET_NAME(IPSET_ERR_EXIST_SETNAME2);
        CASE_RET_NAME(IPSET_ERR_TYPE_MISMATCH);
        CASE_RET_NAME(IPSET_ERR_EXIST);
        CASE_RET_NAME(IPSET_ERR_INVALID_CIDR);
        CASE_RET_NAME(IPSET_ERR_INVALID_NETMASK);
        CASE_RET_NAME(IPSET_ERR_INVALID_FAMILY);
        CASE_RET_NAME(IPSET_ERR_INVALID_MARKMASK);
        CASE_RET_NAME(IPSET_ERR_TIMEOUT);
        CASE_RET_NAME(IPSET_ERR_REFERENCED);
        CASE_RET_NAME(IPSET_ERR_IPADDR_IPV4);
        CASE_RET_NAME(IPSET_ERR_IPADDR_IPV6);
        CASE_RET_NAME(IPSET_ERR_COUNTER);
        CASE_RET_NAME(IPSET_ERR_COMMENT);
        CASE_RET_NAME(IPSET_ERR_SKBINFO);
        CASE_RET_NAME(IPSET_ERR_HASH_FULL);
        CASE_RET_NAME(IPSET_ERR_HASH_ELEM);
        CASE_RET_NAME(IPSET_ERR_INVALID_PROTO);
        CASE_RET_NAME(IPSET_ERR_MISSING_PROTO);
        CASE_RET_NAME(IPSET_ERR_HASH_RANGE_UNSUPPORTED);
        CASE_RET_NAME(IPSET_ERR_HASH_RANGE);
        default: return strerror(-errcode);
    }
}

#define BUFSZ_REQ NLMSG_ALIGN(512) /* nfgenmsg */
#define BUFSZ_ACK NLMSG_ALIGN(64) /* nlmsgerr */

static void       *s_buffer4        = (char [BUFSZ_REQ]){0}; /* chnroute */
static void       *s_buffer6        = (char [BUFSZ_REQ]){0}; /* chnroute6 */
static void       *s_ack_buffer     = (char [BUFSZ_ACK]){0};
static uint32_t    s_comlen4        = 0; /* nlh + nfh + proto + setname */
static uint32_t    s_comlen6        = 0; /* nlh + nfh + proto + setname */
static bool        s_dirty4         = false; /* need to commit (ip_add) */
static bool        s_dirty6         = false; /* need to commit (ip_add) */

#define nlmsg(is_ipv4) \
    ((struct nlmsghdr *)((is_ipv4) ? s_buffer4 : s_buffer6))

#define comlen(is_ipv4) \
    ((is_ipv4) ? s_comlen4 : s_comlen6)

#define pcomlen(is_ipv4) \
    ((is_ipv4) ? &s_comlen4 : &s_comlen6)

#define setname(is_ipv4) \
    ((is_ipv4) ? g_ipset_setname4 : g_ipset_setname6)

#define setnamelen(is_ipv4) \
    ((is_ipv4) ? (strlen(g_ipset_setname4) + 1) : (strlen(g_ipset_setname6) + 1))

static void prebuild_nlmsg(bool is_ipv4) {
    /* netlink header */
    struct nlmsghdr *nlmsg = nlmsg_init_hdr(nlmsg(is_ipv4), 0, 0);

    /* netfilter header */
    struct nfgenmsg *nfmsg = nlmsg_add_data(nlmsg, BUFSZ_REQ, NULL, sizeof(*nfmsg));
    nfmsg->nfgen_family = is_ipv4 ? AF_INET : AF_INET6;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    /* protocol */
    nlmsg_add_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_PROTOCOL, &(ubyte){IPSET_PROTOCOL}, sizeof(ubyte));

    /* setname */
    nlmsg_add_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_SETNAME, setname(is_ipv4), setnamelen(is_ipv4));

    *pcomlen(is_ipv4) = nlmsg->nlmsg_len;
}

void ipset_init(void) {
    nl_init();
    prebuild_nlmsg(true);
    prebuild_nlmsg(false);
}

/* nlh | nfh | proto | setname */
#define reset_nlmsg(is_ipv4, cmd, ack) \
    nlmsg_set_hdr(nlmsg(is_ipv4), \
        comlen(is_ipv4), /* msglen */ \
        (NFNL_SUBSYS_IPSET << 8) | (cmd), /* datatype */ \
        NLM_F_REQUEST | ((ack) ? NLM_F_ACK : 0) /* flags */ )

static void add_ip_nla(bool is_ipv4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = nlmsg(is_ipv4);
    struct nlattr *data_nla = nlmsg_add_nest_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_DATA);
    struct nlattr *ip_nla = nlmsg_add_nest_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_IP);
    if (is_ipv4)
        nlmsg_add_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_IPADDR_IPV4|NLA_F_NET_BYTEORDER, ip, IPV4_BINADDR_LEN);
    else
        nlmsg_add_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_IPADDR_IPV6|NLA_F_NET_BYTEORDER, ip, IPV6_BINADDR_LEN);
    nlmsg_end_nest_nla(nlmsg, ip_nla);
    nlmsg_end_nest_nla(nlmsg, data_nla);
}

bool ipset_ip_exists(const void *noalias ip, bool is_ipv4) {
    reset_nlmsg(is_ipv4, IPSET_CMD_TEST, true);
    add_ip_nla(is_ipv4, ip);

    unlikely_if (!nlmsg_send(nlmsg(is_ipv4))) return false;
    unlikely_if (!nlmsg_recv(s_ack_buffer, &(ssize_t){BUFSZ_ACK})) return false;
    int errcode = nlmsg_errcode(s_ack_buffer);

    if (errcode == 0) {
        return true; // exists
    } else if (errcode == IPSET_ERR_EXIST) {
        return false; // not exists
    } else {
        LOGE("error when querying v%c addr: (%d) %s", is_ipv4 ? '4' : '6', errcode, ipset_strerror(errcode));
        return false; // error occurred
    }
}

#define is_dirty(is_ipv4) \
    ((is_ipv4) ? s_dirty4 : s_dirty6)

#define set_dirty(is_ipv4, dirty) \
    (*((is_ipv4) ? &s_dirty4 : &s_dirty6) = (dirty))

#define ip_attr_size(is_ipv4) \
    (NLA_HDRLEN /* data_nla */ + NLA_HDRLEN /* ip_nla */ + \
        NLA_HDRLEN + NLA_ALIGN((is_ipv4) ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN) /* ipattr_nla */ )

#define commit_if_full(is_ipv4) ({ \
    int committed_ = 0; \
    unlikely_if (!nlmsg_space_ok(nlmsg(is_ipv4), BUFSZ_REQ, ip_attr_size(is_ipv4))) { \
        ipset_ip_add_commit(); \
        committed_ = 1; \
    } \
    committed_; \
})

void ipset_ip_add(const void *noalias ip, bool is_ipv4) {
    if (!is_dirty(is_ipv4) || commit_if_full(is_ipv4)) {
        struct nlmsghdr *nlmsg = nlmsg(is_ipv4);
        reset_nlmsg(is_ipv4, IPSET_CMD_ADD, false);
        nlmsg_add_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_LINENO, &(uint32_t){0}, sizeof(uint32_t)); /* dummy lineno */
        nlmsg_add_nest_nla(nlmsg, BUFSZ_REQ, IPSET_ATTR_ADT);
        set_dirty(is_ipv4, true);
    }
    add_ip_nla(is_ipv4, ip);
}

#define lineno_nla_size() \
    (NLA_HDRLEN + NLA_ALIGN(sizeof(uint32_t)))

#define adt_nla(is_ipv4) \
    ((struct nlattr *)((void *)nlmsg(is_ipv4) + comlen(is_ipv4) + lineno_nla_size()))

#define try_commit(is_ipv4) ({ \
    if (is_dirty(is_ipv4)) { \
        nlmsg_end_nest_nla(nlmsg(is_ipv4), adt_nla(is_ipv4)); \
        nlmsg_send(nlmsg(is_ipv4)); \
        set_dirty(is_ipv4, false); \
    } \
})

void ipset_ip_add_commit(void) {
    try_commit(true);
    try_commit(false);
}
