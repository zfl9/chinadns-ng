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
#include <arpa/inet.h>
#include <assert.h>

/* #include <linux/netfilter/nfnetlink.h> */
struct nfgenmsg {
    u8     nfgen_family;   /* AF_xxx */
    u8     version;        /* nfnetlink version */
    u16    res_id;         /* resource id (be) */
};

/* [nft] nfgen_family */
#define NFPROTO_INET 1 /* inet(v4/v6) */
#define NFPROTO_IPV4 2 /* ip */
#define NFPROTO_IPV6 10 /* ip6 */

/* nfgenmsg.version */
#define NFNETLINK_V0 0

/* [ipset] include \0 */
#define IPSET_MAXNAMELEN 32

/* [nft] include \0 */
#define NFT_NAME_MAXLEN 256

/* [nfnl] nlmsg_type */
#define NFNL_MSG_BATCH_BEGIN 16
#define NFNL_MSG_BATCH_END 17

/* [ipset] nlmsg_type (subsys << 8 | cmd) */
#define NFNL_SUBSYS_IPSET 6
#define IPSET_CMD_TEST 11
#define IPSET_CMD_ADD 9

/* [nft] nlmsg_type (subsys << 8 | msg) */
#define NFNL_SUBSYS_NFTABLES 10
#define NFT_MSG_GETSETELEM 13
#define NFT_MSG_NEWSETELEM 12

/* [ipset] nlattr type */
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_LINENO 9
#define IPSET_ATTR_ADT 8 /* {data, ...} */
#define IPSET_ATTR_DATA 7 /* {ip} */
#define IPSET_ATTR_IP 1 /* {ipaddr} */
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

/* [nft] nlattr type */
#define NFTA_SET_ELEM_LIST_TABLE 1
#define NFTA_SET_ELEM_LIST_SET 2
#define NFTA_SET_ELEM_LIST_ELEMENTS 3 /* {list_elem, ...} */
#define NFTA_LIST_ELEM 1 /* {set_elem_*, ...} */
#define NFTA_SET_ELEM_KEY 1 /* {data_value} */
#define NFTA_SET_ELEM_FLAGS 3 /* u32(be) */
#define NFTA_DATA_VALUE 1 /* binary */

/* [ipset] nlattr value */
#define IPSET_PROTOCOL 6

/* [nft] nlattr value */
#define NFT_SET_ELEM_INTERVAL_END 1 /* elem_flags */

/* [ipset] errcode */
#define IPSET_ERR_PROTOCOL 4097
#define IPSET_ERR_FIND_TYPE 4098
#define IPSET_ERR_MAX_SETS 4099
#define IPSET_ERR_BUSY 4100
#define IPSET_ERR_EXIST_SETNAME2 4101
#define IPSET_ERR_TYPE_MISMATCH 4102
#define IPSET_ERR_EXIST 4103
#define IPSET_ERR_INVALID_CIDR 4104
#define IPSET_ERR_INVALID_NETMASK 4105
#define IPSET_ERR_INVALID_FAMILY 4106
#define IPSET_ERR_TIMEOUT 4107
#define IPSET_ERR_REFERENCED 4108
#define IPSET_ERR_IPADDR_IPV4 4109
#define IPSET_ERR_IPADDR_IPV6 4110
#define IPSET_ERR_COUNTER 4111
#define IPSET_ERR_COMMENT 4112
#define IPSET_ERR_INVALID_MARKMASK 4113
#define IPSET_ERR_SKBINFO 4114
#define IPSET_ERR_BITMASK_NETMASK_EXCL 4115
#define IPSET_ERR_HASH_FULL 4352
#define IPSET_ERR_HASH_ELEM 4353
#define IPSET_ERR_INVALID_PROTO 4354
#define IPSET_ERR_MISSING_PROTO 4355
#define IPSET_ERR_HASH_RANGE_UNSUPPORTED 4356
#define IPSET_ERR_HASH_RANGE 4357

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
        default: return strerror(errcode);
    }
}

/* ====================================================== */

/* in single add-request (v4/v6) */
#define IP_N 10

/* ipset: 1+IP_N{v4} + 1+IP_N{v6} | nft: IP_N*5{v4} + IP_N*5{v6} */
#define IOV_N (IP_N * 5 * 2)

/*
  [add-req] ipset: 1+1 | nft: IP_N+IP_N (v4+v6)
  [add-res] ipset: 1+1 | nft: IP_N+IP_N (v4+v6)
*/
#define MSG_N (IP_N * 2)

#define iplen(v4) \
    ((v4) ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN)

#define IPSET_BUFSZ(v4) ( \
    /* test */ \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* nlh + nfh */ + \
    nla_size_calc(sizeof(ubyte)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    nla_size_calc(0) /* data_nla(nested) */ + \
    nla_size_calc(0) /* ip_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* ipaddr_nla */ + \
    /* add */ \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* nlh + nfh */ + \
    nla_size_calc(sizeof(ubyte)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    nla_size_calc(sizeof(u32)) /* lineno_nla */ + \
    nla_size_calc(0) /* adt_nla(nested) */ + \
    IP_N * ( \
        nla_size_calc(0) /* data_nla(nested) */ + \
        nla_size_calc(0) /* ip_nla(nested) */ + \
        nla_size_calc(iplen(v4)) /* ipaddr_nla */ \
    ) \
)

#define NFT_BUFSZ(v4) ( \
    /* test */ \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* nlh + nfh */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* table_name */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* set_name */ + \
    nla_size_calc(0) /* elems_nla(nested) */ + \
    nla_size_calc(0) /* elem_nla(nested) */ + \
    nla_size_calc(0) /* key_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* data_nla(nested) */ + \
    /* add */ \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* batch_begin */ + \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* nlh + nfh */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* table_name */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* set_name */ + \
    nla_size_calc(0) /* elems_nla(nested) */ + \
    nla_size_calc(0) /* elem_nla(nested) */ + \
    nla_size_calc(0) /* key_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* data_nla(nested) */ + \
    nla_size_calc(0) /* elem_nla(nested) */ + \
    nla_size_calc(sizeof(u32)) /* flags_nla */ + \
    nla_size_calc(0) /* key_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* data_nla(nested) */ + \
    NLMSG_SPACE(sizeof(struct nfgenmsg)) /* batch_end */ + \
    IP_N * (iplen(v4)) * 2 /* ip to add [start, end) */ \
)

#define BUFSZ_4 max(IPSET_BUFSZ(true), NFT_BUFSZ(true))
#define BUFSZ_6 max(IPSET_BUFSZ(false), NFT_BUFSZ(false))
#define BUFSZ(v4) ((v4) ? BUFSZ_4 : BUFSZ_6)

#define BUFSZ_R max( \
    NLMSG_SPACE(128), /* [test] ipset: nlmsgerr | nft: newsetelem or nlmsgerr */ \
    NLMSG_SPACE(sizeof(struct nlmsgerr)) * IP_N * 2 /* [add] ipset: 1{v4} + 1{v6} | nft: IP_N{v4} + IP_N{v6} */ \
)

static int s_sock   = -1; /* netlink socket fd */
static u32 s_portid = 0; /* local address (port-id) */

static struct mmsghdr s_msgv[MSG_N];
static struct iovec   s_iov[IOV_N];

static void *s_buf_req4 = (char [BUFSZ_4]){0}; /* ip4 request {test_req, add_req} */
static void *s_buf_req6 = (char [BUFSZ_6]){0}; /* ip6 request {test_req, add_req} */
static void *s_buf_res  = (char [BUFSZ_R]){0}; /* response {test_res or add_res} */

static void *s_test_ip4 = NULL; /* copy the target ip4 to here */
static void *s_test_ip6 = NULL; /* copy the target ip6 to here */

static int s_add_ip4_n    = 0; /* number of ip4 to be added */
static int s_add_ip6_n    = 0; /* number of ip6 to be added */
static u32 s_add_initlen4 = 0; /* ipset: msg | nft: batch_begin,msg,batch_end */
static u32 s_add_initlen6 = 0; /* ipset: msg | nft: batch_begin,msg,batch_end */

static bool (*test_res)(void);
static bool test_res_ipset(void);
static bool test_res_nft(void);

static void (*add_ip)(bool v4, const void *noalias ip);
static void add_ip_ipset(bool v4, const void *noalias ip);
static void add_ip_nft(bool v4, const void *noalias ip);

static int (*end_add_ip)(void);
static int end_add_ip_ipset(void);
static int end_add_ip_nft(void);

/* ======================== helper ======================== */

/* ipset: "set_name"
   nft: "family_name@table_name@set_name" */
#define setname(v4) \
    ((v4) ? g_ipset_name4 : g_ipset_name6)

/* ip-test req */
#define t_nlmsg(v4) \
    cast(struct nlmsghdr *, (v4) ? s_buf_req4 : s_buf_req6)

#define t_bufsz(v4) \
    BUFSZ(v4)

#define t_ipaddr(v4) \
    (*((v4) ? &s_test_ip4 : &s_test_ip6))

/* ip-add req (nft: batch_begin,msg,batch_end) */
#define a_nlmsg(v4) \
    cast(struct nlmsghdr *, (void *)t_nlmsg(v4) + t_nlmsg(v4)->nlmsg_len)

#define a_bufsz(v4) \
    (BUFSZ(v4) - t_nlmsg(v4)->nlmsg_len)

#define a_initlen(v4) \
    (*((v4) ? &s_add_initlen4 : &s_add_initlen6))

#define a_ip_n(v4) \
    (*((v4) ? &s_add_ip4_n : &s_add_ip6_n))

#define init_nlh(nlmsg, bufsz, type) ({ \
    (nlmsg)->nlmsg_len = NLMSG_HDRLEN; \
    (nlmsg)->nlmsg_type = (type); \
    (nlmsg)->nlmsg_flags = NLM_F_REQUEST; \
    (nlmsg)->nlmsg_seq = 0; /* used to track messages */ \
    (nlmsg)->nlmsg_pid = s_portid; \
})

#define init_nfh(nlmsg, bufsz, family, resid) ({ \
    struct nfgenmsg *nfh_ = nlmsg_add_data(nlmsg, bufsz, NULL, sizeof(*nfh_)); \
    nfh_->nfgen_family = (family); \
    nfh_->version = NFNETLINK_V0; \
    nfh_->res_id = htons(resid); \
})

#define add_elem_ipset(nlmsg, bufsz, ip, v4) ({ \
    u16 attrtype_ = (v4) ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6; \
    struct nlattr *data_nla_ = nlmsg_add_nest_nla(nlmsg, bufsz, IPSET_ATTR_DATA); \
    struct nlattr *ip_nla_ = nlmsg_add_nest_nla(nlmsg, bufsz, IPSET_ATTR_IP); \
    struct nlattr *addr_nla_ = nlmsg_add_nla(nlmsg, bufsz, attrtype_|NLA_F_NET_BYTEORDER, ip, iplen(v4)); \
    nlmsg_end_nest_nla(nlmsg, ip_nla_); \
    nlmsg_end_nest_nla(nlmsg, data_nla_); \
    addr_nla_; \
})

#define add_elem_nft(nlmsg, bufsz, ip, v4, flags) ({ \
    struct nlattr *elem_nla_ = nlmsg_add_nest_nla(nlmsg, bufsz, NFTA_LIST_ELEM); \
    if (flags) nlmsg_add_nla(nlmsg, bufsz, NFTA_SET_ELEM_FLAGS, &(u32){htonl(flags)}, sizeof(u32)); \
    struct nlattr *key_nla_ = nlmsg_add_nest_nla(nlmsg, bufsz, NFTA_SET_ELEM_KEY); \
    struct nlattr *data_nla_ = nlmsg_add_nla(nlmsg, bufsz, NFTA_DATA_VALUE|NLA_F_NET_BYTEORDER, ip, iplen(v4)); \
    nlmsg_end_nest_nla(nlmsg, key_nla_); \
    nlmsg_end_nest_nla(nlmsg, elem_nla_); \
    data_nla_; \
})

/* ======================== init ======================== */

static void init_req_ipset(bool v4) {
    const char *name = setname(v4);
    size_t namelen = strlen(name) + 1;
    if (namelen > IPSET_MAXNAMELEN) {
        log_error("name max length is %d: '%s'", IPSET_MAXNAMELEN - 1, name);
        exit(1);
    }

    /* ============ test ============ */

    struct nlmsghdr *nlmsg = t_nlmsg(v4);
    size_t bufsz = t_bufsz(v4);

    /* nlh */
    init_nlh(nlmsg, bufsz, (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST);

    /* nfh */
    init_nfh(nlmsg, bufsz, v4 ? AF_INET : AF_INET6, 0);

    /* protocol */
    nlmsg_add_nla(nlmsg, bufsz, IPSET_ATTR_PROTOCOL, &(ubyte){IPSET_PROTOCOL}, sizeof(ubyte));

    /* setname */
    nlmsg_add_nla(nlmsg, bufsz, IPSET_ATTR_SETNAME, name, namelen);

    u32 len = nlmsg->nlmsg_len;

    /* data { ip { addr } } */
    t_ipaddr(v4) = nla_data(add_elem_ipset(nlmsg, bufsz, NULL, v4));

    /* ============ add ============ */

    nlmsg = memcpy(a_nlmsg(v4), nlmsg, len);
    bufsz = a_bufsz(v4);

    /* nlh */
    nlmsg->nlmsg_len = len;
    nlmsg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;

    /* lineno */
    nlmsg_add_nla(nlmsg, bufsz, IPSET_ATTR_LINENO, &(u32){0}, sizeof(u32));

    /* adt { data, data, ... } */
    nlmsg_add_nest_nla(nlmsg, bufsz, IPSET_ATTR_ADT);

    a_initlen(v4) = nlmsg->nlmsg_len;
}

#define parse_name_nft(v4, start, field, is_last) ({ \
    size_t len_; \
    if (!(is_last)) { \
        const char *end_ = strchr(start, '@'); \
        if (!end_) { \
            log_error("bad format: '%s' (family_name@table_name@set_name)", setname(v4)); \
            exit(1); \
        } \
        len_ = end_ - (start); \
    } else { \
        len_ = strlen(start); \
    } \
    if (len_ < 1) { \
        log_error("%s min length is 1: '%.*s'", #field, (int)len_, start); \
        exit(1); \
    } \
    if (len_ + 1 > sizeof(field)) { \
        log_error("%s max length is %zu: '%.*s'", #field, sizeof(field) - 1, (int)len_, start); \
        exit(1); \
    } \
    memcpy(field, start, len_); \
    (field)[len_] = 0; \
    (start) += len_ + 1; \
})

static void init_req_nft(bool v4) {
    char family_name[sizeof("inet")]; /* ip | ip6 | inet */
    char table_name[NFT_NAME_MAXLEN];
    char set_name[NFT_NAME_MAXLEN];

    const char *start = setname(v4);
    parse_name_nft(v4, start, family_name, false);
    parse_name_nft(v4, start, table_name, false);
    parse_name_nft(v4, start, set_name, true); /* last field */

    u8 family;
    if (strcmp(family_name, "ip") == 0)
        family = NFPROTO_IPV4;
    else if (strcmp(family_name, "ip6") == 0)   
        family = NFPROTO_IPV6;
    else if (strcmp(family_name, "inet") == 0)
        family = NFPROTO_INET;
    else {
        log_error("invalid family: '%s' (ip | ip6 | inet)", family_name);
        exit(1);
    }

    /* ============ test ============ */

    struct nlmsghdr *nlmsg = t_nlmsg(v4);
    size_t bufsz = t_bufsz(v4);

    /* nlh */
    init_nlh(nlmsg, bufsz, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM);

    /* nfh */
    init_nfh(nlmsg, bufsz, family, 0);

    /* table_name */
    nlmsg_add_nla(nlmsg, bufsz, NFTA_SET_ELEM_LIST_TABLE, table_name, strlen(table_name) + 1);

    /* set_name */
    nlmsg_add_nla(nlmsg, bufsz, NFTA_SET_ELEM_LIST_SET, set_name, strlen(set_name) + 1);

    u32 len = nlmsg->nlmsg_len;

    /* elements {elem, elem, ...} */
    struct nlattr *elems_nla = nlmsg_add_nest_nla(nlmsg, bufsz, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* elem */
    t_ipaddr(v4) = nla_data(add_elem_nft(nlmsg, bufsz, NULL, v4, 0));

    /* elements end */
    nlmsg_end_nest_nla(nlmsg, elems_nla);

    /* ============ add ============ */

    nlmsg = a_nlmsg(v4);
    bufsz = a_bufsz(v4);

    /* batch_begin (transaction begin) */
    init_nlh(nlmsg, bufsz, NFNL_MSG_BATCH_BEGIN);
    init_nfh(nlmsg, bufsz, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);

    a_initlen(v4) += nlmsg->nlmsg_len;
    bufsz -= nlmsg->nlmsg_len;

    /* nlh */
    nlmsg = memcpy(nlmsg_dataend(nlmsg), t_nlmsg(v4), len);
    nlmsg->nlmsg_len = len;
    nlmsg->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;

    /* elements {elem, elem, ...} */
    elems_nla = nlmsg_add_nest_nla(nlmsg, bufsz, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* elem [start, end) */
    add_elem_nft(nlmsg, bufsz, NULL, v4, 0);
    add_elem_nft(nlmsg, bufsz, NULL, v4, NFT_SET_ELEM_INTERVAL_END);

    /* elements end */
    nlmsg_end_nest_nla(nlmsg, elems_nla);

    a_initlen(v4) += nlmsg->nlmsg_len;
    bufsz -= nlmsg->nlmsg_len;

    /* batch_end (transaction end) */
    nlmsg = nlmsg_dataend(nlmsg);
    init_nlh(nlmsg, bufsz, NFNL_MSG_BATCH_END);
    init_nfh(nlmsg, bufsz, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);

    a_initlen(v4) += nlmsg->nlmsg_len;
    bufsz -= nlmsg->nlmsg_len;
}

void ipset_init(void) {
    /*
      for the netfilter module, req_nlmsg is always processed synchronously in the context of the sendmsg system call,
        and the res_nlmsg is placed in the sender's receive queue before sendmsg returns.
    */
    s_sock = nl_sock_create(NETLINK_NETFILTER, &s_portid);

    if (!strchr(g_ipset_name4, '@') && !strchr(g_ipset_name6, '@')) {
        log_info("ipset for ipv4: %s", g_ipset_name4);
        log_info("ipset for ipv6: %s", g_ipset_name6);
        if (g_add_tagchn_ip) log_info("add ip of tag:chn to ipset");
        test_res = test_res_ipset;
        add_ip = add_ip_ipset;
        end_add_ip = end_add_ip_ipset;
        init_req_ipset(true);
        init_req_ipset(false);
    } else {
        log_info("nftset for ipv4: %s", g_ipset_name4);
        log_info("nftset for ipv6: %s", g_ipset_name6);
        if (g_add_tagchn_ip) log_info("add ip of tag:chn to nftset");
        test_res = test_res_nft;
        add_ip = add_ip_nft;
        end_add_ip = end_add_ip_nft;
        init_req_nft(true);
        init_req_nft(false);
    }
}

/* ======================== test-ip ======================== */

#define send_req(n_msg) ({ \
    assert((n_msg) != 0); \
    int n_sent_ = sendall(sendmmsg, s_sock, s_msgv, n_msg, 0); \
    assert(n_sent_ != 0); \
    unlikely_if (n_sent_ != (n_msg)) \
        log_error("failed to send nlmsg: %d != %d, (%d) %s", n_sent_, (int)(n_msg), errno, strerror(errno)); \
    n_sent_; \
})

/* return 0 if no-msg */
#define recv_res(n_msg, err_if_nomsg) ({ \
    assert((n_msg) != 0); \
    int n_recv_ = recvmmsg(s_sock, s_msgv, n_msg, MSG_DONTWAIT, NULL); \
    assert(n_recv_ != 0); \
    if (n_recv_ < 0) { /* no-msg or error */ \
        if (errno == EAGAIN || errno == EWOULDBLOCK) n_recv_ = 0; \
        unlikely_if ((err_if_nomsg) || n_recv_ < 0) \
            log_error("failed to recv nlmsg: (%d) %s", errno, strerror(errno)); \
    } \
    n_recv_; \
})

static bool test_res_ipset(void) {
    const struct nlmsghdr *nlmsg = s_buf_res;
    int errcode = nlmsg_errcode(nlmsg);
    assert(errcode);
    if (errcode != IPSET_ERR_EXIST)
        log_error("error when querying ip: (%d) %s", errcode, ipset_strerror(errcode));
    return false;
}

static bool test_res_nft(void) {
    const struct nlmsghdr *nlmsg = s_buf_res;
    if (nlmsg->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM))
        return true;
    int errcode = nlmsg_errcode(nlmsg);
    assert(errcode);
    if (errcode != ENOENT) /* ENOENT: table not exists; set not exists; elem not exists */
        log_error("error when querying ip: (%d) %s", errcode, strerror(errcode));
    return false;
}

bool ipset_test_ip(const void *noalias ip, bool v4) {
    memcpy(t_ipaddr(v4), ip, iplen(v4));

    /* send request */
    struct nlmsghdr *nlmsg = t_nlmsg(v4);
    simple_msghdr(&s_msgv[0].msg_hdr, &s_iov[0], nlmsg, nlmsg->nlmsg_len);
    unlikely_if (send_req(1) < 0) return false; /* send failed */

    /* recv response */
    simple_msghdr(&s_msgv[0].msg_hdr, &s_iov[0], s_buf_res, BUFSZ_R);
    switch (recv_res(1, false)) {
        case 0: /* no msg */
            return true;
        case 1:
            return test_res();
        default: /* error occurs */
            return false;
    }
}

/* ======================== add-ip ======================== */

static void add_ip_ipset(bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = a_nlmsg(v4);
    if (!a_ip_n(v4)) nlmsg->nlmsg_len = a_initlen(v4);
    size_t bufsz = a_bufsz(v4);
    add_elem_ipset(nlmsg, bufsz, ip, v4);
}

static void add_ip_nft(bool v4, const void *noalias ip) {
    int len = iplen(v4);
    void *start = (void *)a_nlmsg(v4) + a_initlen(v4) + a_ip_n(v4) * len * 2;
    ubyte *end = start + len;

    memcpy(start, ip, len);
    memcpy(end, ip, len);

    /* [start, end) */
    for (int i = len - 1; i >= 0; --i) {
        ubyte old = end[i];
        if (++end[i] > old) break;
    }
}

void ipset_add_ip(const void *noalias ip, bool v4) {
    if (a_ip_n(v4) >= IP_N) ipset_end_add_ip();
    add_ip(v4, ip);
    ++a_ip_n(v4); /* must be after `add_ip` */
}

/* ======================== end-add-ip ======================== */

#define init_nlerr_msgv(n) ({ \
    size_t sz_ = NLMSG_SPACE(sizeof(struct nlmsgerr)); \
    for (__typeof__(n) i_ = 0; i_ < (n); ++i_) \
        simple_msghdr(&s_msgv[i_].msg_hdr, &s_iov[i_], s_buf_res + sz_ * i_, sz_); \
})

/* zero `exists` before calling */
static void test_ips(bitvec_t exists[noalias],
                     void (*next_ip)(bool v4, void **noalias p),
                     bool (*test_ip)(const struct nlmsghdr *noalias nlmsg))
{
    int n_msg = 0;

    /* fill ip-test msg */
    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(v4);
        if (ipn <= 0) continue;

        void *base1 = NULL;
        size_t len1 = iplen(v4);

        struct nlmsghdr *base0 = t_nlmsg(v4);
        size_t len0 = base0->nlmsg_len - len1; /* iplen is aligned(4) */

        for (int ipi = 0; ipi < ipn; ++ipi) {
            int i = n_msg++;
            next_ip(v4, &base1);
            s_iov[i*2].iov_base = base0;
            s_iov[i*2].iov_len = len0;
            s_iov[i*2+1].iov_base = base1;
            s_iov[i*2+1].iov_len = len1;
            simple_msghdr_iov(&s_msgv[i].msg_hdr, &s_iov[i*2], 2);
        }
    }

    if (n_msg <= 0) return;

    unlikely_if ((n_msg = send_req(n_msg)) < 0) return; /* all failed */

    init_nlerr_msgv(n_msg);
    unlikely_if ((n_msg = recv_res(n_msg, true)) <= 0) return;

    /* save result to bit-vector */
    for (int i = 0; i < n_msg; ++i) {
        if (test_ip(s_iov[i].iov_base))
            bitvec_set1(exists, i);
    }
}

static void next_ip_ipset(bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_nlmsg(v4) + a_initlen(v4) + NLA_HDRLEN * 3;
    else
        *p += iplen(v4) /* aligned(4) */ + NLA_HDRLEN * 3;
}

static bool test_ip_ipset(const struct nlmsghdr *noalias nlmsg) {
    return nlmsg_errcode(nlmsg) == 0;
}

static int end_add_ip_ipset(void) {
    int n_msg = 0;

    /* set ack flag */
    t_nlmsg(true)->nlmsg_flags |= NLM_F_ACK;
    t_nlmsg(false)->nlmsg_flags |= NLM_F_ACK;

    bitvec_t exists[bitvec_n(IP_N * 2)] = {0};
    test_ips(exists, next_ip_ipset, test_ip_ipset);

    /* remove ack flag */
    t_nlmsg(true)->nlmsg_flags &= ~NLM_F_ACK;
    t_nlmsg(false)->nlmsg_flags &= ~NLM_F_ACK;

    int iov_i = 0;

    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(v4);
        if (ipn <= 0) continue;

        struct nlmsghdr *nlmsg = a_nlmsg(v4);
        nlmsg->nlmsg_len = a_initlen(v4);

        void *elem = nlmsg_dataend(nlmsg);
        size_t elemsz = NLA_HDRLEN * 3 + iplen(v4) /* aligned(4) */;

        int add_n = 0;

        s_iov[iov_i].iov_base = nlmsg;
        s_iov[iov_i].iov_len = nlmsg->nlmsg_len;
        ++iov_i;

        for (int ipi = 0; ipi < ipn; ++ipi, elem += elemsz) {
            if (!bitvec_get(exists, ipi)) {
                s_iov[iov_i].iov_base = elem;
                s_iov[iov_i].iov_len = elemsz;
                ++iov_i;
                ++add_n;
            }
        }

        if (add_n <= 0) {
            --iov_i;
            continue;
        }

        struct nlattr *adt_nla = nlmsg_dataend(nlmsg) - NLA_HDRLEN;
        adt_nla->nla_len = nla_len_calc(add_n * elemsz);
        nlmsg->nlmsg_len += add_n * elemsz;

        int i = n_msg++;
        simple_msghdr_iov(&s_msgv[i].msg_hdr, &s_iov[iov_i - add_n - 1], 1 + add_n);
    }

    return n_msg;
}

static void next_ip_nft(bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_nlmsg(v4) + a_initlen(v4);
    else
        *p += iplen(v4) * 2;
}

static bool test_ip_nft(const struct nlmsghdr *noalias nlmsg) {
    return nlmsg->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM);
}

static int end_add_ip_nft(void) {
    int n_msg = 0;

    bitvec_t exists[bitvec_n(IP_N * 2)] = {0};
    test_ips(exists, next_ip_nft, test_ip_nft);

    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(v4);
        if (ipn <= 0) continue;

        /* batch_begin|msg|batch_end */
        void *nlmsg = a_nlmsg(v4);
        u32 initlen = a_initlen(v4);

        void *basev[5];
        size_t lenv[5];
        int iplen = iplen(v4);

        /* batch_end */
        lenv[4] = NLMSG_SPACE(sizeof(struct nfgenmsg));
        basev[4] = nlmsg + initlen - lenv[4];

        /* ip_end */
        lenv[3] = iplen;
        basev[3] = nlmsg + initlen + iplen; /* step:2 */

        /* elem2_nla */
        lenv[2] = NLA_HDRLEN /* elem_h */ + nla_size_calc(sizeof(u32)) /* flags */ + NLA_HDRLEN /* key_h */ + NLA_HDRLEN /* data_h */;
        basev[2] = basev[4] - lenv[3] - lenv[2];

        /* ip_start */
        lenv[1] = iplen;
        basev[1] = nlmsg + initlen; /* step:2 */

        /* batch_begin... */
        lenv[0] = initlen - lenv[4] - lenv[3] - lenv[2] - lenv[1];
        basev[0] = nlmsg;

        for (int ipi = 0; ipi < ipn; ++ipi) {
            if (!bitvec_get(exists, ipi)) {
                int i = n_msg++;
                for (int j = 0; j < (int)array_n(basev); ++j) {
                    s_iov[i*5+j].iov_base = basev[j];
                    s_iov[i*5+j].iov_len = lenv[j];
                }
                simple_msghdr_iov(&s_msgv[i].msg_hdr, &s_iov[i*5], 5);
            }
            basev[1] += iplen + iplen;
            basev[3] += iplen + iplen;
        }
    }

    return n_msg;
}

void ipset_end_add_ip(void) {
    /*
      current dns servers do not carry both A and AAAA answers, but they may in the future.
      see: https://datatracker.ietf.org/doc/html/draft-vavrusa-dnsop-aaaa-for-free-00
    */

    if (a_ip_n(true) + a_ip_n(false) <= 0) return;

    int n_msg = end_add_ip();

    /* reset to 0 */
    a_ip_n(true) = 0;
    a_ip_n(false) = 0;

    if (n_msg <= 0) return;

    unlikely_if ((n_msg = send_req(n_msg)) < 0) return; /* all failed */

    /* recv nlmsgerr */
    init_nlerr_msgv(n_msg);
    likely_if ((n_msg = recv_res(n_msg, false)) == 0) return; /* no msg */

    for (int i = 0; i < n_msg; ++i) {
        const struct nlmsghdr *nlmsg = s_iov[i].iov_base;
        int errcode = nlmsg_errcode(nlmsg);
        log_error("error when adding ip: (%d) %s", errcode, ipset_strerror(errcode));
    }
}
