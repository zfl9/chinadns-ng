#define _GNU_SOURCE
#include "ipset.h"
#include "opt.h"
#include "net.h"
#include "log.h"
#include "dnl.h"
#include "nl.h"
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

struct nlnfhdr {
    struct nlmsghdr nlh struct_alignto(NLMSG_ALIGNTO);
    struct nfgenmsg nfh struct_alignto(NLMSG_ALIGNTO);
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

/* "set_name" | "family_name@table_name@set_name" (include \0) */
#define NAME_MAXLEN \
    ((int)sizeof("inet") + NFT_NAME_MAXLEN + NFT_NAME_MAXLEN)

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
#define IPSET_ATTR_PROTOCOL 1 /* u8 */
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_LINENO 9 /* u32 */
#define IPSET_ATTR_ADT 8 /* {data, ...} */
#define IPSET_ATTR_DATA 7 /* {ip} */
#define IPSET_ATTR_IP 1 /* {ipaddr} */
#define IPSET_ATTR_IPADDR_IPV4 1 /* u32(be) 4byte */
#define IPSET_ATTR_IPADDR_IPV6 2 /* u128(be) 16byte */

/* [nft] nlattr type */
#define NFTA_SET_ELEM_LIST_TABLE 1 /* table_name */
#define NFTA_SET_ELEM_LIST_SET 2 /* set_name */
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
/* type specific error codes (hash) */
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
        CASE_RET_NAME(IPSET_ERR_TIMEOUT);
        CASE_RET_NAME(IPSET_ERR_REFERENCED);
        CASE_RET_NAME(IPSET_ERR_IPADDR_IPV4);
        CASE_RET_NAME(IPSET_ERR_IPADDR_IPV6);
        CASE_RET_NAME(IPSET_ERR_COUNTER);
        CASE_RET_NAME(IPSET_ERR_COMMENT);
        CASE_RET_NAME(IPSET_ERR_INVALID_MARKMASK);
        CASE_RET_NAME(IPSET_ERR_SKBINFO);
        CASE_RET_NAME(IPSET_ERR_BITMASK_NETMASK_EXCL);
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

/* in single add-request (v4 or v6) */
#define IP_N 10

/* [add] [test_ips #req] ipset: IP_N*2  | nft: IP_N*2
   [add] [test_ips #res] ipset: IP_N    | nft: IP_N
   [add] [add_ips  #req] ipset: 1+IP_N  | nft: 2+IP_N+1
   [add] [add_ips  #res] ipset: 1       | nft: 1        */
#define IOV_N (max(IP_N*2, 2+IP_N+1) * 2) /* v4 + v6 */

/* [add] v4 + v6 */
#define MSG_N (IP_N * 2)

#define iplen(v4) \
    ((v4) ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN)

#define BUFSZ_TEST_IPSET(v4) ( \
    sizeof(struct nlnfhdr) + \
    nla_size_calc(sizeof(u8)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    NLA_HDRLEN /* data_nla(nested) */ + \
    NLA_HDRLEN /* ip_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* addr_nla */ \
)

#define BUFSZ_ADD_IPSET(v4) ( \
    sizeof(struct nlnfhdr) + \
    nla_size_calc(sizeof(u8)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    nla_size_calc(sizeof(u32)) /* lineno_nla */ + \
    NLA_HDRLEN /* adt_nla(nested) */ + \
    IP_N * ( \
        NLA_HDRLEN /* data_nla(nested) */ + \
        NLA_HDRLEN /* ip_nla(nested) */ + \
        nla_size_calc(iplen(v4)) /* addr_nla */ \
    ) \
)

#define BUFSZ_TEST_NFT(v4) ( \
    sizeof(struct nlnfhdr) + \
    nla_size_calc(NFT_NAME_MAXLEN) /* table_name */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* set_name */ + \
    NLA_HDRLEN /* elems_nla(nested) */ + \
    NLA_HDRLEN /* elem_nla(nested) */ + \
    NLA_HDRLEN /* key_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* data_nla */ \
)

#define BUFSZ_ADD_NFT(v4) ( \
    sizeof(struct nlnfhdr) + \
    nla_size_calc(NFT_NAME_MAXLEN) /* table_name */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* set_name */ + \
    NLA_HDRLEN /* elems_nla(nested) */ + \
    IP_N * ( \
        /* interval begin */ \
        NLA_HDRLEN /* elem_nla(nested) */ + \
        NLA_HDRLEN /* key_nla(nested) */ + \
        nla_size_calc(iplen(v4)) /* data_nla */ + \
        /* interval end */ \
        NLA_HDRLEN /* elem_nla(nested) */ + \
        nla_size_calc(sizeof(u32)) /* flags_nla */ + \
        NLA_HDRLEN /* key_nla(nested) */ + \
        nla_size_calc(iplen(v4)) /* data_nla */ \
    ) \
)

#define BUFSZ_TEST(v4) \
    max(BUFSZ_TEST_IPSET(v4), BUFSZ_TEST_NFT(v4))

#define BUFSZ_ADD(v4) \
    max(BUFSZ_ADD_IPSET(v4), BUFSZ_ADD_NFT(v4))

/* none_test, chn_test,chn_add, gfw_test,gfw_add */
#define BUFSZ_4 \
    (BUFSZ_TEST(true) + (BUFSZ_TEST(true) + BUFSZ_ADD(true)) * 2)

/* none_test, chn_test,chn_add, gfw_test,gfw_add */
#define BUFSZ_6 \
    (BUFSZ_TEST(false) + (BUFSZ_TEST(false) + BUFSZ_ADD(false)) * 2)

/* [add test_ips] v4 + v6 */
#define BUFSZ_R \
    (NLMSG_SPACE(sizeof(struct nlmsgerr)) * IP_N * 2)

/* offset of chn{test,add} */
#define OFFSET_CHN(v4) \
    BUFSZ_TEST(v4)

/* offset of gfw{test,add} */
#define OFFSET_GFW(v4) \
    (BUFSZ_TEST(v4) + BUFSZ_TEST(v4) + BUFSZ_ADD(v4))

static int s_sock   = -1; /* netlink socket fd */
static u32 s_portid = 0; /* local address (port-id) */

static struct mmsghdr s_msgv[MSG_N];
static struct iovec   s_iov[IOV_N];

/* for nft [add] */
static struct nlnfhdr s_batch_begin;
static struct nlnfhdr s_batch_end;

static void *s_buf_req4 = (char [BUFSZ_4]){0}; /* tag:none{test} + tag:chn{test,add} + tag:gfw{test,add} */
static void *s_buf_req6 = (char [BUFSZ_6]){0}; /* tag:none{test} + tag:chn{test,add} + tag:gfw{test,add} */
static void *s_buf_res  = (char [BUFSZ_R]){0};

/* tag:none */
static void *s_test_ip4 = NULL; /* copy the target ip4 to here */
static void *s_test_ip6 = NULL; /* copy the target ip6 to here */

struct addctx {
    struct nlmsghdr *nlmsg4; /* nlmsg {test,add} */
    struct nlmsghdr *nlmsg6; /* nlmsg {test,add} */
    u32 initlen4; /* initial length of add_msg (ip_n:0) */
    u32 initlen6; /* initial length of add_msg (ip_n:0) */
    int ip4_n; /* number of ip in queue */
    int ip6_n; /* number of ip in queue */
};
static struct addctx s_chn_addctx; /* tag:chn */
static struct addctx s_gfw_addctx; /* tag:gfw */

static bool (*test_res)(const struct nlmsghdr *noalias nlmsg);
static bool test_res_ipset(const struct nlmsghdr *noalias nlmsg);
static bool test_res_nft(const struct nlmsghdr *noalias nlmsg);

static void (*add_ip)(const struct addctx *noalias ctx, bool v4, const void *noalias ip);
static void add_ip_ipset(const struct addctx *noalias ctx, bool v4, const void *noalias ip);
static void add_ip_nft(const struct addctx *noalias ctx, bool v4, const void *noalias ip);

static int (*end_add_ip)(const struct addctx *noalias ctx);
static int end_add_ip_ipset(const struct addctx *noalias ctx);
static int end_add_ip_nft(const struct addctx *noalias ctx);

/* ======================== helper ======================== */

/* tag:none test */
#define t_nlmsg(v4) \
    cast(struct nlmsghdr *, (v4) ? s_buf_req4 : s_buf_req6)

/* tag:none test */
#define t_ipaddr(v4) \
    (*((v4) ? &s_test_ip4 : &s_test_ip6))

/* tag:chn/gfw add */
#define a_ctx(chn) \
    ((chn) ? &s_chn_addctx : &s_gfw_addctx)

/* tag:chn/gfw add */
#define a_testmsg(ctx, v4) \
    (*((v4) ? &(ctx)->nlmsg4 : &(ctx)->nlmsg6))

/* tag:chn/gfw add */
#define a_addmsg(ctx, v4) \
    cast(struct nlmsghdr *, (void *)a_testmsg(ctx, v4) + BUFSZ_TEST(v4))

/* tag:chn/gfw add */
#define a_initlen(ctx, v4) \
    (*((v4) ? &(ctx)->initlen4 : &(ctx)->initlen6))

/* tag:chn/gfw add */
#define a_ip_n(ctx, v4) \
    (*((v4) ? &(ctx)->ip4_n : &(ctx)->ip6_n))

#define init_nlnfhdr(nlmsg, nlh_type, nlh_flags, nfh_family, nfh_res_id) ({ \
    struct nlnfhdr *h_ = (struct nlnfhdr *)(nlmsg); \
    h_->nlh.nlmsg_len = sizeof(struct nlnfhdr); \
    h_->nlh.nlmsg_type = (nlh_type); \
    h_->nlh.nlmsg_flags = (nlh_flags); \
    h_->nlh.nlmsg_seq = 0; /* used to track messages */ \
    h_->nlh.nlmsg_pid = s_portid; \
    h_->nfh.nfgen_family = (nfh_family); \
    h_->nfh.version = NFNETLINK_V0; \
    h_->nfh.res_id = htons(nfh_res_id); \
})

#define add_elem_ipset(nlmsg, ip, v4) ({ \
    u16 attrtype_ = (v4) ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6; \
    struct nlattr *data_nla_ = nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_DATA); \
    struct nlattr *ip_nla_ = nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_IP); \
    struct nlattr *addr_nla_ = nlmsg_add_nla(nlmsg, attrtype_|NLA_F_NET_BYTEORDER, ip, iplen(v4)); \
    nlmsg_end_nest_nla(nlmsg, ip_nla_); \
    nlmsg_end_nest_nla(nlmsg, data_nla_); \
    addr_nla_; \
})

#define add_elem_nft(nlmsg, ip, v4, flags) ({ \
    struct nlattr *elem_nla_ = nlmsg_add_nest_nla(nlmsg, NFTA_LIST_ELEM); \
    if (flags) nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_FLAGS, &(u32){htonl(flags)}, sizeof(u32)); \
    struct nlattr *key_nla_ = nlmsg_add_nest_nla(nlmsg, NFTA_SET_ELEM_KEY); \
    struct nlattr *data_nla_ = nlmsg_add_nla(nlmsg, NFTA_DATA_VALUE|NLA_F_NET_BYTEORDER, ip, iplen(v4)); \
    nlmsg_end_nest_nla(nlmsg, key_nla_); \
    nlmsg_end_nest_nla(nlmsg, elem_nla_); \
    data_nla_; \
})

/* ======================== init ======================== */

static void init_req_ipset(bool v4, const char *noalias name, struct addctx *noalias ctx) {
    size_t namelen = strlen(name) + 1;
    if (namelen > IPSET_MAXNAMELEN) {
        log_error("name max length is %d: '%s'", IPSET_MAXNAMELEN - 1, name);
        exit(1);
    }

    /* ================= test-msg ================= */

    struct nlmsghdr *nlmsg = !ctx ? t_nlmsg(v4) : a_testmsg(ctx, v4);

    /* nlh + nfh */
    init_nlnfhdr(nlmsg, (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST, NLM_F_REQUEST, v4 ? AF_INET : AF_INET6, 0);

    /* protocol */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_PROTOCOL, &(u8){IPSET_PROTOCOL}, sizeof(u8));

    /* setname */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_SETNAME, name, namelen);

    u32 len = nlmsg->nlmsg_len;

    /* data { ip { addr } } */
    struct nlattr *ip_nla = add_elem_ipset(nlmsg, NULL, v4);

    if (!ctx) {
        t_ipaddr(v4) = nla_data(ip_nla);
    } else {
        /* add ack flags (test_ips) */
        nlmsg->nlmsg_flags |= NLM_F_ACK;

        /* ================= add-msg ================= */

        nlmsg = memcpy(a_addmsg(ctx, v4), nlmsg, len);
        nlmsg->nlmsg_len = len;
        nlmsg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
        nlmsg->nlmsg_flags &= ~NLM_F_ACK; /* remove ack flags */

        /* lineno */
        nlmsg_add_nla(nlmsg, IPSET_ATTR_LINENO, &(u32){0}, sizeof(u32));

        /* adt { data, data, ... } */
        nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_ADT);

        a_initlen(ctx, v4) = nlmsg->nlmsg_len;
    }
}

#define parse_name_nft(name, start, field, is_last) ({ \
    size_t len_; \
    if (!(is_last)) { \
        const char *end_ = strchr(start, '@'); \
        if (!end_) { \
            log_error("bad format: '%s' (family_name@table_name@set_name)", name); \
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

static void init_req_nft(bool v4, const char *noalias name, struct addctx *noalias ctx) {
    char family_name[sizeof("inet")]; /* ip | ip6 | inet */
    char table_name[NFT_NAME_MAXLEN];
    char set_name[NFT_NAME_MAXLEN];

    const char *start = name;
    parse_name_nft(name, start, family_name, false);
    parse_name_nft(name, start, table_name, false);
    parse_name_nft(name, start, set_name, true); /* last field */

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

    /* ================= test-msg ================= */

    struct nlmsghdr *nlmsg = !ctx ? t_nlmsg(v4) : a_testmsg(ctx, v4);

    /* nlh + nfh */
    init_nlnfhdr(nlmsg, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM, NLM_F_REQUEST, family, 0);

    /* table_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_TABLE, table_name, strlen(table_name) + 1);

    /* set_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_SET, set_name, strlen(set_name) + 1);

    /* elements {elem, elem, ...} */
    struct nlattr *elems_nla = nlmsg_add_nest_nla(nlmsg, NFTA_SET_ELEM_LIST_ELEMENTS);

    u32 len = nlmsg->nlmsg_len;

    /* elem */
    struct nlattr *ip_nla = add_elem_nft(nlmsg, NULL, v4, 0);

    /* elements end */
    nlmsg_end_nest_nla(nlmsg, elems_nla);

    if (!ctx) {
        t_ipaddr(v4) = nla_data(ip_nla);
    } else {
        /* ================= add-msg ================= */

        nlmsg = memcpy(a_addmsg(ctx, v4), nlmsg, len);
        nlmsg->nlmsg_len = len;
        nlmsg->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;

        a_initlen(ctx, v4) = nlmsg->nlmsg_len;
    }
}

/* name4,name6 */
static void parse_name46(const char *noalias input, char name4[noalias], char name6[noalias]) {
    const char *d = strchr(input, ',');
    if (!d) {
        log_error("bad format: '%s' (setname4,setname6)", input);
        exit(1);
    }

    const char *p = input;
    int len = d - p;
    if (len > NAME_MAXLEN - 1) goto err;

    memcpy(name4, p, len);
    name4[len] = 0;

    p = d + 1;
    len = strlen(p);
    if (len > NAME_MAXLEN - 1) goto err;

    memcpy(name6, p, len);
    name6[len] = 0;

    return;

err:
    log_error("name max length is %d: '%.*s'", NAME_MAXLEN - 1, len, p);
    exit(1);
}

void ipset_init(void) {
    /*
      for the netfilter module, req_nlmsg is always processed synchronously in the context of the sendmsg system call,
        and the res_nlmsg is placed in the sender's receive queue before sendmsg returns.
    */
    s_sock = nl_sock_create(NETLINK_NETFILTER, &s_portid);

    __typeof__(&init_req_ipset) init_req;

    if (strchr(g_ipset_name4, '@') || strchr(g_ipset_name6, '@') ||
        strchr(g_add_tagchn_ip ?: "", '@') || strchr(g_add_taggfw_ip ?: "", '@'))
    {
        log_info("current backend: nft");
        init_req = init_req_nft;
        test_res = test_res_nft;
        add_ip = add_ip_nft;
        end_add_ip = end_add_ip_nft;
        /* batch_begin/batch_end */
        init_nlnfhdr(&s_batch_begin, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        init_nlnfhdr(&s_batch_end, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
    } else {
        log_info("current backend: ipset");
        init_req = init_req_ipset;
        test_res = test_res_ipset;
        add_ip = add_ip_ipset;
        end_add_ip = end_add_ip_ipset;
    }

    /* tag:chn add */
    if (g_add_tagchn_ip) {
        char name4[NAME_MAXLEN], name6[NAME_MAXLEN];
        parse_name46(g_add_tagchn_ip, name4, name6);
        log_info("tag:chn add: %s", name4);
        log_info("tag:chn add: %s", name6);
        struct addctx *noalias ctx = a_ctx(true);
        a_testmsg(ctx, true) = (void *)t_nlmsg(true) + OFFSET_CHN(true);
        a_testmsg(ctx, false) = (void *)t_nlmsg(false) + OFFSET_CHN(false);
        init_req(true, name4, ctx);
        init_req(false, name6, ctx);
    }

    /* tag:gfw add */
    if (g_add_taggfw_ip) {
        char name4[NAME_MAXLEN], name6[NAME_MAXLEN];
        parse_name46(g_add_taggfw_ip, name4, name6);
        log_info("tag:gfw add: %s", name4);
        log_info("tag:gfw add: %s", name6);
        struct addctx *noalias ctx = a_ctx(false);
        a_testmsg(ctx, true) = (void *)t_nlmsg(true) + OFFSET_GFW(true);
        a_testmsg(ctx, false) = (void *)t_nlmsg(false) + OFFSET_GFW(false);
        init_req(true, name4, ctx);
        init_req(false, name6, ctx);
    }

    /* tag:none test */
    if (g_default_tag == NAME_TAG_NONE) {
        log_info("tag:none test: %s", g_ipset_name4);
        log_info("tag:none test: %s", g_ipset_name6);
        init_req(true, g_ipset_name4, NULL);
        init_req(false, g_ipset_name6, NULL);
    }
}

/* ======================== test-ip ======================== */

/* res<0: error || res>0: n_sent */
static inline int send_req(int n_msg) {
    assert(n_msg > 0);
    assert(n_msg <= MSG_N);
    int n_sent = sendall(x_sendmmsg, s_sock, s_msgv, n_msg, 0);
    assert(n_sent != 0);
    unlikely_if (n_sent != n_msg)
        log_error("failed to send nlmsg: %d != %d, (%d) %s", n_sent, n_msg, errno, strerror(errno));
    return n_sent;
}

/* res<0: error || res=0: no-msg || res>0: n_recv */
static inline int recv_res(int n_msg, bool err_if_nomsg) {
    assert(n_msg > 0);
    assert(n_msg <= MSG_N);
    int n_recv = x_recvmmsg(s_sock, s_msgv, n_msg, MSG_DONTWAIT, NULL);
    assert(n_recv != 0);
    if (n_recv < 0) { /* no-msg or error */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            n_recv = 0;
        unlikely_if (err_if_nomsg || n_recv < 0)
            log_error("failed to recv nlmsg: (%d) %s", errno, strerror(errno));
    }
    return n_recv;
}

static bool test_res_ipset(const struct nlmsghdr *noalias nlmsg) {
    int errcode = nlmsg_errcode(nlmsg);
    switch (errcode) {
        case 0:
            return true;
        case IPSET_ERR_EXIST:
            return false;
        default:
            log_warning("error when querying ip: (%d) %s", errcode, ipset_strerror(errcode));
            return false;
    }
}

static bool test_res_nft(const struct nlmsghdr *noalias nlmsg) {
    if (nlmsg->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM))
        return true;
    int errcode = nlmsg_errcode(nlmsg);
    unlikely_if (errcode != ENOENT) /* ENOENT: table not exists; set not exists; elem not exists */
        log_warning("error when querying ip: (%d) %s", errcode, strerror(errcode));
    return false;
}

bool ipset_test_ip(const void *noalias ip, bool v4) {
    memcpy(t_ipaddr(v4), ip, iplen(v4));

    /* send request */
    set_iov(&s_iov[0], t_nlmsg(v4), t_nlmsg(v4)->nlmsg_len);
    set_msghdr(&s_msgv[0].msg_hdr, &s_iov[0], 1, NULL, 0);
    unlikely_if (send_req(1) < 0) return false; /* send failed */

    /* recv response */
    set_iov(&s_iov[0], s_buf_res, BUFSZ_R);
    switch (recv_res(1, false)) {
        case 0: /* no msg */
            return true;
        case 1:
            return test_res(s_buf_res);
        default: /* error occurs */
            return false;
    }
}

/* ======================== add-ip ======================== */

static void add_ip_ipset(const struct addctx *noalias ctx, bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = a_addmsg(ctx, v4);
    add_elem_ipset(nlmsg, ip, v4);
}

static void add_ip_nft(const struct addctx *noalias ctx, bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = a_addmsg(ctx, v4);
    add_elem_nft(nlmsg, ip, v4, 0); /* start */
    ubyte *p = nla_data(add_elem_nft(nlmsg, ip, v4, NFT_SET_ELEM_INTERVAL_END)); /* end */
    for (int i = iplen(v4) - 1; i >= 0; --i) { /* lsb -> msb */
        ubyte old = p[i];
        if (++p[i] > old) break;
    }
}

void ipset_add_ip(const void *noalias ip, bool v4, bool chn) {
    struct addctx *noalias ctx = a_ctx(chn);
    int n = a_ip_n(ctx, v4);
    if (n <= 0)
        a_addmsg(ctx, v4)->nlmsg_len = a_initlen(ctx, v4);
    else if (n >= IP_N) {
        ipset_end_add_ip(chn);
        assert(a_ip_n(ctx, v4) == 0);
        a_addmsg(ctx, v4)->nlmsg_len = a_initlen(ctx, v4);
    }
    add_ip(ctx, v4, ip);
    ++a_ip_n(ctx, v4);
}

/* ======================== end-add-ip ======================== */

static inline void init_nlerr_msgv(int n) {
    assert(n > 0);
    assert(n <= MSG_N);
    size_t sz = NLMSG_SPACE(sizeof(struct nlmsgerr));
    for (int i = 0; i < n; ++i) {
        set_iov(&s_iov[i], s_buf_res + sz * i, sz);
        set_msghdr(&s_msgv[i].msg_hdr, &s_iov[i], 1, NULL, 0);
    }
}

/* v4 and v6, zero `exists` before calling */
static void test_ips(const struct addctx *noalias ctx, bitvec_t exists[noalias],
    void (*next_ip)(const struct addctx *noalias ctx, bool v4, void **noalias p))
{
    int n_msg = 0;

    /* fill ip-test msg */
    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(ctx, v4);
        if (ipn <= 0) continue;

        void *base1 = NULL;
        size_t len1 = iplen(v4);

        struct nlmsghdr *base0 = a_testmsg(ctx, v4);
        size_t len0 = base0->nlmsg_len - len1; /* iplen is aligned(4) */

        for (int ipi = 0; ipi < ipn; ++ipi) {
            int i = n_msg++;
            next_ip(ctx, v4, &base1);
            set_iov(&s_iov[i*2], base0, len0);
            set_iov(&s_iov[i*2+1], base1, len1);
            set_msghdr(&s_msgv[i].msg_hdr, &s_iov[i*2], 2, NULL, 0);
        }
    }

    if (n_msg <= 0) return;

    unlikely_if ((n_msg = send_req(n_msg)) < 0) return; /* all failed */

    init_nlerr_msgv(n_msg);
    unlikely_if ((n_msg = recv_res(n_msg, true)) <= 0) return;

    /* save result to bit-vector */
    for (int i = 0; i < n_msg; ++i) {
        if (test_res(s_iov[i].iov_base))
            bitvec_set1(exists, i);
    }
}

static void next_ip_ipset(const struct addctx *noalias ctx, bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_addmsg(ctx, v4) + a_initlen(ctx, v4) + NLA_HDRLEN * 3;
    else
        *p += NLA_HDRLEN * 3 + iplen(v4) /* aligned(4) */;
}

static int end_add_ip_ipset(const struct addctx *noalias ctx) {
    /* v4 and v6 */
    bitvec_t exists[bitvec_n(IP_N * 2)] = {0};
    test_ips(ctx, exists, next_ip_ipset);

    int iov_i = 0;
    int n_msg = 0;

    /* exists (bitvec) */
    int bit_i = 0;

    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(ctx, v4);
        if (ipn <= 0) continue;

        struct nlmsghdr *nlmsg = a_addmsg(ctx, v4);
        nlmsg->nlmsg_len = a_initlen(ctx, v4);

        void *elem = nlmsg_dataend(nlmsg);
        size_t elemsz = NLA_HDRLEN * 3 + iplen(v4) /* aligned(4) */;

        int add_n = 0;

        set_iov(&s_iov[iov_i], nlmsg, nlmsg->nlmsg_len);
        ++iov_i;

        for (int ipi = 0; ipi < ipn; ++ipi, elem += elemsz, ++bit_i) {
            if (!bitvec_get(exists, bit_i)) {
                set_iov(&s_iov[iov_i], elem, elemsz);
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
        set_msghdr(&s_msgv[i].msg_hdr, &s_iov[iov_i - 1 - add_n], 1 + add_n, NULL, 0);
    }

    return n_msg;
}

static void next_ip_nft(const struct addctx *noalias ctx, bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_addmsg(ctx, v4) + a_initlen(ctx, v4) + NLA_HDRLEN * 3;
    else
        *p += NLA_HDRLEN * 7 + NLA_ALIGN(sizeof(u32)) + iplen(v4) * 2 /* aligned(4) */;
}

static int end_add_ip_nft(const struct addctx *noalias ctx) {
    /* v4 and v6 */
    bitvec_t exists[bitvec_n(IP_N * 2)] = {0};
    test_ips(ctx, exists, next_ip_nft);

    int iov_i = 0;

    /* transaction begin */
    set_iov(&s_iov[iov_i], &s_batch_begin, sizeof(s_batch_begin));
    ++iov_i;

    /* exists (bitvec) */
    int bit_i = 0;

    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ip_n(ctx, v4);
        if (ipn <= 0) continue;

        struct nlmsghdr *nlmsg = a_addmsg(ctx, v4);
        nlmsg->nlmsg_len = a_initlen(ctx, v4);

        void *elem = nlmsg_dataend(nlmsg);
        size_t elemsz = NLA_HDRLEN * 7 + NLA_ALIGN(sizeof(u32)) + iplen(v4) * 2 /* aligned(4) */;

        int add_n = 0;

        set_iov(&s_iov[iov_i], nlmsg, nlmsg->nlmsg_len);
        ++iov_i;

        for (int ipi = 0; ipi < ipn; ++ipi, elem += elemsz, ++bit_i) {
            if (!bitvec_get(exists, bit_i)) {
                set_iov(&s_iov[iov_i], elem, elemsz);
                ++iov_i;
                ++add_n;
            }
        }

        if (add_n <= 0) {
            --iov_i;
            continue;
        }

        struct nlattr *elems_nla = nlmsg_dataend(nlmsg) - NLA_HDRLEN;
        elems_nla->nla_len = nla_len_calc(add_n * elemsz);
        nlmsg->nlmsg_len += add_n * elemsz;
    }

    if (iov_i <= 1)
        return 0;

    /* transaction end */
    set_iov(&s_iov[iov_i], &s_batch_end, sizeof(s_batch_end));
    ++iov_i;

    set_msghdr(&s_msgv[0].msg_hdr, &s_iov[0], iov_i, NULL, 0);

    return 1;
}

void ipset_end_add_ip(bool chn) {
    /*
      current dns servers do not carry both A and AAAA answers, but they may in the future.
      see: https://datatracker.ietf.org/doc/html/draft-vavrusa-dnsop-aaaa-for-free-00
    */

    struct addctx *noalias ctx = a_ctx(chn);

    if (a_ip_n(ctx, true) + a_ip_n(ctx, false) <= 0) return;

    int n_msg = end_add_ip(ctx);

    /* reset to 0 */
    a_ip_n(ctx, true) = 0;
    a_ip_n(ctx, false) = 0;

    if (n_msg <= 0) return;

    unlikely_if (send_req(n_msg) < 0) return; /* all failed */

    /* recv nlmsgerr */
    n_msg = max(n_msg, 2); /* nft send v4 and v6 together, but the res are separate */
    init_nlerr_msgv(n_msg);
    likely_if ((n_msg = recv_res(n_msg, false)) == 0) return; /* no msg */

    for (int i = 0; i < n_msg; ++i) {
        const struct nlmsghdr *nlmsg = s_iov[i].iov_base;
        int errcode = nlmsg_errcode(nlmsg);
        log_warning("error when adding ip: (%d) %s", errcode, ipset_strerror(errcode));
    }
}
