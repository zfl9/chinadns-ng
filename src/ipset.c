#define _GNU_SOURCE
#include "ipset.h"
#include "net.h"
#include "log.h"
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

/* linux/netfilter/nfnetlink.h */
struct nfgenmsg {
    u8     nfgen_family;   /* AF_xxx */
    u8     version;        /* nfnetlink version */
    u16    res_id;         /* resource id (be) */
};

struct header {
    struct nlmsghdr nl struct_alignto(NLMSG_ALIGNTO);
    struct nfgenmsg nf struct_alignto(NLMSG_ALIGNTO);
};

/* [nft] nfgen_family */
#define NFPROTO_INET    1
#define NFPROTO_IPV4    2
#define NFPROTO_ARP     3
#define NFPROTO_NETDEV  5
#define NFPROTO_BRIDGE  7
#define NFPROTO_IPV6   10

/* nfgenmsg.version */
#define NFNETLINK_V0 0

/* [ipset] include \0 */
#define IPSET_MAXNAMELEN 32

/* [nft] include \0 */
#define NFT_NAME_MAXLEN 256

/* [nft] include \0 */
#define NFT_FAMILY_MAXLEN ((int)sizeof("netdev"))

/* "set_name" | "family_name@table_name@set_name" (include \0) */
#define NAME_MAXLEN \
    (NFT_FAMILY_MAXLEN + NFT_NAME_MAXLEN + NFT_NAME_MAXLEN)

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

#define case_ret_name(err) \
    case err: return #err

static const char *ipset_strerror(int errcode) {
    switch (errcode) {
        case_ret_name(IPSET_ERR_PROTOCOL);
        case_ret_name(IPSET_ERR_FIND_TYPE);
        case_ret_name(IPSET_ERR_MAX_SETS);
        case_ret_name(IPSET_ERR_BUSY);
        case_ret_name(IPSET_ERR_EXIST_SETNAME2);
        case_ret_name(IPSET_ERR_TYPE_MISMATCH);
        case_ret_name(IPSET_ERR_EXIST);
        case_ret_name(IPSET_ERR_INVALID_CIDR);
        case_ret_name(IPSET_ERR_INVALID_NETMASK);
        case_ret_name(IPSET_ERR_INVALID_FAMILY);
        case_ret_name(IPSET_ERR_TIMEOUT);
        case_ret_name(IPSET_ERR_REFERENCED);
        case_ret_name(IPSET_ERR_IPADDR_IPV4);
        case_ret_name(IPSET_ERR_IPADDR_IPV6);
        case_ret_name(IPSET_ERR_COUNTER);
        case_ret_name(IPSET_ERR_COMMENT);
        case_ret_name(IPSET_ERR_INVALID_MARKMASK);
        case_ret_name(IPSET_ERR_SKBINFO);
        case_ret_name(IPSET_ERR_BITMASK_NETMASK_EXCL);
        case_ret_name(IPSET_ERR_HASH_FULL);
        case_ret_name(IPSET_ERR_HASH_ELEM);
        case_ret_name(IPSET_ERR_INVALID_PROTO);
        case_ret_name(IPSET_ERR_MISSING_PROTO);
        case_ret_name(IPSET_ERR_HASH_RANGE_UNSUPPORTED);
        case_ret_name(IPSET_ERR_HASH_RANGE);
        default: return strerror(errcode);
    }
}

#undef case_ret_name

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
    ((v4) ? IPV4_LEN : IPV6_LEN)

#define BUFSZ_TEST_IPSET(v4) ( \
    sizeof(struct header) + \
    nla_size_calc(sizeof(u8)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    /* element */ \
    NLA_HDRLEN /* data_nla(nested) */ + \
    NLA_HDRLEN /* ip_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* addr_nla */ \
)

#define BUFSZ_ADD_IPSET(v4) ( \
    sizeof(struct header) + \
    nla_size_calc(sizeof(u8)) /* protocol */ + \
    nla_size_calc(IPSET_MAXNAMELEN) /* set_name */ + \
    nla_size_calc(sizeof(u32)) /* lineno_nla */ + \
    NLA_HDRLEN /* adt_nla(nested) */ + \
    IP_N * ( \
        /* element */ \
        NLA_HDRLEN /* data_nla(nested) */ + \
        NLA_HDRLEN /* ip_nla(nested) */ + \
        nla_size_calc(iplen(v4)) /* addr_nla */ \
    ) \
)

#define BUFSZ_TEST_NFTSET(v4) ( \
    sizeof(struct header) + \
    nla_size_calc(NFT_NAME_MAXLEN) /* table_name */ + \
    nla_size_calc(NFT_NAME_MAXLEN) /* set_name */ + \
    NLA_HDRLEN /* elems_nla(nested) */ + \
    NLA_HDRLEN /* elem_nla(nested) */ + \
    NLA_HDRLEN /* key_nla(nested) */ + \
    nla_size_calc(iplen(v4)) /* data_nla */ \
)

#define BUFSZ_ADD_NFTSET(v4) ( \
    sizeof(struct header) + \
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

#define BUFSZ_TEST(is_ipset, v4) \
    ((is_ipset) ? BUFSZ_TEST_IPSET(v4) : BUFSZ_TEST_NFTSET(v4))

#define BUFSZ_ADD(is_ipset, v4) \
    ((is_ipset) ? BUFSZ_ADD_IPSET(v4) : BUFSZ_ADD_NFTSET(v4))

/* [add test_ips] v4 + v6 */
#define BUFSZ_RES \
    (NLMSG_SPACE(sizeof(struct nlmsgerr)) * IP_N * 2)

/* ====================================================== */

/* add ip */
bool ipset_blacklist = true;

static int s_sock   = -1; /* netlink socket fd */
static u32 s_portid = 0; /* local address (port-id) */

static MMSGHDR *s_msgv;
static struct iovec *s_iov;

/* store ack/err nlmsg */
static void *s_buf_res;

/* nft transaction [add] */
static struct header s_batch_begin;
static struct header s_batch_end;

/* ====================================================== */

struct ipset_testctx {
    struct nlmsghdr *msg4;
    struct nlmsghdr *msg6;
};

/* tag:chn, tag:gfw, ... */
struct ipset_addctx {
    struct ipset_testctx testctx;
    struct nlmsghdr *msg4;
    struct nlmsghdr *msg6;
    u32 baselen4; /* the nlmsg_len when there is no ip */
    u32 baselen6; /* the nlmsg_len when there is no ip */
    int ipcnt4; /* the number of ip in the msg4 */
    int ipcnt6; /* the number of ip in the msg6 */
};

/* ====================================================== */

/* return `exists_in_set` */
static bool (*test_res)(const struct nlmsghdr *noalias res);
static bool test_res_ipset(const struct nlmsghdr *noalias res);
static bool test_res_nftset(const struct nlmsghdr *noalias res);

static void (*add_ip)(const struct ipset_addctx *noalias ctx, bool v4, const void *noalias ip);
static void add_ip_ipset(const struct ipset_addctx *noalias ctx, bool v4, const void *noalias ip);
static void add_ip_nftset(const struct ipset_addctx *noalias ctx, bool v4, const void *noalias ip);

/* return `n_msg_to_send` */
static int (*end_add_ip)(const struct ipset_addctx *noalias ctx);
static int end_add_ip_ipset(const struct ipset_addctx *noalias ctx);
static int end_add_ip_nftset(const struct ipset_addctx *noalias ctx);

/* ====================================================== */

/* testctx */
#define t_msg(ctx, v4) \
    (*((v4) ? &(ctx)->msg4 : &(ctx)->msg6))

/* testctx */
#define t_ip(ctx, v4) \
    (nlmsg_dataend(t_msg(ctx, v4)) - iplen(v4))

/* addctx */
#define a_testmsg(ctx, v4) \
    t_msg(&(ctx)->testctx, v4)

/* addctx */
#define a_msg(ctx, v4) \
    (*((v4) ? &(ctx)->msg4 : &(ctx)->msg6))

/* addctx */
#define a_baselen(ctx, v4) \
    (*((v4) ? &(ctx)->baselen4 : &(ctx)->baselen6))

/* addctx */
#define a_ipcnt(ctx, v4) \
    (*((v4) ? &(ctx)->ipcnt4 : &(ctx)->ipcnt6))

/* ====================================================== */

static void init_header(void *noalias nlmsg, u16 type, u16 flags, u8 family, u16 resid) {
    struct header *h = nlmsg;
    h->nl.nlmsg_len = sizeof(*h);
    h->nl.nlmsg_type = type;
    h->nl.nlmsg_flags = flags;
    h->nl.nlmsg_seq = 0; /* used to track messages */
    h->nl.nlmsg_pid = s_portid;
    h->nf.nfgen_family = family;
    h->nf.version = NFNETLINK_V0;
    h->nf.res_id = htons(resid);
}

static struct nlattr *add_elem_ipset(struct nlmsghdr *noalias nlmsg, const void *noalias ip, bool v4) {
    u16 attrtype = (v4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER;
    struct nlattr *data_nla = nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_DATA);
    struct nlattr *ip_nla = nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_IP);
    struct nlattr *addr_nla = nlmsg_add_nla(nlmsg, attrtype, ip, iplen(v4));
    nlmsg_end_nest_nla(nlmsg, ip_nla);
    nlmsg_end_nest_nla(nlmsg, data_nla);
    return addr_nla;
}

static struct nlattr *add_elem_nftset(struct nlmsghdr *noalias nlmsg, const void *noalias ip, bool v4, u32 flags) {
    struct nlattr *elem_nla = nlmsg_add_nest_nla(nlmsg, NFTA_LIST_ELEM);
    if (flags) nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_FLAGS, &(u32){htonl(flags)}, sizeof(u32));
    struct nlattr *key_nla = nlmsg_add_nest_nla(nlmsg, NFTA_SET_ELEM_KEY);
    struct nlattr *data_nla = nlmsg_add_nla(nlmsg, NFTA_DATA_VALUE|NLA_F_NET_BYTEORDER, ip, iplen(v4));
    nlmsg_end_nest_nla(nlmsg, key_nla);
    nlmsg_end_nest_nla(nlmsg, elem_nla);
    return data_nla;
}

/* ====================================================== */

static size_t get_namelen_ipset(const char *noalias name) {
    size_t namelen = strlen(name);
    unlikely_if (namelen < 1 || namelen > IPSET_MAXNAMELEN - 1) {
        log_error("invalid name: '%s'", name);
        exit(1);
    }
    return namelen;
}

static void init_testmsg_ipset(struct nlmsghdr *noalias nlmsg, const char *noalias name, bool v4, bool ack) {
    /* header */
    u16 type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST;
    u16 flags = NLM_F_REQUEST | (ack ? NLM_F_ACK : 0);
    init_header(nlmsg, type, flags, v4 ? AF_INET : AF_INET6, 0);

    /* protocol */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_PROTOCOL, &(u8){IPSET_PROTOCOL}, sizeof(u8));

    /* setname */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_SETNAME, name, get_namelen_ipset(name) + 1);

    /* element */
    add_elem_ipset(nlmsg, NULL, v4);
}

static void init_addmsg_ipset(struct nlmsghdr *noalias nlmsg, const char *noalias name, bool v4) {
    /* header */
    u16 type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
    u16 flags = NLM_F_REQUEST;
    init_header(nlmsg, type, flags, v4 ? AF_INET : AF_INET6, 0);

    /* protocol */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_PROTOCOL, &(u8){IPSET_PROTOCOL}, sizeof(u8));

    /* setname */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_SETNAME, name, get_namelen_ipset(name) + 1);

    /* lineno */
    nlmsg_add_nla(nlmsg, IPSET_ATTR_LINENO, &(u32){0}, sizeof(u32));

    /* adt { element, ... } */
    nlmsg_add_nest_nla(nlmsg, IPSET_ATTR_ADT);
}

/* ====================================================== */

static void parse_name_nftset(const char *noalias name,
    u8 *noalias p_family, char table_name[noalias], char set_name[noalias])
{
    int n = 0;
    const char *err;

    for (const char *start = name, *end, *name_end = name + strlen(name);
        start < name_end && ((end = memchr(start, '@', name_end - start)) || (end = name_end));
        start = (end < name_end) ? end + 1 : name_end)
    {
        ++n;
        int len = end - start;
        if (n == 1) {
            char family[NFT_FAMILY_MAXLEN];
            if (len > NFT_FAMILY_MAXLEN - 1) {
                err = "invalid family";
                goto err;
            }
            memcpy(family, start, len);
            family[len] = 0;
            if (strcmp(family, "ip") == 0)
                *p_family = NFPROTO_IPV4;
            else if (strcmp(family, "ip6") == 0)
                *p_family = NFPROTO_IPV6;
            else if (strcmp(family, "inet") == 0)
                *p_family = NFPROTO_INET;
            else if (strcmp(family, "arp") == 0)
                *p_family = NFPROTO_ARP;
            else if (strcmp(family, "bridge") == 0)
                *p_family = NFPROTO_BRIDGE;
            else if (strcmp(family, "netdev") == 0)
                *p_family = NFPROTO_NETDEV;
            else {
                err = "invalid family";
                goto err;
            }
        } else if (n <= 3) {
            bool is_table = n == 2;
            if (len < 1 || len > NFT_NAME_MAXLEN - 1) {
                err = is_table ? "invalid table_name" : "invalid set_name";
                goto err;
            }
            char *p = is_table ? table_name : set_name;
            memcpy(p, start, len);
            p[len] = 0;
        } else {
            err = "invalid format";
            goto err;
        }
    }

    unlikely_if (n != 3) {
        err = "invalid format";
        goto err;
    }

    return;

err:
    log_error("%s: '%s'", err, name);
    exit(1);
}

static void init_testmsg_nftset(struct nlmsghdr *noalias nlmsg, const char *noalias name, bool v4) {
    u8 family;
    char table_name[NFT_NAME_MAXLEN];
    char set_name[NFT_NAME_MAXLEN];
    parse_name_nftset(name, &family, table_name, set_name);

    /* header */
    u16 type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM;
    u16 flags = NLM_F_REQUEST;
    init_header(nlmsg, type, flags, family, 0);

    /* table_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_TABLE, table_name, strlen(table_name) + 1);

    /* set_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_SET, set_name, strlen(set_name) + 1);

    /* elements {elem, elem, ...} */
    struct nlattr *elems_nla = nlmsg_add_nest_nla(nlmsg, NFTA_SET_ELEM_LIST_ELEMENTS);

    /* element */
    add_elem_nftset(nlmsg, NULL, v4, 0);

    /* elements end */
    nlmsg_end_nest_nla(nlmsg, elems_nla);
}

static void init_addmsg_nftset(struct nlmsghdr *noalias nlmsg, const char *noalias name, bool v4) {
    (void)v4;

    u8 family;
    char table_name[NFT_NAME_MAXLEN];
    char set_name[NFT_NAME_MAXLEN];
    parse_name_nftset(name, &family, table_name, set_name);

    /* header */
    u16 type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
    u16 flags = NLM_F_REQUEST;
    init_header(nlmsg, type, flags, family, 0);

    /* table_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_TABLE, table_name, strlen(table_name) + 1);

    /* set_name */
    nlmsg_add_nla(nlmsg, NFTA_SET_ELEM_LIST_SET, set_name, strlen(set_name) + 1);

    /* elements {elem, elem, ...} */
    nlmsg_add_nest_nla(nlmsg, NFTA_SET_ELEM_LIST_ELEMENTS);
}

/* ====================================================== */

static void parse_name46(const char *noalias input, char name4[noalias], char name6[noalias]) {
    size_t input_len = strlen(input);
    const char *input_end = input + input_len;

    const char *start = input;
    const char *sep = memchr(input, ',', input_len) ?: input_end;
    int len = sep - start;

    if (len == 4 && memcmp("null", start, len) == 0) {
        name4[0] = 0;
    } else {
        if (len < 1 || len > NAME_MAXLEN - 1) goto err;
        memcpy(name4, start, len);
        name4[len] = 0;
    }

    if (sep == input_end || ((len = input_end - (start = sep + 1)) == 4 && memcmp("null", start, len) == 0)) {
        name6[0] = 0;
    } else {
        if (len < 1 || len > NAME_MAXLEN - 1) goto err;
        memcpy(name6, start, len);
        name6[len] = 0;
    }

    if (*name4 || *name6) return;

err:
    log_error("invalid format: '%s'", input);
    exit(1);
}

/* return `is_ipset` */
static bool init(const char *noalias name46) {
    bool is_ipset = !strchr(name46, '@');

    /* already initialized ? */
    if (s_sock >= 0) {
        /* the backend must be the same */
        bool is_ipset_backend = test_res == test_res_ipset;
        unlikely_if (is_ipset != is_ipset_backend) {
            log_error("mixing two backends is not allowed");
            log_error("backend: %s, setnames: %s", is_ipset_backend ? "ipset" : "nftset", name46);
            exit(1);
        }
        return is_ipset;
    }

    /*
      for the netfilter module, req_nlmsg is always processed synchronously in the context of the sendmsg system call,
        and the res_nlmsg is placed in the sender's receive queue before sendmsg returns.
    */
    s_sock = nl_sock_create(NETLINK_NETFILTER, &s_portid);

    size_t msgv_sz = sizeof(*s_msgv) * MSG_N;
    size_t iov_sz = sizeof(*s_iov) * IOV_N;
    size_t res_sz = BUFSZ_RES;
    void *p = malloc(msgv_sz + iov_sz + res_sz);

    s_msgv = p;
    s_iov = p + msgv_sz;
    s_buf_res = p + msgv_sz + iov_sz;

    if (is_ipset) {
        test_res = test_res_ipset;
        add_ip = add_ip_ipset;
        end_add_ip = end_add_ip_ipset;
    } else {
        test_res = test_res_nftset;
        add_ip = add_ip_nftset;
        end_add_ip = end_add_ip_nftset;
        /* batch_begin/batch_end */
        init_header(&s_batch_begin, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        init_header(&s_batch_end, NFNL_MSG_BATCH_END, NLM_F_REQUEST, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
    }

    // log_info("current backend: %s", is_ipset ? "ipset" : "nftset");

    return is_ipset;
}

static void init_testctx(const struct ipset_testctx *noalias ctx,
    const char *noalias name4, const char *noalias name6,
    bool is_ipset, bool ack)
{
    if (is_ipset) {
        if (ctx->msg4) init_testmsg_ipset(ctx->msg4, name4, true, ack);
        if (ctx->msg6) init_testmsg_ipset(ctx->msg6, name6, false, ack);
    } else {
        if (ctx->msg4) init_testmsg_nftset(ctx->msg4, name4, true);
        if (ctx->msg6) init_testmsg_nftset(ctx->msg6, name6, false);
    }
}

/* ====================================================== */

const struct ipset_testctx *ipset_new_testctx(const char *noalias name46) {
    bool is_ipset = init(name46);

    char name4[NAME_MAXLEN], name6[NAME_MAXLEN];
    parse_name46(name46, name4, name6);

    size_t ctx_sz = sizeof(struct ipset_testctx);
    size_t msg4_sz = BUFSZ_TEST(is_ipset, true);
    size_t msg6_sz = BUFSZ_TEST(is_ipset, false);

    if (!*name4) msg4_sz = 0;
    if (!*name6) msg6_sz = 0;

    void *p = malloc(ctx_sz + msg4_sz + msg6_sz);

    struct ipset_testctx *ctx = p;
    ctx->msg4 = msg4_sz ? p + ctx_sz : NULL;
    ctx->msg6 = msg6_sz ? p + ctx_sz + msg4_sz : NULL;

    init_testctx(ctx, name4, name6, is_ipset, false);

    return ctx;
}

struct ipset_addctx *ipset_new_addctx(const char *noalias name46) {
    bool is_ipset = init(name46);

    char name4[NAME_MAXLEN], name6[NAME_MAXLEN];
    parse_name46(name46, name4, name6);

    size_t ctx_sz = sizeof(struct ipset_addctx);
    size_t test_msg4_sz = BUFSZ_TEST(is_ipset, true);
    size_t test_msg6_sz = BUFSZ_TEST(is_ipset, false);
    size_t add_msg4_sz = BUFSZ_ADD(is_ipset, true);
    size_t add_msg6_sz = BUFSZ_ADD(is_ipset, false);

    if (!*name4) {
        test_msg4_sz = 0;
        add_msg4_sz = 0;
    }
    if (!*name6) {
        test_msg6_sz = 0;
        add_msg6_sz = 0;
    }

    void *p = malloc(ctx_sz + test_msg4_sz + test_msg6_sz + add_msg4_sz + add_msg6_sz);

    struct ipset_addctx *ctx = p;
    ctx->testctx.msg4 = test_msg4_sz ? p + ctx_sz : NULL;
    ctx->testctx.msg6 = test_msg6_sz ? p + ctx_sz + test_msg4_sz : NULL;
    ctx->msg4 = add_msg4_sz ? p + ctx_sz + test_msg4_sz + test_msg6_sz : NULL;
    ctx->msg6 = add_msg6_sz ? p + ctx_sz + test_msg4_sz + test_msg6_sz + add_msg4_sz : NULL;
    ctx->ipcnt4 = ctx->ipcnt6 = 0;

    init_testctx(&ctx->testctx, name4, name6, is_ipset, true);

    __typeof__(&init_addmsg_ipset) init_addmsg = is_ipset ? init_addmsg_ipset : init_addmsg_nftset;

    if (ctx->msg4)
        ctx->baselen4 = (init_addmsg(ctx->msg4, name4, true), ctx->msg4->nlmsg_len);
    if (ctx->msg6)
        ctx->baselen6 = (init_addmsg(ctx->msg6, name6, false), ctx->msg6->nlmsg_len);

    return ctx;
}

/* ====================================================== */

/* res<0: error || res>0: n_sent */
static int send_req(int n_msg) {
    assert(n_msg > 0);
    assert(n_msg <= MSG_N);
    int n_sent = sendall(SENDMMSG, s_sock, s_msgv, n_msg, 0);
    assert(n_sent != 0);
    unlikely_if (n_sent != n_msg)
        log_warning("failed to send nlmsg: %d != %d, (%d) %m", n_sent, n_msg, errno);
    return n_sent;
}

/* res<0: error || res=0: no-msg || res>0: n_recv */
static int recv_res(int n_msg, bool err_if_nomsg) {
    assert(n_msg > 0);
    assert(n_msg <= MSG_N);
    int n_recv = RECVMMSG(s_sock, s_msgv, n_msg, MSG_DONTWAIT, NULL);
    assert(n_recv != 0);
    if (n_recv < 0) { /* no-msg or error */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            n_recv = 0;
        unlikely_if (err_if_nomsg || n_recv < 0)
            log_warning("failed to recv nlmsg: (%d) %m", errno);
    }
    return n_recv;
}

/* ======================== test-ip ======================== */

static bool test_res_ipset(const struct nlmsghdr *noalias res) {
    int errcode = nlmsg_errcode(res);
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

static bool test_res_nftset(const struct nlmsghdr *noalias res) {
    if (res->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM))
        return true;
    int errcode = nlmsg_errcode(res);
    unlikely_if (errcode != ENOENT) /* ENOENT: table not exists; set not exists; elem not exists */
        log_warning("error when querying ip: (%d) %s", errcode, strerror(errcode));
    return false;
}

bool ipset_test_ip(const struct ipset_testctx *noalias ctx, const void *noalias ip, bool v4) {
    struct nlmsghdr *msg = t_msg(ctx, v4);
    if (!msg) return false;

    memcpy(t_ip(ctx, v4), ip, iplen(v4));

    /* send request */
    set_iov(&s_iov[0], msg, msg->nlmsg_len);
    set_MSGHDR(&s_msgv[0].msg_hdr, &s_iov[0], 1, NULL, 0);
    unlikely_if (send_req(1) < 0) return false; /* send failed */

    /* recv response */
    set_iov(&s_iov[0], s_buf_res, BUFSZ_RES);
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

static void add_ip_ipset(const struct ipset_addctx *noalias ctx, bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = a_msg(ctx, v4);
    add_elem_ipset(nlmsg, ip, v4);
}

static void add_ip_nftset(const struct ipset_addctx *noalias ctx, bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = a_msg(ctx, v4);
    add_elem_nftset(nlmsg, ip, v4, 0); /* start */
    ubyte *p = nla_data(add_elem_nftset(nlmsg, ip, v4, NFT_SET_ELEM_INTERVAL_END)); /* end */
    for (int i = iplen(v4) - 1; i >= 0; --i) { /* lsb -> msb */
        ubyte old = p[i];
        if (++p[i] > old) break;
    }
}

static bool in_blacklist(const ubyte *noalias ip, bool v4) {
    if (v4) {
        if (ip[0] == 127 || ip[0] == 0) return true;
    } else {
        const ubyte zeros[15] = {0};
        if (memcmp(ip, zeros, 15) == 0 && (ip[15] == 0 || ip[15] == 1)) return true;
    }
    return false;
}

void ipset_add_ip(struct ipset_addctx *noalias ctx, const void *noalias ip, bool v4) {
    struct nlmsghdr *msg = a_msg(ctx, v4);
    if (!msg) return;

    if (ipset_blacklist && in_blacklist(ip, v4)) return;

    int n = a_ipcnt(ctx, v4);
    if (n <= 0)
        msg->nlmsg_len = a_baselen(ctx, v4);
    else if (n >= IP_N) {
        ipset_end_add_ip(ctx);
        assert(a_ipcnt(ctx, v4) == 0);
        msg->nlmsg_len = a_baselen(ctx, v4);
    }

    add_ip(ctx, v4, ip);
    ++a_ipcnt(ctx, v4);
}

/* ======================== end-add-ip ======================== */

static void init_nlerr_msgv(int n) {
    assert(n > 0);
    assert(n <= MSG_N);
    size_t sz = NLMSG_SPACE(sizeof(struct nlmsgerr));
    for (int i = 0; i < n; ++i) {
        set_iov(&s_iov[i], s_buf_res + sz * i, sz);
        set_MSGHDR(&s_msgv[i].msg_hdr, &s_iov[i], 1, NULL, 0);
    }
}

/* v4 and v6, zero `exists` before calling */
static void test_ips(const struct ipset_addctx *noalias ctx, bitvec_t exists[noalias],
    void (*next_ip)(const struct ipset_addctx *noalias ctx, bool v4, void **noalias p))
{
    int n_msg = 0;

    /* fill ip-test msg */
    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ipcnt(ctx, v4);
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
            set_MSGHDR(&s_msgv[i].msg_hdr, &s_iov[i*2], 2, NULL, 0);
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

/* ====================================================== */

static void next_ip_ipset(const struct ipset_addctx *noalias ctx, bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_msg(ctx, v4) + a_baselen(ctx, v4) + NLA_HDRLEN * 3;
    else
        *p += NLA_HDRLEN * 3 + iplen(v4) /* aligned(4) */;
}

static int end_add_ip_ipset(const struct ipset_addctx *noalias ctx) {
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

        int ipn = a_ipcnt(ctx, v4);
        if (ipn <= 0) continue;

        struct nlmsghdr *nlmsg = a_msg(ctx, v4);
        nlmsg->nlmsg_len = a_baselen(ctx, v4);

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
        set_MSGHDR(&s_msgv[i].msg_hdr, &s_iov[iov_i - 1 - add_n], 1 + add_n, NULL, 0);
    }

    return n_msg;
}

/* ====================================================== */

static void next_ip_nftset(const struct ipset_addctx *noalias ctx, bool v4, void **noalias p) {
    if (!*p)
        *p = (void *)a_msg(ctx, v4) + a_baselen(ctx, v4) + NLA_HDRLEN * 3;
    else
        *p += NLA_HDRLEN * 7 + NLA_ALIGN(sizeof(u32)) + iplen(v4) * 2 /* aligned(4) */;
}

static int end_add_ip_nftset(const struct ipset_addctx *noalias ctx) {
    /* v4 and v6 */
    bitvec_t exists[bitvec_n(IP_N * 2)] = {0};
    test_ips(ctx, exists, next_ip_nftset);

    int iov_i = 0;

    /* transaction begin */
    set_iov(&s_iov[iov_i], &s_batch_begin, sizeof(s_batch_begin));
    ++iov_i;

    /* exists (bitvec) */
    int bit_i = 0;

    const bool v4vec[] = {true, false};
    for (int v4i = 0; v4i < (int)array_n(v4vec); ++v4i) {
        const bool v4 = v4vec[v4i];

        int ipn = a_ipcnt(ctx, v4);
        if (ipn <= 0) continue;

        struct nlmsghdr *nlmsg = a_msg(ctx, v4);
        nlmsg->nlmsg_len = a_baselen(ctx, v4);

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

    set_MSGHDR(&s_msgv[0].msg_hdr, &s_iov[0], iov_i, NULL, 0);

    return 1;
}

/* ====================================================== */

void ipset_end_add_ip(struct ipset_addctx *noalias ctx) {
    /*
      current dns servers do not carry both A and AAAA answers, but they may in the future.
      see: https://datatracker.ietf.org/doc/html/draft-vavrusa-dnsop-aaaa-for-free-00
    */

    if (a_ipcnt(ctx, true) + a_ipcnt(ctx, false) <= 0) return;

    int n_msg = end_add_ip(ctx);

    /* reset to 0 */
    a_ipcnt(ctx, true) = 0;
    a_ipcnt(ctx, false) = 0;

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
