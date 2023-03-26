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

/* #include <linux/netfilter/ipset/ip_set.h> */
#define NFNETLINK_V0 0 /* nfgenmsg.version */

/* #include <linux/netfilter/nfnetlink.h> */
struct nfgenmsg {
    uint8_t     nfgen_family;   /* AF_xxx */
    uint8_t     version;        /* nfnetlink version */
    uint16_t    res_id;         /* resource id */
};

/* [nftset] nfgen_family */
#define NFPROTO_INET 1 /* inet(v4/v6) */
#define NFPROTO_IPV4 2 /* ip */
#define NFPROTO_IPV6 10 /* ip6 */

/* [ipset] nlmsg_type (subsys << 8 | cmd) */
#define NFNL_SUBSYS_IPSET 6
#define IPSET_CMD_TEST 11
#define IPSET_CMD_ADD 9

/* [nftset] nlmsg_type (subsys << 8 | msg) */
#define NFNL_SUBSYS_NFTABLES 10
#define NFT_MSG_GETSETELEM 13
#define NFT_MSG_NEWSETELEM 12

/* [nfnl_batch] nlmsg_type */
#define NFNL_MSG_BATCH_BEGIN 16
#define NFNL_MSG_BATCH_END 17

/* [ipset] nlattr type */
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_LINENO 9
#define IPSET_ATTR_ADT 8 /* {data, ...} */
#define IPSET_ATTR_DATA 7 /* {ip} */
#define IPSET_ATTR_IP 1 /* {ipaddr} */
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

/* [nftset] nlattr type */
#define NFTA_SET_ELEM_LIST_TABLE 1
#define NFTA_SET_ELEM_LIST_SET 2
#define NFTA_SET_ELEM_LIST_ELEMENTS 3 /* {list_elem, ...} */
#define NFTA_LIST_ELEM 1 /* {set_elem_*, ...} */
#define NFTA_SET_ELEM_KEY 1 /* {data_value} */
#define NFTA_SET_ELEM_FLAGS 3 /* uint32_t(be) */
#define NFTA_DATA_VALUE 1 /* binary */

/* [ipset] nlattr value */
#define IPSET_PROTOCOL 6

/* [nftset] nlattr value */
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

/* include \0 */
#define IPSET_MAXNAMELEN 32

/* include \0 */
#define NFT_NAME_MAXLEN 256

/* "table_name#set_name" (include \0) */
#define NFT_TABLE_SET_NAMELEN (NFT_NAME_MAXLEN + NFT_NAME_MAXLEN)

// see NFT_TABLE_SET_NAMELEN
#define MSGBUFSZ NLMSG_ALIGN(1024)

/* for nft add element (batch_begin|batch_end) */
#define BATCH_MSGBUFSZ NLMSG_SPACE(sizeof(struct nfgenmsg))

static int       s_sock        = -1; /* netlink socket fd */
static uint32_t  s_portid      = 0; /* local address (port-id) */
static uint32_t  s_msgseq      = 0;
static void     *s_reqbuf4     = (char [MSGBUFSZ]){0};
static void     *s_reqbuf6     = (char [MSGBUFSZ]){0};
static void     *s_resbuf1     = (char [MSGBUFSZ]){0};
static void     *s_resbuf2     = (char [MSGBUFSZ]){0};
static void     *s_batch_begin = (char [BATCH_MSGBUFSZ]){0};
static void     *s_batch_end   = (char [BATCH_MSGBUFSZ]){0};
static uint32_t  s_comlen4     = 0; /* nlh + nfh + (proto + setname | tablename + setname + elements_h) */
static uint32_t  s_comlen6     = 0; /* nlh + nfh + (proto + setname | tablename + setname + elements_h) */
static bool      s_dirty4      = false; /* need to commit (ip_add) */
static bool      s_dirty6      = false; /* need to commit (ip_add) */

static void (*start_req)(bool v4, bool cmd_test);
static void start_req_ipset(bool v4, bool cmd_test);
static void start_req_nftset(bool v4, bool cmd_test);

static void (*add_req_ip)(bool v4, const void *noalias ip, bool cmd_test);
static void add_req_ip_ipset(bool v4, const void *noalias ip, bool cmd_test);
static void add_req_ip_nftset(bool v4, const void *noalias ip, bool cmd_test);

static void (*end_req)(bool v4, bool cmd_test);
static void end_req_ipset(bool v4, bool cmd_test);
static void end_req_nftset(bool v4, bool cmd_test);

static bool (*test_result)(bool v4, const struct nlmsghdr *noalias nlmsg);
static bool test_result_ipset(bool v4, const struct nlmsghdr *noalias nlmsg);
static bool test_result_nftset(bool v4, const struct nlmsghdr *noalias nlmsg);

/* for ipset_end_add */
static void (*set_msghdr)(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int i);
static void set_msghdr_ipset(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int i);
static void set_msghdr_nftset(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int i);

/* req msg */
#define nlmsg(v4) \
    cast(struct nlmsghdr *, (v4) ? s_reqbuf4 : s_reqbuf6)

#define comlen(v4) \
    (*((v4) ? &s_comlen4 : &s_comlen6))

/* ipset: "set_name"
   nftset: "family_name@table_name@set_name" */
#define setname(v4) \
    ((v4) ? g_ipset_name4 : g_ipset_name6)

static void init_req_ipset(bool v4) {
    struct nlmsghdr *nlmsg = nlmsg(v4);

    /* netfilter header */
    struct nfgenmsg *nfmsg = nlmsg_add_data(nlmsg, MSGBUFSZ, NULL, sizeof(*nfmsg));
    nfmsg->nfgen_family = v4 ? AF_INET : AF_INET6;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    /* protocol */
    nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_PROTOCOL, &(ubyte){IPSET_PROTOCOL}, sizeof(ubyte));

    /* setname */
    const char *setname = setname(v4);
    size_t setnamelen = strlen(setname) + 1;
    if (setnamelen > IPSET_MAXNAMELEN) {
        LOGE("name max length is %d: '%s'", IPSET_MAXNAMELEN - 1, setname);
        exit(1);
    }
    nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_SETNAME, setname, setnamelen);
}

#define parse_nftset_name(v4, start, field, is_last) ({ \
    size_t len_; \
    if (!(is_last)) { \
        const char *end_ = strchr(start, '@'); \
        if (!end_) { \
            LOGE("bad format: '%s' (family_name@table_name@set_name)", setname(v4)); \
            exit(1); \
        } \
        len_ = end_ - (start); \
    } else { \
        len_ = strlen(start); \
    } \
    if (len_ < 1) { \
        LOGE("%s min length is 1: '%.*s'", #field, (int)len_, start); \
        exit(1); \
    } \
    if (len_ + 1 > sizeof(field)) { \
        LOGE("%s max length is %zu: '%.*s'", #field, sizeof(field) - 1, (int)len_, start); \
        exit(1); \
    } \
    memcpy(field, start, len_); \
    (field)[len_] = 0; \
    (start) += len_ + 1; \
})

static void init_req_nftset(bool v4) {
    struct nlmsghdr *nlmsg = nlmsg(v4);

    char family_name[sizeof("inet")]; /* ip | ip6 | inet */
    char table_name[NFT_NAME_MAXLEN];
    char set_name[NFT_NAME_MAXLEN];

    const char *start = setname(v4);
    parse_nftset_name(v4, start, family_name, false);
    parse_nftset_name(v4, start, table_name, false);
    parse_nftset_name(v4, start, set_name, true); /* last field */

    uint8_t family;
    if (strcmp(family_name, "ip") == 0)
        family = NFPROTO_IPV4;
    else if (strcmp(family_name, "ip6") == 0)   
        family = NFPROTO_IPV6;
    else if (strcmp(family_name, "inet") == 0)
        family = NFPROTO_INET;
    else {
        LOGE("invalid family: '%s' (ip | ip6 | inet)", family_name);
        exit(1);
    }

    /* netfilter header */
    struct nfgenmsg *nfmsg = nlmsg_add_data(nlmsg, MSGBUFSZ, NULL, sizeof(*nfmsg));
    nfmsg->nfgen_family = family;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    nlmsg_add_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_LIST_TABLE, table_name, strlen(table_name) + 1);
    nlmsg_add_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_LIST_SET, set_name, strlen(set_name) + 1);
    nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_LIST_ELEMENTS);
}

/* for nft add element */
static void init_batch_msg(void) {
    void *bufs[] = {s_batch_begin, s_batch_end};
    uint16_t msgtypes[] = {NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END};

    for (size_t i = 0; i < array_n(bufs); ++i) {
        struct nlmsghdr *nlmsg = bufs[i];
        nlmsg->nlmsg_len = NLMSG_HDRLEN;
        nlmsg->nlmsg_type = msgtypes[i];
        nlmsg->nlmsg_flags = NLM_F_REQUEST;
        nlmsg->nlmsg_seq = 0;
        nlmsg->nlmsg_pid = s_portid;

        struct nfgenmsg *nfmsg = nlmsg_add_data(nlmsg, BATCH_MSGBUFSZ, NULL, sizeof(*nfmsg));
        nfmsg->nfgen_family = AF_UNSPEC;
        nfmsg->version = NFNETLINK_V0;
        nfmsg->res_id = htons(NFNL_SUBSYS_NFTABLES); /* sub_sys_id */
    }
}

static void init_req(bool is_ipset, bool v4) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    nlmsg->nlmsg_len = NLMSG_HDRLEN;
    nlmsg->nlmsg_flags = NLM_F_REQUEST;
    nlmsg->nlmsg_pid = s_portid; /* sender port-id */

    if (is_ipset)
        init_req_ipset(v4);
    else
        init_req_nftset(v4);

    comlen(v4) = nlmsg->nlmsg_len;
}

void ipset_init(void) {
    /*
      for the netfilter module, req_nlmsg is always processed synchronously in the context of the sendmsg system call,
        and the res_nlmsg is placed in the sender's receive queue before sendmsg returns.
    */
    s_sock = nl_sock_create(NETLINK_NETFILTER, &s_portid);

    if (!strchr(g_ipset_name4, '@') && !strchr(g_ipset_name6, '@')) {
        start_req = start_req_ipset;
        add_req_ip = add_req_ip_ipset;
        end_req = end_req_ipset;
        test_result = test_result_ipset;
        set_msghdr = set_msghdr_ipset;
        init_req(true, true);
        init_req(true, false);
    } else {
        start_req = start_req_nftset;
        add_req_ip = add_req_ip_nftset;
        end_req = end_req_nftset;
        test_result = test_result_nftset;
        set_msghdr = set_msghdr_nftset;
        init_req(false, true);
        init_req(false, false);
        init_batch_msg();
    }
}

static void start_req_ipset(bool v4, bool cmd_test) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    nlmsg->nlmsg_len = comlen(v4);
    nlmsg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | (cmd_test ? IPSET_CMD_TEST : IPSET_CMD_ADD);
    nlmsg->nlmsg_seq = s_msgseq++;

    if (!cmd_test) { // cmd_add
        nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_LINENO, &(uint32_t){0}, sizeof(uint32_t)); /* dummy lineno */
        nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_ADT);
    }
}

static void start_req_nftset(bool v4, bool cmd_test) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    nlmsg->nlmsg_len = comlen(v4);
    nlmsg->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | (cmd_test ? NFT_MSG_GETSETELEM : NFT_MSG_NEWSETELEM);
    nlmsg->nlmsg_seq = s_msgseq++;
}

static void add_req_ip_ipset(bool v4, const void *noalias ip, bool cmd_test) {
    (void)cmd_test;

    struct nlmsghdr *nlmsg = nlmsg(v4);
    uint16_t attrtype = v4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ERR_IPADDR_IPV6;
    int len = v4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;

    struct nlattr *data_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_DATA);

    struct nlattr *ip_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_IP);
    nlmsg_add_nla(nlmsg, MSGBUFSZ, attrtype|NLA_F_NET_BYTEORDER, ip, len);
    nlmsg_end_nest_nla(nlmsg, ip_nla);

    nlmsg_end_nest_nla(nlmsg, data_nla);
}

static void add_req_ip_nftset(bool v4, const void *noalias ip, bool cmd_test) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    int len = v4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;

    struct nlattr *elem_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, NFTA_LIST_ELEM);

    struct nlattr *key_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_KEY);
    nlmsg_add_nla(nlmsg, MSGBUFSZ, NFTA_DATA_VALUE|NLA_F_NET_BYTEORDER, ip, len);
    nlmsg_end_nest_nla(nlmsg, key_nla);

    nlmsg_end_nest_nla(nlmsg, elem_nla);

    if (!cmd_test) { // cmd_add
        ubyte ip_end[IPV6_BINADDR_LEN];
        memcpy(ip_end, ip, len);

        // [ip, ip_end)
        for (int i = len - 1; i >= 0; --i) {
            ubyte old = ip_end[i];
            if (++ip_end[i] > old) break;
        }

        struct nlattr *elem_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, NFTA_LIST_ELEM);

        struct nlattr *key_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_KEY);
        nlmsg_add_nla(nlmsg, MSGBUFSZ, NFTA_DATA_VALUE|NLA_F_NET_BYTEORDER, ip_end, len);
        nlmsg_end_nest_nla(nlmsg, key_nla);

        uint32_t flags = htonl(NFT_SET_ELEM_INTERVAL_END);
        nlmsg_add_nla(nlmsg, MSGBUFSZ, NFTA_SET_ELEM_FLAGS, &flags, sizeof(flags));

        nlmsg_end_nest_nla(nlmsg, elem_nla);
    }
}

static void end_req_ipset(bool v4, bool cmd_test) {
    if (!cmd_test) { // cmd_add
        struct nlmsghdr *nlmsg = nlmsg(v4);
        struct nlattr *adt_nla = (void *)nlmsg + comlen(v4) + NLA_HDRLEN + NLA_ALIGN(sizeof(uint32_t));
        nlmsg_end_nest_nla(nlmsg, adt_nla);
    }
}

static void end_req_nftset(bool v4, bool cmd_test) {
    (void)cmd_test;
    struct nlmsghdr *nlmsg = nlmsg(v4);
    struct nlattr *elems_nla = (void *)nlmsg + comlen(v4) - NLA_HDRLEN;
    nlmsg_end_nest_nla(nlmsg, elems_nla);
}

static bool test_result_ipset(bool v4, const struct nlmsghdr *noalias res_nlmsg) {
    int errcode = nlmsg_errcode(res_nlmsg);
    assert(errcode);
    if (errcode != IPSET_ERR_EXIST)
        LOGE("error when querying v%c ip: (%d) %s", v4 ? '4' : '6', errcode, ipset_strerror(errcode));
    return false;
}

static bool test_result_nftset(bool v4, const struct nlmsghdr *noalias res_nlmsg) {
    if (res_nlmsg->nlmsg_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM))
        return true;
    int errcode = nlmsg_errcode(res_nlmsg);
    assert(errcode);
    if (errcode != ENOENT) /* ENOENT: table not exists; set not exists; elem not exists */
        LOGE("error when query v%c ip: (%d) %s", v4 ? '4' : '6', errcode, strerror(errcode));
    return false;
}

bool ipset_test(const void *noalias ip, bool v4) {
    start_req(v4, true);
    add_req_ip(v4, ip, true);
    end_req(v4, true);

    struct iovec iov[1];
    struct mmsghdr mmsgv[1];

    struct nlmsghdr *req_nlmsg = nlmsg(v4);
    simple_msghdr(&mmsgv[0].msg_hdr, &iov[0], req_nlmsg, req_nlmsg->nlmsg_len);

    unlikely_if (sendall(sendmmsg, s_sock, mmsgv, array_n(mmsgv), 0) != 1) {
        LOGE("failed to send v%c nlmsg: (%d) %s", v4 ? '4' : '6', errno, strerror(errno));
        return false;
    }

    const struct nlmsghdr *res_nlmsg = s_resbuf1;
    simple_msghdr(&mmsgv[0].msg_hdr, &iov[0], s_resbuf1, MSGBUFSZ);
 
    /* up to one message */
    unlikely_if (recvmmsg(s_sock, mmsgv, array_n(mmsgv), MSG_DONTWAIT, NULL) != 1) {
        likely_if (errno == EAGAIN || errno == EWOULDBLOCK) return true; /* no error msg */
        LOGE("failed to recv v%c nlmsg: (%d) %s", v4 ? '4' : '6', errno, strerror(errno));
        return false;
    }

    return test_result(v4, res_nlmsg);
}

#define is_dirty(v4) \
    ((v4) ? s_dirty4 : s_dirty6)

#define set_dirty(v4, dirty) \
    (*((v4) ? &s_dirty4 : &s_dirty6) = (dirty))

/* cmd_add (max_size) */
#define req_ip_maxsize() ( \
    NLA_HDRLEN +                               /* elem_nla(start) */ \
    NLA_HDRLEN +                               /* key_nla(start)  */ \
    NLA_HDRLEN + NLA_ALIGN(IPV6_BINADDR_LEN) + /* data_nla(start) */ \
    NLA_HDRLEN +                               /* elem_nla(end)   */ \
    NLA_HDRLEN +                               /* key_nla(end)    */ \
    NLA_HDRLEN + NLA_ALIGN(IPV6_BINADDR_LEN) + /* data_nla(end)   */ \
    NLA_HDRLEN + NLA_ALIGN(sizeof(uint32_t))   /* flags_nla(end)  */ \
)

static bool try_end_add(bool v4) {
    unlikely_if (!nlmsg_space_ok(nlmsg(v4), MSGBUFSZ, req_ip_maxsize())) {
        ipset_end_add();
        return true;
    }
    return false;
}

void ipset_add(const void *noalias ip, bool v4) {
    if (!is_dirty(v4) || try_end_add(v4)) {
        set_dirty(v4, true);
        start_req(v4, false);
    }
    add_req_ip(v4, ip, false);
}

static void set_msghdr_ipset(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int i) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    simple_msghdr(&mmsgv[i].msg_hdr, &iov[i], nlmsg, nlmsg->nlmsg_len);
}

static void set_msghdr_nftset(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int i) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    iov[i*3].iov_base = s_batch_begin;
    iov[i*3].iov_len = cast(struct nlmsghdr *, s_batch_begin)->nlmsg_len;
    iov[i*3+1].iov_base = nlmsg;
    iov[i*3+1].iov_len = nlmsg->nlmsg_len;
    iov[i*3+2].iov_base = s_batch_end;
    iov[i*3+2].iov_len = cast(struct nlmsghdr *, s_batch_end)->nlmsg_len;
    simple_msghdr_iov(&mmsgv[i].msg_hdr, &iov[i*3], 3);
}

static bool end_add(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int *noalias n) {
    if (is_dirty(v4)) {
        set_dirty(v4, false);
        end_req(v4, false);
        set_msghdr(v4, mmsgv, iov, (*n)++);
        return true;
    }
    return false;
}

void ipset_end_add(void) {
    struct mmsghdr mmsgv[2]; /* v4 and v6 */
    struct iovec iov[6]; /* each msg consume one （nft need 3 iov) */

    /*
      current dns servers do not carry both A and AAAA answers, but they may in the future.
      see: https://datatracker.ietf.org/doc/html/draft-vavrusa-dnsop-aaaa-for-free-00
    */
    int n = 0;
    bool has_v4 = end_add(true, mmsgv, iov, &n);
    bool has_v6 = end_add(false, mmsgv, iov, &n);
    if (n <= 0) return;

    int n_sent = sendall(sendmmsg, s_sock, mmsgv, n, 0);
    assert(n_sent != 0);
    unlikely_if (n_sent != n) { /* some failed */
        LOGE("failed to send nlmsg: n_sent:%d != n:%d; errno:%d %s", n_sent, n, errno, strerror(errno));
        if (n_sent < 0) return; /* all failed */
        assert(n == 2);
        assert(n_sent == 1);
        has_v6 = false;
    }

    LOGI("has_v4:%d v4_seq:%lu", has_v4, (ulong)nlmsg(true)->nlmsg_seq);
    LOGI("has_v6:%d v6_seq:%lu", has_v6, (ulong)nlmsg(false)->nlmsg_seq);

    simple_msghdr(&mmsgv[0].msg_hdr, &iov[0], s_resbuf1, MSGBUFSZ);
    simple_msghdr(&mmsgv[1].msg_hdr, &iov[1], s_resbuf2, MSGBUFSZ);

    /* recv nlmsgerr(ack), up to 2 */
    int n_recv = recvmmsg(s_sock, mmsgv, array_n(mmsgv), MSG_DONTWAIT, NULL);
    assert(n_recv != 0);
    likely_if (n_recv < 0) {
        unlikely_if (errno != EAGAIN && errno != EWOULDBLOCK)
            LOGE("failed to recv nlmsg: errno:%d %s", errno, strerror(errno));
        return;
    }

    for (int i = 0; i < n_recv; ++i) {
        const struct nlmsghdr *res_nlmsg = iov[i].iov_base;
        int errcode = nlmsg_errcode(res_nlmsg);
        if (has_v4 && res_nlmsg->nlmsg_seq == nlmsg(true)->nlmsg_seq)
            LOGE("error when adding v4 ip: (%d) %s", errcode, ipset_strerror(errcode));
        else if (has_v6 && res_nlmsg->nlmsg_seq == nlmsg(false)->nlmsg_seq)
            LOGE("error when adding v6 ip: (%d) %s", errcode, ipset_strerror(errcode));
        else
            LOGE("unknown response: nlmsg_type:%u nlmsg_seq:%lu", (uint)res_nlmsg->nlmsg_type, (ulong)res_nlmsg->nlmsg_seq);
    }
}
