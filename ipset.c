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
#include <assert.h>

/* #include <linux/netfilter/ipset/ip_set.h> */
#define NFNETLINK_V0 0 /* nfgenmsg.version */

/* #include <linux/netfilter/nfnetlink.h> */
struct nfgenmsg {
    uint8_t     nfgen_family;   /* AF_xxx */
    uint8_t     version;        /* nfnetlink version */
    uint16_t    res_id;         /* resource id */
};

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

#define MSGBUFSZ NLMSG_ALIGN(512)

static int         s_sock      = -1; /* netlink socket fd */
static uint32_t    s_portid    = 0; /* local address (port-id) */
static void       *s_reqbuf4   = (char [MSGBUFSZ]){0};
static void       *s_reqbuf6   = (char [MSGBUFSZ]){0};
static void       *s_resbuf1   = (char [MSGBUFSZ]){0};
static void       *s_resbuf2   = (char [MSGBUFSZ]){0};
static uint32_t    s_comlen4   = 0; /* nlh + nfh + proto + setname */
static uint32_t    s_comlen6   = 0; /* nlh + nfh + proto + setname */
static bool        s_dirty4    = false; /* need to commit (ip_add) */
static bool        s_dirty6    = false; /* need to commit (ip_add) */

/* get req nlmsg */
#define nlmsg(v4) \
    cast(struct nlmsghdr *, (v4) ? s_reqbuf4 : s_reqbuf6)

/* common length of req nlmsg */
#define comlen(v4) \
    ((v4) ? s_comlen4 : s_comlen6)

#define pcomlen(v4) \
    ((v4) ? &s_comlen4 : &s_comlen6)

#define setname(v4) \
    ((v4) ? g_ipset_setname4 : g_ipset_setname6)

#define setnamelen(v4) \
    ((v4) ? (strlen(g_ipset_setname4) + 1) : (strlen(g_ipset_setname6) + 1))

static void prebuild_nlmsg(bool v4) {
    /* netlink header */
    struct nlmsghdr *nlmsg = nlmsg_init(nlmsg(v4), 0, NLM_F_REQUEST|NLM_F_ACK, s_portid);

    /* netfilter header */
    struct nfgenmsg *nfmsg = nlmsg_add_data(nlmsg, MSGBUFSZ, NULL, sizeof(*nfmsg));
    nfmsg->nfgen_family = v4 ? AF_INET : AF_INET6;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    /* protocol */
    nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_PROTOCOL, &(ubyte){IPSET_PROTOCOL}, sizeof(ubyte));

    /* setname */
    nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_SETNAME, setname(v4), setnamelen(v4));

    *pcomlen(v4) = nlmsg->nlmsg_len;
}

void ipset_init(void) {
    /*
      for the netfilter module, req_nlmsg is always processed synchronously in the context of the sendmsg system call,
        and the res_nlmsg is placed in the sender's receive queue before sendmsg returns.
    */
    s_sock = nl_sock_create(NETLINK_NETFILTER, &s_portid);
    prebuild_nlmsg(true);
    prebuild_nlmsg(false);
}

/* nlh | nfh | proto | setname */
#define reset_nlmsg(v4, cmd) ({ \
    nlmsg(v4)->nlmsg_len = comlen(v4); \
    nlmsg(v4)->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | (cmd); \
})

static void add_ip_nla(bool v4, const void *noalias ip) {
    struct nlmsghdr *nlmsg = nlmsg(v4);
    struct nlattr *data_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_DATA);
    struct nlattr *ip_nla = nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_IP);
    if (v4)
        nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_IPADDR_IPV4|NLA_F_NET_BYTEORDER, ip, IPV4_BINADDR_LEN);
    else
        nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_IPADDR_IPV6|NLA_F_NET_BYTEORDER, ip, IPV6_BINADDR_LEN);
    nlmsg_end_nest_nla(nlmsg, ip_nla);
    nlmsg_end_nest_nla(nlmsg, data_nla);
}

bool ipset_ip_exists(const void *noalias ip, bool v4) {
    reset_nlmsg(v4, IPSET_CMD_TEST);
    add_ip_nla(v4, ip);

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

do_recv:
    /* in most cases there will only be one response message (i.e. ack) */
    unlikely_if (recvmmsg(s_sock, mmsgv, array_n(mmsgv), MSG_DONTWAIT, NULL) != 1) {
        LOGE("failed to recv v%c nlmsg: (%d) %s", v4 ? '4' : '6', errno, strerror(errno));
        return false; /* no msg in recv queue */
    }

    /* check nlmsg_seq */
    unlikely_if (res_nlmsg->nlmsg_seq != req_nlmsg->nlmsg_seq) {
        LOGE("unknown response nlmsg: res_seq:%lu != req_seq:%lu", (ulong)res_nlmsg->nlmsg_seq, (ulong)req_nlmsg->nlmsg_seq);
        goto do_recv;
    }

    /* res_nlmsg always end with nlmsgerr(ack) */
    unlikely_if (res_nlmsg->nlmsg_type != NLMSG_ERROR) {
        LOGE("unknown response nlmsg: nlmsg_type:%u != NLMSG_ERROR:%d", (uint)res_nlmsg->nlmsg_type, NLMSG_ERROR);
        goto do_recv;
    }

    int errcode = nlmsg_errcode(res_nlmsg);
    switch (errcode) {
        case 0:
            return true; // exists
        case IPSET_ERR_EXIST:
            return false; // not exists
        default:
            LOGE("error when querying v%c ip: (%d) %s", v4 ? '4' : '6', errcode, ipset_strerror(errcode));
            return false; // error occurred
    }
}

#define is_dirty(v4) \
    ((v4) ? s_dirty4 : s_dirty6)

#define set_dirty(v4, dirty) \
    (*((v4) ? &s_dirty4 : &s_dirty6) = (dirty))

#define ip_attr_size(v4) \
    (NLA_HDRLEN /* data_nla */ + NLA_HDRLEN /* ip_nla */ + \
        NLA_HDRLEN + NLA_ALIGN((v4) ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN) /* ipattr_nla */ )

static bool commit_if_full(bool v4) {
    unlikely_if (!nlmsg_space_ok(nlmsg(v4), MSGBUFSZ, ip_attr_size(v4))) {
        ipset_ip_add_commit();
        return true;
    }
    return false;
}

void ipset_ip_add(const void *noalias ip, bool v4) {
    if (!is_dirty(v4) || commit_if_full(v4)) {
        set_dirty(v4, true);
        struct nlmsghdr *nlmsg = nlmsg(v4);
        reset_nlmsg(v4, IPSET_CMD_ADD);
        nlmsg_add_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_LINENO, &(uint32_t){0}, sizeof(uint32_t)); /* dummy lineno */
        nlmsg_add_nest_nla(nlmsg, MSGBUFSZ, IPSET_ATTR_ADT);
    }
    add_ip_nla(v4, ip);
}

#define lineno_nla_size() \
    (NLA_HDRLEN + NLA_ALIGN(sizeof(uint32_t)))

#define adt_nla(v4) \
    cast(struct nlattr *, (void *)nlmsg(v4) + comlen(v4) + lineno_nla_size())

static bool try_commit(bool v4, struct mmsghdr mmsgv[noalias], struct iovec iov[noalias], int *noalias n) {
    if (is_dirty(v4)) {
        set_dirty(v4, false);
        nlmsg_end_nest_nla(nlmsg(v4), adt_nla(v4));
        simple_msghdr(&mmsgv[*n].msg_hdr, &iov[*n], nlmsg(v4), nlmsg(v4)->nlmsg_len);
        ++*n;
        return true;
    }
    return false;
}

static bool check_ack(bool v4, const struct nlmsghdr *noalias res_nlmsg) {
    likely_if (res_nlmsg->nlmsg_type == NLMSG_ERROR) {
        int errcode = nlmsg_errcode(res_nlmsg);
        unlikely_if (errcode)
            LOGE("error when adding v%c ip: (%d) %s", v4 ? '4' : '6', errcode, ipset_strerror(errcode));
        return true;
    }
    LOGE("unknown response nlmsg: nlmsg_type:%u nlmsg_seq:%lu", (uint)res_nlmsg->nlmsg_type, (ulong)res_nlmsg->nlmsg_seq);
    return false;
}

void ipset_ip_add_commit(void) {
    struct mmsghdr mmsgv[2];
    struct iovec iov[2]; /* each msg consume one */

    /*
      current dns servers do not carry both A and AAAA answers, but they may in the future.
      see: https://datatracker.ietf.org/doc/html/draft-vavrusa-dnsop-aaaa-for-free-00
    */
    int n = 0;
    bool has_v4 = try_commit(true, mmsgv, iov, &n);
    bool has_v6 = try_commit(false, mmsgv, iov, &n);
    if (n <= 0) return;

    int n_sent = sendall(sendmmsg, s_sock, mmsgv, n, 0);
    assert(n_sent != 0);
    unlikely_if (n_sent != n) { /* not all sent */
        LOGE("failed to send nlmsg: n_sent:%d != n:%d; errno:%d %s", n_sent, n, errno, strerror(errno));
        if (n_sent < 0) return; /* all failed */
        assert(n == 2);
        assert(n_sent == 1);
        has_v6 = false;
    }

    bool v4_acked = !has_v4, v6_acked = !has_v6;
    simple_msghdr(&mmsgv[0].msg_hdr, &iov[0], s_resbuf1, MSGBUFSZ);
    simple_msghdr(&mmsgv[1].msg_hdr, &iov[1], s_resbuf2, MSGBUFSZ);

do_recv:
    /* recv nlmsgerr(ack), up to 2 */
    int n_recv = recvmmsg(s_sock, mmsgv, array_n(mmsgv), MSG_DONTWAIT, NULL);
    assert(n_recv != 0);
    unlikely_if (n_recv < 0) {
        LOGE("failed to recv nlmsg: errno:%d %s", errno, strerror(errno));
        return; /* no msg in recv queue */
    }

    for (int i = 0; i < n_recv; ++i) {
        const struct nlmsghdr *res_nlmsg = iov[i].iov_base;
        if (has_v4 && res_nlmsg->nlmsg_seq == nlmsg(true)->nlmsg_seq) {
            likely_if (!v4_acked) v4_acked = check_ack(true, res_nlmsg);
            else LOGE("v4 nlmsg acked, but response still recv. nlmsg_type:%u", (uint)res_nlmsg->nlmsg_type);
        } else if (has_v6 && res_nlmsg->nlmsg_seq == nlmsg(false)->nlmsg_seq) {
            likely_if (!v6_acked) v6_acked = check_ack(false, res_nlmsg);
            else LOGE("v6 nlmsg acked, but response still recv. nlmsg_type:%u", (uint)res_nlmsg->nlmsg_type);
        } else {
            LOGE("unknown response nlmsg: nlmsg_type:%u nlmsg_seq:%lu", (uint)res_nlmsg->nlmsg_type, (ulong)res_nlmsg->nlmsg_seq);
        }
    }

    if (!v4_acked || !v6_acked) {
        LOGE("v4 or v6 nlmsg not acked: v4_acked:%d v6_acked:%d (continue receiving nlmsg)", v4_acked, v6_acked);
        goto do_recv;
    }
}
