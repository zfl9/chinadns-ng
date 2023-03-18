#define _GNU_SOURCE
#include "ipset.h"
#include "opt.h"
#include "net.h"
#include "log.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* #include <linux/netfilter/ipset/ip_set.h> */
#define NFNETLINK_V0 0
#define NFNL_SUBSYS_IPSET 6
#define IPSET_PROTOCOL 6

#define IPSET_CMD_TEST 11
#define IPSET_CMD_ADD 9

#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

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

/* #include <linux/netfilter/nfnetlink.h> */
struct nfgenmsg {
    uint8_t     nfgen_family;   /* AF_xxx */
    uint8_t     version;        /* nfnetlink version */
    uint16_t    res_id;         /* resource id */
};

#define NLMSG_BUFSZ 256 /* netlink_header + netfilter_header + nlattrs... */

static int         s_nlsocket        = -1;
static uint32_t    s_nlmsg_seq       = 0;
static void       *s_send_buffer4    = (char [NLMSG_BUFSZ]){0};
static void       *s_send_buffer6    = (char [NLMSG_BUFSZ]){0};
static void       *s_recv_buffer     = (char [NLMSG_BUFSZ]){0};
static void       *s_ipv4addr_pos    = NULL; /* point to send_buffer4 */
static void       *s_ipv6addr_pos    = NULL; /* point to send_buffer6 */

static void create_nlsocket(void) {
    /* create netlink socket */
    s_nlsocket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    unlikely_if (s_nlsocket < 0) {
        LOGE("failed to create netlink socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    /* bind netlink address */
    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = getpid(), .nl_groups = 0};
    unlikely_if (bind(s_nlsocket, (void *)&self_addr, sizeof(self_addr))) {
        LOGE("failed to bind address to socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    /* connect to kernel */
    struct sockaddr_nl kernel_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    unlikely_if (connect(s_nlsocket, (void *)&kernel_addr, sizeof(kernel_addr))) {
        LOGE("failed to connect to kernel: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
}

#define nla_data(nla) \
    ((void *)(nla) + NLA_HDRLEN)

#define calc_nla_len(datalen) \
    (NLA_HDRLEN + (datalen))

#define calc_nla_size(datalen) \
    (NLA_HDRLEN + NLA_ALIGN(datalen))

#define nlmsg_end(nlmsg) \
    ((void *)(nlmsg) + (nlmsg)->nlmsg_len)

#define inc_nlmsg_len(nlmsg, nlmsg_maxlen, datalen) ({ \
    ((nlmsg)->nlmsg_len += NLMSG_ALIGN(datalen)); \
    unlikely_if ((nlmsg)->nlmsg_len > (nlmsg_maxlen)) { \
        fprintf(stderr, "BUG: nlmsg_len:%lu > nlmsg_maxlen:%lu\n", \
            (ulong)(nlmsg)->nlmsg_len, (ulong)(nlmsg_maxlen)); \
        abort(); \
    } \
})

static struct nlattr *add_nla(struct nlmsghdr *noalias nlmsg, size_t nlmsg_maxlen,
    uint16_t attrtype, const void *noalias data, size_t datalen)
{
    struct nlattr *nla = nlmsg_end(nlmsg);
    inc_nlmsg_len(nlmsg, nlmsg_maxlen, calc_nla_size(datalen));
    nla->nla_len = calc_nla_len(datalen);
    nla->nla_type = attrtype;
    if (data) memcpy(nla_data(nla), data, datalen);
    return nla;
}

#define start_nest_nla(nlmsg, nlmsg_maxlen, attrtype) \
    add_nla(nlmsg, nlmsg_maxlen, (attrtype) | NLA_F_NESTED, NULL, 0)

#define end_nest_nla(nlmsg, container) \
    ((container)->nla_len = nlmsg_end(nlmsg) - (void *)(container))

static void prebuild_nlmsg(bool is_ipv4) {
    void *buffer = is_ipv4 ? s_send_buffer4 : s_send_buffer6;
    const char *setname = is_ipv4 ? g_ipset_setname4 : g_ipset_setname6;
    const size_t setnamelen = strlen(setname) + 1;

    /* netlink header */
    struct nlmsghdr *nlmsg = buffer;
    nlmsg->nlmsg_len = NLMSG_HDRLEN;
    nlmsg->nlmsg_type = 0; // set on request
    nlmsg->nlmsg_flags = 0; // set on request
    nlmsg->nlmsg_pid = getpid(); /* sender port id */
    nlmsg->nlmsg_seq = 0; // set on request

    /* netfilter header */
    struct nfgenmsg *nfmsg = buffer + nlmsg->nlmsg_len;
    inc_nlmsg_len(nlmsg, NLMSG_BUFSZ, sizeof(*nfmsg));
    nfmsg->nfgen_family = is_ipv4 ? AF_INET : AF_INET6;
    nfmsg->version = NFNETLINK_V0;
    nfmsg->res_id = 0;

    /* protocol */
    add_nla(nlmsg, NLMSG_BUFSZ, IPSET_ATTR_PROTOCOL, &(ubyte){IPSET_PROTOCOL}, sizeof(ubyte));

    /* setname */
    add_nla(nlmsg, NLMSG_BUFSZ, IPSET_ATTR_SETNAME, setname, setnamelen);

    /* data start */
    struct nlattr *data = start_nest_nla(nlmsg, NLMSG_BUFSZ, IPSET_ATTR_DATA);

    /* ip start */
    struct nlattr *ip = start_nest_nla(nlmsg, NLMSG_BUFSZ, IPSET_ATTR_IP);

    /* ipaddr */
    uint16_t attrtype = (is_ipv4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER;
    size_t datalen = is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;
    struct nlattr *ipaddr = add_nla(nlmsg, NLMSG_BUFSZ, attrtype, NULL, datalen);
    *(is_ipv4 ? &s_ipv4addr_pos : &s_ipv6addr_pos) = nla_data(ipaddr);

    /* ip end */
    end_nest_nla(nlmsg, ip);

    /* data end */
    end_nest_nla(nlmsg, data);
}

void ipset_init(void) {
    create_nlsocket();
    prebuild_nlmsg(true);
    prebuild_nlmsg(false);
}

bool ipset_addr_exists(const void *noalias addr, bool is_ipv4) {
    struct nlmsghdr *nlmsg = is_ipv4 ? s_send_buffer4 : s_send_buffer6;
    void *addr_pos = is_ipv4 ? s_ipv4addr_pos : s_ipv6addr_pos;
    size_t addr_sz = is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;

    nlmsg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST;
    nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlmsg->nlmsg_seq = s_nlmsg_seq++; /* increment seq */
    memcpy(addr_pos, addr, addr_sz); /* set ipv4/ipv6 addr */

    unlikely_if (send(s_nlsocket, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
        LOGE("failed to send v%c addr query: (%d) %s", is_ipv4 ? '4' : '6', errno, strerror(errno));
        return false;
    }

    // todo: check for turncated
    unlikely_if (recv(s_nlsocket, s_recv_buffer, NLMSG_BUFSZ, 0) < 0) {
        LOGE("failed to recv v%c addr reply: (%d) %s", is_ipv4 ? '4' : '6', errno, strerror(errno));
        return false;
    }

    /* the data type of the ack msg is also `struct nlmsgerr` */
    const struct nlmsgerr *res = NLMSG_DATA(s_recv_buffer);
    const int errcode = res->error;

    if (errcode == 0) { // ack
        return true; // exists
    } else if (errcode == IPSET_ERR_EXIST) {
        return false; // not exists
    } else {
        LOGE("error when querying v%c addr: (%d) %s", is_ipv4 ? '4' : '6', errcode, ipset_strerror(errcode));
        return false; // error occurred
    }
}

void ipset_addr_add(const void *noalias addr, bool is_ipv4) {
    struct nlmsghdr *nlmsg = is_ipv4 ? s_send_buffer4 : s_send_buffer6;
    void *addr_pos = is_ipv4 ? s_ipv4addr_pos : s_ipv6addr_pos;
    size_t addr_sz = is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN;

    nlmsg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
    nlmsg->nlmsg_flags = NLM_F_REQUEST;
    nlmsg->nlmsg_seq = 0; /* no response required */
    memcpy(addr_pos, addr, addr_sz); /* set ipv4/ipv6 addr */

    // todo: is it possible to add multiple ip at once ?
    unlikely_if (send(s_nlsocket, nlmsg, nlmsg->nlmsg_len, 0) < 0)
        LOGE("failed to send v%c addr query: (%d) %s", is_ipv4 ? '4' : '6', errno, strerror(errno));
}
