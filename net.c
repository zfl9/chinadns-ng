#define _GNU_SOURCE
#include "net.h"
#include "log.h"
#include "opt.h"
#include "misc.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* since linux 3.9 */
#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

/* netfilter and ipset constants definition */
#define NFNETLINK_V0 0
#define NFNL_SUBSYS_IPSET 6
#define IPSET_CMD_TEST 11
#define IPSET_PROTOCOL 6
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

/* ipset error code constants definition */
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

/* netfilter's general netlink message structure */
struct nfgenmsg {
    __u8    nfgen_family;   /* AF_xxx */
    __u8    version;        /* nfnetlink version */
    __be16  res_id;         /* resource id */
};

/* ipset netlink msg buffer maxlen */
#define MSGBUFFER_MAXLEN 256

/* static global variable declaration */
static int     s_ipset_nlsocket        = -1;
static __u32   s_ipset_nlmsg_seq       = 0;
static void   *s_ipset_sendbuffer4     = (char [MSGBUFFER_MAXLEN]){0};
static void   *s_ipset_sendbuffer6     = (char [MSGBUFFER_MAXLEN]){0};
static void   *s_ipset_recvbuffer      = (char [MSGBUFFER_MAXLEN]){0};
static void   *s_ipset_ipv4addr_ptr    = NULL;
static void   *s_ipset_ipv6addr_ptr    = NULL;
static __u32  *s_ipset_nlmsg4_seq_ptr  = NULL;
static __u32  *s_ipset_nlmsg6_seq_ptr  = NULL;

/* setsockopt(IPV6_V6ONLY) */
static inline void set_ipv6_only(int sockfd) {
    unlikely_if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int))) {
        LOGE("setsockopt(%d, IPV6_V6ONLY): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEADDR) */
static inline void set_reuse_addr(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) {
        LOGE("setsockopt(%d, SO_REUSEADDR): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEPORT) */
void set_reuse_port(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))) {
        LOGE("setsockopt(%d, SO_REUSEPORT): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* create a udp socket (v4/v6) */
int new_udp_socket(int family) {
    int sockfd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0); /* since Linux 2.6.27 */
    unlikely_if (sockfd < 0) {
        LOGE("failed to create udp%c socket: (%d) %s", family == AF_INET ? '4' : '6', errno, strerror(errno));
        exit(errno);
    }
    if (family == AF_INET6) set_ipv6_only(sockfd);
    set_reuse_addr(sockfd);
    return sockfd;
}

/* AF_INET or AF_INET6 or -1(invalid) */
int get_ipstr_family(const char *noalias ipstr) {
    if (!ipstr) return -1;
    char buffer[IPV6_BINADDR_LEN]; /* v4 or v6 */
    if (inet_pton(AF_INET, ipstr, buffer) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, ipstr, buffer) == 1) {
        return AF_INET6;
    } else {
        return -1;
    }
}

/* build v4/v6 address structure */
void build_socket_addr(int family, skaddr_u *noalias skaddr, const char *noalias ipstr, portno_t portno) {
    if (family == AF_INET) {
        skaddr->sin.sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &skaddr->sin.sin_addr);
        skaddr->sin.sin_port = htons(portno);
    } else {
        skaddr->sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &skaddr->sin6.sin6_addr);
        skaddr->sin6.sin6_port = htons(portno);
    }
}

/* parse v4/v6 address structure */
void parse_socket_addr(const skaddr_u *noalias skaddr, char *noalias ipstr, portno_t *noalias portno) {
    if (skaddr_is_sin(skaddr)) {
        inet_ntop(AF_INET, &skaddr->sin.sin_addr, ipstr, INET_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin.sin_port);
    } else {
        inet_ntop(AF_INET6, &skaddr->sin6.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin6.sin6_port);
    }
}

/* create ipset netlink socket */
static void ipset_create_nlsocket(void) {
    /* create netlink socket */
    s_ipset_nlsocket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    unlikely_if (s_ipset_nlsocket < 0) {
        LOGE("failed to create netlink socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    /* bind netlink address */
    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = getpid(), .nl_groups = 0};
    unlikely_if (bind(s_ipset_nlsocket, (void *)&self_addr, sizeof(self_addr))) {
        LOGE("failed to bind address to socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    /* connect to kernel */
    struct sockaddr_nl kernel_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    unlikely_if (connect(s_ipset_nlsocket, (void *)&kernel_addr, sizeof(kernel_addr))) {
        LOGE("failed to connect to kernel: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
}

/* prebuild nlmsg for ipset query */
static void ipset_prebuild_nlmsg(bool is_ipv4) {
    void *buffer = is_ipv4 ? s_ipset_sendbuffer4 : s_ipset_sendbuffer6;
    const char *setname = is_ipv4 ? g_ipset_setname4 : g_ipset_setname6;
    const size_t setnamelen = strlen(setname) + 1;

    /* netlink msg */
    struct nlmsghdr *netlink_msg = buffer;
    netlink_msg->nlmsg_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
    netlink_msg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST;
    netlink_msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    netlink_msg->nlmsg_pid = getpid(); /* sender port id */
    netlink_msg->nlmsg_seq = s_ipset_nlmsg_seq; // should be incremented
    *(is_ipv4 ? &s_ipset_nlmsg4_seq_ptr : &s_ipset_nlmsg6_seq_ptr) = &netlink_msg->nlmsg_seq;

    /* netfilter msg */
    struct nfgenmsg *netfilter_msg = buffer + netlink_msg->nlmsg_len;
    netfilter_msg->nfgen_family = is_ipv4 ? AF_INET : AF_INET6;
    netfilter_msg->version = NFNETLINK_V0;
    netfilter_msg->res_id = htons(0);
    netlink_msg->nlmsg_len += NLMSG_ALIGN(sizeof(struct nfgenmsg)); // update netlink msglen

    /* ipset_protocol attr */
    struct nlattr *ipset_protocol_attr = buffer + netlink_msg->nlmsg_len;
    ipset_protocol_attr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + sizeof(ubyte);
    ipset_protocol_attr->nla_type = IPSET_ATTR_PROTOCOL;
    *((ubyte *)ipset_protocol_attr + NLMSG_ALIGN(sizeof(struct nlattr))) = IPSET_PROTOCOL;
    netlink_msg->nlmsg_len += NLMSG_ALIGN(ipset_protocol_attr->nla_len); // update netlink msglen

    /* ipset_setname attr */
    struct nlattr *ipset_setname_attr = buffer + netlink_msg->nlmsg_len;
    ipset_setname_attr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + setnamelen;
    ipset_setname_attr->nla_type = IPSET_ATTR_SETNAME;
    memcpy((void *)ipset_setname_attr + NLMSG_ALIGN(sizeof(struct nlattr)), setname, setnamelen);
    netlink_msg->nlmsg_len += NLMSG_ALIGN(ipset_setname_attr->nla_len); // update netlink msglen

    /* ipset_data attr (nested) */
    struct nlattr *ipset_data_nestedattr = buffer + netlink_msg->nlmsg_len;
    ipset_data_nestedattr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr));
    ipset_data_nestedattr->nla_type = IPSET_ATTR_DATA | NLA_F_NESTED;
    netlink_msg->nlmsg_len += ipset_data_nestedattr->nla_len; // update netlink msglen

    /* ipset_ip addr (nested) */
    struct nlattr *ipset_ip_nestedattr = buffer + netlink_msg->nlmsg_len;
    ipset_ip_nestedattr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr));
    ipset_ip_nestedattr->nla_type = IPSET_ATTR_IP | NLA_F_NESTED;
    ipset_data_nestedattr->nla_len += ipset_ip_nestedattr->nla_len; // update ipset_data attrlen
    netlink_msg->nlmsg_len += ipset_ip_nestedattr->nla_len; // update netlink msglen

    /* ipset_ip attr */
    struct nlattr *ipset_ip_attr = buffer + netlink_msg->nlmsg_len;
    ipset_ip_attr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + (is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN);
    ipset_ip_attr->nla_type = (is_ipv4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER;
    *(is_ipv4 ? &s_ipset_ipv4addr_ptr : &s_ipset_ipv6addr_ptr) = (void *)ipset_ip_attr + NLMSG_ALIGN(sizeof(struct nlattr));
    ipset_ip_nestedattr->nla_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update ipset_ip attrlen
    ipset_data_nestedattr->nla_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update ipset_data attrlen
    netlink_msg->nlmsg_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update netlink msglen
}

/* init netlink socket for ipset query */
void ipset_init_nlsocket(void) {
    ipset_create_nlsocket(); /* create netlink socket */
    ipset_prebuild_nlmsg(true); /* prebuild ipv4 nlmsg */
    ipset_prebuild_nlmsg(false); /* prebuild ipv6 nlmsg */
}

#define CASE_RET_NAME(MACRO) \
    case MACRO: return #MACRO

/* get a string description of the ipset error code */
static inline const char *ipset_error_tostr(int errcode) {
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

/* check given ipaddr is exists in ipset */
bool ipset_addr_is_exists(const void *noalias addr_ptr, bool is_ipv4) {
    void *ipaddr_buf = is_ipv4 ? s_ipset_ipv4addr_ptr : s_ipset_ipv6addr_ptr;
    __u32 *msgseq_ptr = is_ipv4 ? s_ipset_nlmsg4_seq_ptr : s_ipset_nlmsg6_seq_ptr;
    const struct nlmsghdr *netlink_sendmsg = (is_ipv4 ? s_ipset_sendbuffer4 : s_ipset_sendbuffer6);

    *msgseq_ptr = s_ipset_nlmsg_seq++; /* increment nlmsg seq */
    memcpy(ipaddr_buf, addr_ptr, is_ipv4 ? IPV4_BINADDR_LEN : IPV6_BINADDR_LEN); /* replace ipv4/ipv6 addr */

    unlikely_if (send(s_ipset_nlsocket, netlink_sendmsg, netlink_sendmsg->nlmsg_len, 0) < 0) {
        LOGE("failed to send v%c addr query: (%d) %s", is_ipv4 ? '4' : '6', errno, strerror(errno));
        return false;
    }
    unlikely_if (recv(s_ipset_nlsocket, s_ipset_recvbuffer, MSGBUFFER_MAXLEN, 0) < 0) {
        LOGE("failed to recv v%c addr reply: (%d) %s", is_ipv4 ? '4' : '6', errno, strerror(errno));
        return false;
    }

    /* the payload type of the ack msg is also `struct nlmsgerr` */
    const struct nlmsgerr *res = NLMSG_DATA(s_ipset_recvbuffer);
    const int errcode = res->error;

    if (errcode == 0) { // ack
        return true; // exists
    } else if (errcode == IPSET_ERR_EXIST) {
        return false; // not exists
    } else {
        LOGE("error when querying v%c addr: (%d) %s", is_ipv4 ? '4' : '6', errcode, ipset_error_tostr(errcode));
        return false; // error occurred
    }
}
