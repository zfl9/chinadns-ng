#define _GNU_SOURCE
#include "netutils.h"
#include "logutils.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* netfilter and ipset constants definition */
#define NFNETLINK_V0 0
#define NFNL_SUBSYS_IPSET 6
#define IPSET_MAXNAMELEN 32
#define IPSET_CMD_TEST 11
#define IPSET_PROTOCOL 7
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2

/* netfilter's general netlink message structure */
struct nfgenmsg {
    __u8    nfgen_family;   /* AF_xxx */
    __u8    version;        /* nfnetlink version */
    __be16  res_id;         /* resource id */
};

#define MSGBUFFER_MAXLEN 512

/* static global variable declaration */
static int          g_ipset_socket = -1;
static __u32        g_ipset_nlmsg_seq = 0;
static char         g_ipset_setname4[IPSET_MAXNAMELEN] = {0};
static char         g_ipset_setname6[IPSET_MAXNAMELEN] = {0};
static char         g_ipset_sendbuffer4[MSGBUFFER_MAXLEN] = {0};
static char         g_ipset_sendbuffer6[MSGBUFFER_MAXLEN] = {0};
static char         g_ipset_recvbuffer[MSGBUFFER_MAXLEN] = {0};
static ipv4_addr_t *g_ipset_ipv4addr_ptr = NULL;
static ipv6_addr_t *g_ipset_ipv6addr_ptr = NULL;
static __u32       *g_ipset_nlmsg4_seq_ptr = NULL;
static __u32       *g_ipset_nlmsg6_seq_ptr = NULL;

/* create a udp socket (AF_INET) */
int new_udp4_socket(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        LOGERR("[new_udp4_socket] socket(AF_INET, SOCK_DGRAM): (%d) %s", errno, strerror(errno));
        exit(errno);
    }
    return sockfd;
}

/* create a udp socket (AF_INET6) */
int new_udp6_socket(void) {
    int sockfd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        LOGERR("[new_udp6_socket] socket(AF_INET6, SOCK_DGRAM): (%d) %s", errno, strerror(errno));
        exit(errno);
    }
    return sockfd;
}

/* AF_INET or AF_INET6 or -1(invalid) */
int get_addrstr_family(const char *addrstr) {
    if (!addrstr || strlen(addrstr) == 0) {
        return -1;
    }
    ipv6_addr_t addrbin;
    if (inet_pton(AF_INET, addrstr, &addrbin) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, addrstr, &addrbin) == 1) {
        return AF_INET6;
    } else {
        return -1;
    }
}

/* build ipv4/ipv6 address structure */
void build_ipv4_addr(struct sockaddr_in *addr, const char *host, uint16_t port) {
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, host, &addr->sin_addr);
    addr->sin_port = htons(port);
}

void build_ipv6_addr(struct sockaddr_in6 *addr, const char *host, uint16_t port) {
    addr->sin6_family = AF_INET6;
    inet_pton(AF_INET6, host, &addr->sin6_addr);
    addr->sin6_port = htons(port);
}

/* parse ipv4/ipv6 address structure */
void parse_ipv4_addr(const struct sockaddr_in *addr, char *host, uint16_t *port) {
	inet_ntop(AF_INET, &addr->sin_addr, host, INET_ADDRSTRLEN);
    *port = ntohs(addr->sin_port);
}

void parse_ipv6_addr(const struct sockaddr_in6 *addr, char *host, uint16_t *port) {
	inet_ntop(AF_INET6, &addr->sin6_addr, host, INET6_ADDRSTRLEN);
    *port = ntohs(addr->sin6_port);
}

/* create netlink socket */
static void ipset_create_nlsocket(void) {
    // create netlink socket
    g_ipset_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    if (g_ipset_socket < 0) {
        LOGERR("[ipset_create_nlsocket] failed to create netlink socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    // bind netlink address
    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = getpid(), .nl_groups = 0};
    if (bind(g_ipset_socket, (void *)&self_addr, sizeof(self_addr))) {
        LOGERR("[ipset_create_nlsocket] failed to bind address to socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    // connect to kernel
    struct sockaddr_nl dest_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    if (connect(g_ipset_socket, (void *)&dest_addr, sizeof(dest_addr))) {
        LOGERR("[ipset_create_nlsocket] failed to connect to kernel: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
}

/* prebuild nlmsg for ipset query */
static void ipset_prebuild_nlmsg(bool is_ipv4) {
    void *buffer = is_ipv4 ? g_ipset_sendbuffer4 : g_ipset_sendbuffer6;
    const char *setname = is_ipv4 ? g_ipset_setname4 : g_ipset_setname6;
    size_t setnamelen = strlen(setname) + 1;

    /* netlink msg */
    struct nlmsghdr *netlink_msg = buffer;
    netlink_msg->nlmsg_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
    netlink_msg->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST;
    netlink_msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    netlink_msg->nlmsg_seq = g_ipset_nlmsg_seq; // should be incremented
    if (is_ipv4) g_ipset_nlmsg4_seq_ptr = &netlink_msg->nlmsg_seq; // ptr for store ipv4 nlmsg seq
    if (!is_ipv4) g_ipset_nlmsg6_seq_ptr = &netlink_msg->nlmsg_seq; // ptr for store ipv6 nlmsg seq
    netlink_msg->nlmsg_pid = getpid();

    /* netfilter msg */
    struct nfgenmsg *netfilter_msg = buffer + netlink_msg->nlmsg_len;
    netfilter_msg->nfgen_family = is_ipv4 ? AF_INET : AF_INET6;
    netfilter_msg->version = NFNETLINK_V0;
    netfilter_msg->res_id = htons(0);
    netlink_msg->nlmsg_len += NLMSG_ALIGN(sizeof(struct nfgenmsg)); // update netlink msglen

    /* ipset_protocol attr */
    struct nlattr *ipset_protocol_attr = buffer + netlink_msg->nlmsg_len;
    ipset_protocol_attr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + sizeof(uint8_t);
    ipset_protocol_attr->nla_type = IPSET_ATTR_PROTOCOL;
    *(uint8_t *)((void *)ipset_protocol_attr + NLMSG_ALIGN(sizeof(struct nlattr))) = IPSET_PROTOCOL;
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
    ipset_ip_attr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + (is_ipv4 ? sizeof(ipv4_addr_t) : sizeof(ipv6_addr_t));
    ipset_ip_attr->nla_type = (is_ipv4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER;
    if (is_ipv4) g_ipset_ipv4addr_ptr = (void *)&ipset_ip_attr->nla_type + sizeof(ipset_ip_attr->nla_type); // ptr for store ipv4 addr
    if (!is_ipv4) g_ipset_ipv6addr_ptr = (void *)&ipset_ip_attr->nla_type + sizeof(ipset_ip_attr->nla_type); // ptr for store ipv6 addr
    ipset_ip_nestedattr->nla_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update ipset_ip attrlen
    ipset_data_nestedattr->nla_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update ipset_data attrlen
    netlink_msg->nlmsg_len += NLMSG_ALIGN(ipset_ip_attr->nla_len); // update netlink msglen
}

/* init netlink socket for ipset query */
void ipset_init_nlsocket(const char *ipset_name4, const char *ipset_name6) {
    strcpy(g_ipset_setname4, ipset_name4);
    strcpy(g_ipset_setname6, ipset_name6);
    ipset_create_nlsocket();
    ipset_prebuild_nlmsg(true);
    ipset_prebuild_nlmsg(false);
}

/* check given ipaddr is exists in set */
bool ipset_addr4_is_exists(ipv4_addr_t addr) {
    *g_ipset_ipv4addr_ptr = addr;
    if (send(g_ipset_socket, g_ipset_sendbuffer4, ((struct nlmsghdr *)g_ipset_sendbuffer4)->nlmsg_len, 0) < 0) {
        LOGERR("[ipset_addr4_is_exists] failed to send netlink msg to kernel: (%d) %s", errno, strerror(errno));
        return false;
    }
    *g_ipset_nlmsg4_seq_ptr = ++g_ipset_nlmsg_seq;

    if (recv(g_ipset_socket, g_ipset_recvbuffer, MSGBUFFER_MAXLEN, 0) < 0) {
        LOGERR("[ipset_addr4_is_exists] failed to recv netlink msg from kernel: (%d) %s", errno, strerror(errno));
        return false;
    }
    struct nlmsgerr *netlink_errmsg = NLMSG_DATA(g_ipset_recvbuffer);
    return netlink_errmsg->error == 0 ? true : false;
}

bool ipset_addr6_is_exists(ipv6_addr_t addr) {
    memcpy(g_ipset_ipv6addr_ptr, addr, sizeof(ipv6_addr_t));
    if (send(g_ipset_socket, g_ipset_sendbuffer6, ((struct nlmsghdr *)g_ipset_sendbuffer6)->nlmsg_len, 0) < 0) {
        LOGERR("[ipset_addr6_is_exists] failed to send netlink msg to kernel: (%d) %s", errno, strerror(errno));
        return false;
    }
    *g_ipset_nlmsg6_seq_ptr = ++g_ipset_nlmsg_seq;

    if (recv(g_ipset_socket, g_ipset_recvbuffer, MSGBUFFER_MAXLEN, 0) < 0) {
        LOGERR("[ipset_addr6_is_exists] failed to recv netlink msg from kernel: (%d) %s", errno, strerror(errno));
        return false;
    }
    struct nlmsgerr *netlink_errmsg = NLMSG_DATA(g_ipset_recvbuffer);
    return netlink_errmsg->error == 0 ? true : false;
}
