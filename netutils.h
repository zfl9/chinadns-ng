#ifndef CHINADNS_NG_NETUTILS_H
#define CHINADNS_NG_NETUTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

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

/* ipv4 binary addr typedef */
typedef uint32_t ipv4_addr_t;
/* ipv6 binary addr typedef */
typedef char ipv6_addr_t[16];

/* init netlink socket for ipset query */
void ipset_init_nlsocket(const char *ipset_name4, const char *ipset_name6);

/* check given ipaddr is exists in set */
bool ipset_addr4_is_exists(ipv4_addr_t addr);
bool ipset_addr6_is_exists(ipv6_addr_t addr);

/* create a udp socket (AF_INET) */
int new_udp4_socket(void);

/* create a udp socket (AF_INET6) */
int new_udp6_socket(void);

/* AF_INET or AF_INET6 or -1(invalid) */
int get_addrstr_family(const char *addr_string);

/* build ipv4/ipv6 address structure */
void build_ipv4_addr(struct sockaddr_in *addr, const char *host, uint16_t port);
void build_ipv6_addr(struct sockaddr_in6 *addr, const char *host, uint16_t port);

/* parse ipv4/ipv6 address structure */
void parse_ipv4_addr(const struct sockaddr_in *addr, char *host, uint16_t *port);
void parse_ipv6_addr(const struct sockaddr_in6 *addr, char *host, uint16_t *port);

#endif
