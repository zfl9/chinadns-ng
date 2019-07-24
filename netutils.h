#ifndef CHINADNS_NG_NETUTILS_H
#define CHINADNS_NG_NETUTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* ipset setname max len (including '\0') */
#define IPSET_MAXNAMELEN 32

/* ipv4 binary addr typedef */
typedef uint32_t ipv4_addr_t;

/* ipv6 binary addr typedef */
typedef char ipv6_addr_t[16];

/* create a udp socket (AF_INET) */
int new_udp4_socket(void);

/* create a udp socket (AF_INET6) */
int new_udp6_socket(void);

/* AF_INET or AF_INET6 or -1(invalid) */
int get_addrstr_family(const char *addrstr);

/* build ipv4/ipv6 address structure */
void build_ipv4_addr(struct sockaddr_in *addr, const char *host, uint16_t port);
void build_ipv6_addr(struct sockaddr_in6 *addr, const char *host, uint16_t port);

/* parse ipv4/ipv6 address structure */
void parse_ipv4_addr(const struct sockaddr_in *addr, char *host, uint16_t *port);
void parse_ipv6_addr(const struct sockaddr_in6 *addr, char *host, uint16_t *port);

/* init netlink socket for ipset query */
void ipset_init_nlsocket(const char *ipset_name4, const char *ipset_name6);

/* check given ipaddr is exists in ipset */
bool ipset_addr4_is_exists(ipv4_addr_t addr);
bool ipset_addr6_is_exists(const ipv6_addr_t addr);

#endif
