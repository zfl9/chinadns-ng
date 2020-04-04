#ifndef CHINADNS_NG_NETUTILS_H
#define CHINADNS_NG_NETUTILS_H

#define _GNU_SOURCE
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* ipset setname max len (including '\0') */
#define IPSET_MAXNAMELEN 32

/* ipv4/ipv6 address length (binary) */
#define IPV4_BINADDR_LEN 4  /* 4byte, 32bit */
#define IPV6_BINADDR_LEN 16 /* 16byte, 128bit */

/* uniform struct sockaddr_* name */
typedef struct sockaddr_in  inet4_skaddr_t;
typedef struct sockaddr_in6 inet6_skaddr_t;

/* socket port number typedef */
typedef uint16_t sock_port_t;

/* create a udp socket (AF_INET) */
int new_udp4_socket(void);

/* create a udp socket (AF_INET6) */
int new_udp6_socket(void);

/* setsockopt(IPV6_V6ONLY) */
void set_ipv6_only(int sockfd);

/* setsockopt(SO_REUSEADDR) */
void set_reuse_addr(int sockfd);

/* setsockopt(SO_REUSEPORT) */
void set_reuse_port(int sockfd);

/* create a timer fd (in seconds) */
int new_once_timerfd(time_t second);

/* AF_INET or AF_INET6 or -1(invalid) */
int get_addrstr_family(const char *addrstr);

/* build ipv4/ipv6 address structure */
void build_socket_addr(int family, void *skaddr, const char *ipstr, sock_port_t portno);

/* parse ipv4/ipv6 address structure */
void parse_socket_addr(const void *skaddr, char *ipstr, sock_port_t *portno);

/* init netlink socket for ipset query */
void ipset_init_nlsocket(void);

/* check given ipaddr is exists in ipset */
bool ipset_addr4_is_exists(const void *addr_ptr);
bool ipset_addr6_is_exists(const void *addr_ptr);

#endif
