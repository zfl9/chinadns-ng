#pragma once

#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* ipv4/ipv6 address length (binary) */
#define IPV4_BINADDR_LEN 4  /* 4byte, 32bit */
#define IPV6_BINADDR_LEN 16 /* 16byte, 128bit */

typedef union skaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
} skaddr_u;

#define skaddr_family(p) ((p)->sa.sa_family)
#define skaddr_is_sin(p) (skaddr_family(p) == AF_INET)
#define skaddr_is_sin6(p) (skaddr_family(p) == AF_INET6)
#define skaddr_size(p) (skaddr_is_sin(p) ? sizeof((p)->sin) : sizeof((p)->sin6))

/* socket port number typedef */
typedef uint16_t portno_t;

/* setsockopt(SO_REUSEPORT) */
void set_reuse_port(int sockfd);

/* create a udp socket (v4/v6) */
int new_udp_socket(int family);

/* AF_INET or AF_INET6 or -1(invalid) */
int get_ipstr_family(const char *ipstr);

/* build ipv4/ipv6 address structure */
void build_socket_addr(int family, skaddr_u *restrict skaddr, const char *restrict ipstr, portno_t portno);

/* parse ipv4/ipv6 address structure */
void parse_socket_addr(const skaddr_u *restrict skaddr, char *restrict ipstr, portno_t *restrict portno);

/* init netlink socket for ipset query */
void ipset_init_nlsocket(void);

/* check given ipaddr is exists in ipset */
bool ipset_addr_is_exists(const void *restrict addr_ptr, bool is_ipv4);
