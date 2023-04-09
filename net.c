#define _GNU_SOURCE
#include "net.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

/* since linux 3.9 */
#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

/* setsockopt(IPV6_V6ONLY) */
static inline void set_ipv6_only(int sockfd) {
    unlikely_if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int))) {
        log_error("setsockopt(%d, IPV6_V6ONLY): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEADDR) */
static inline void set_reuse_addr(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) {
        log_error("setsockopt(%d, SO_REUSEADDR): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* setsockopt(SO_REUSEPORT) */
void set_reuse_port(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int))) {
        log_error("setsockopt(%d, SO_REUSEPORT): (%d) %s", sockfd, errno, strerror(errno));
        exit(errno);
    }
}

/* create a udp socket (v4/v6) */
int new_udp_socket(int family) {
    int sockfd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0); /* since Linux 2.6.27 */
    unlikely_if (sockfd < 0) {
        log_error("failed to create udp%c socket: (%d) %s", family == AF_INET ? '4' : '6', errno, strerror(errno));
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

/* build v4/v6 address structure (zero before calling) */
void skaddr_build(int family, union skaddr *noalias skaddr, const char *noalias ipstr, u16 portno) {
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
void skaddr_parse(const union skaddr *noalias skaddr, char *noalias ipstr, u16 *noalias portno) {
    if (skaddr_is_sin(skaddr)) {
        inet_ntop(AF_INET, &skaddr->sin.sin_addr, ipstr, INET_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin.sin_port);
    } else {
        inet_ntop(AF_INET6, &skaddr->sin6.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin6.sin6_port);
    }
}
