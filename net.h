#pragma once

#include "misc.h"
#include <stdint.h>
#include <netinet/in.h>
#include <assert.h>

/* "65535" (include \0) */
#define PORT_STRLEN 6

/* "ip#port" (include \0) */
#define IP_PORT_STRLEN (INET6_ADDRSTRLEN + PORT_STRLEN)

/* ipv4/ipv6 address length (binary) */
#define IPV4_BINADDR_LEN 4  /* 4byte, 32bit */
#define IPV6_BINADDR_LEN 16 /* 16byte, 128bit */

typedef union skaddr {
    struct sockaddr_in6 sin6; /* largest member as first (for zero init) */
    struct sockaddr_in sin;
    struct sockaddr sa;
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
int get_ipstr_family(const char *noalias ipstr);

/* build ipv4/ipv6 address structure */
void build_socket_addr(int family, skaddr_u *noalias skaddr, const char *noalias ipstr, portno_t portno);

/* parse ipv4/ipv6 address structure */
void parse_socket_addr(const skaddr_u *noalias skaddr, char *noalias ipstr, portno_t *noalias portno);

/* try to send all for `f(fd, base, len, args...)` (blocking send) */
#define sendall(f, fd, base, len, args...) ({ \
    __typeof__(f(fd, base, len, ##args)) nsent_ = 0; \
    __auto_type base_ = (base); \
    __typeof__(nsent_) len_ = (len); \
    assert(len_ > 0); \
    do { \
        __auto_type ret_ = retry_EINTR(f(fd, &base_[nsent_], len_ - nsent_, ##args)); \
        if (ret_ < 0) break; /* error occurs */ \
        nsent_ += ret_; \
    } while (nsent_ < len_); \
    nsent_ == 0 ? (__typeof__(nsent_))-1 : nsent_; \
})

#define simple_msghdr_iov(msg, iov, iovlen) ({ \
    (msg)->msg_name = NULL; \
    (msg)->msg_namelen = 0; \
    (msg)->msg_iov = (iov); \
    (msg)->msg_iovlen = (iovlen); \
    (msg)->msg_control = NULL; \
    (msg)->msg_controllen = 0; \
    (msg)->msg_flags = 0; /* set by recvmsg() | ignored by sendmsg() */ \
})

#define simple_msghdr(msg, iov, buf, sz) ({ \
    (iov)->iov_base = (buf); \
    (iov)->iov_len = (sz); \
    simple_msghdr_iov(msg, iov, 1); \
})
