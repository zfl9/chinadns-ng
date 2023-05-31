#pragma once

#include "misc.h"
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

/* "65535" (include \0) */
#define PORT_STRLEN 6

/* "ip#port" (include \0) */
#define IP_PORT_STRLEN (INET6_ADDRSTRLEN + PORT_STRLEN)

/* ipv4/ipv6 address length (binary) */
#define IPV4_BINADDR_LEN 4  /* 4byte, 32bit */
#define IPV6_BINADDR_LEN 16 /* 16byte, 128bit */

union skaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

#define skaddr_family(p) ((p)->sa.sa_family)
#define skaddr_is_sin(p) (skaddr_family(p) == AF_INET)
#define skaddr_is_sin6(p) (skaddr_family(p) == AF_INET6)
#define skaddr_size(p) (skaddr_is_sin(p) ? sizeof((p)->sin) : sizeof((p)->sin6))

/* compatible with old kernel (runtime) */
extern int (*x_recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

/* compatible with old kernel (runtime) */
extern int (*x_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);

void net_init(void);

void set_reuse_port(int sockfd);

int new_udp_socket(int family, bool for_bind);

int get_ipstr_family(const char *noalias ipstr);

void skaddr_build(int family, union skaddr *noalias skaddr, const char *noalias ipstr, u16 portno);

void skaddr_parse(const union skaddr *noalias skaddr, char *noalias ipstr, u16 *noalias portno);

/* try to (blocking) send all, retry if interrupted by signal */
#define sendall(f, fd, base, len, args...) ({ \
    __typeof__(f(fd, base, len, ##args)) nsent_ = 0; \
    __auto_type base_ = (base); \
    __typeof__(nsent_) len_ = (len); \
    assert(len_ > 0); \
    do { \
        __auto_type ret_ = retry_EINTR(f(fd, &base_[nsent_], len_ - nsent_, ##args)); \
        unlikely_if (ret_ < 0) break; /* error occurs */ \
        assert(ret_ != 0); \
        nsent_ += ret_; \
    } while (nsent_ < len_); \
    nsent_ == 0 ? (__typeof__(nsent_))-1 : nsent_; \
})

#define set_iov(iov, buf, sz) ({ \
    (iov)->iov_base = (buf); \
    (iov)->iov_len = (sz); \
})

#define set_msghdr(msg, iov, iovlen, name, namelen) ({ \
    (msg)->msg_name = (name); \
    (msg)->msg_namelen = (namelen); \
    (msg)->msg_iov = (iov); \
    (msg)->msg_iovlen = (iovlen); \
    (msg)->msg_control = NULL; \
    (msg)->msg_controllen = 0; \
    (msg)->msg_flags = 0; /* set by recvmsg() | ignored by sendmsg() */ \
})
