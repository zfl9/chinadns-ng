#define _GNU_SOURCE
#include "net.h"
#include "log.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

/* since linux 3.9 */
#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

int (*RECVMMSG)(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

int (*SENDMMSG)(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags);

#ifdef MUSL
static int syscall_recvmmsg(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    return syscall(SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
}
#else
#define syscall_recvmmsg recvmmsg
#endif

static int userspace_recvmmsg(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    unlikely_if (vlen <= 0 || timeout) {
        errno = EINVAL;
        return -1;
    }

    bool wait_for_one = flags & MSG_WAITFORONE;
    flags &= ~MSG_WAITFORONE;

    int nrecv = 0;

    for (uint i = 0; i < vlen; ++i) {
        ssize_t res = RECVMSG(sockfd, &msgvec[i].msg_hdr, flags);
        if (res < 0) break;

        msgvec[i].msg_len = res;
        ++nrecv;

        if (wait_for_one)
            flags |= MSG_DONTWAIT;
    }

    return nrecv ?: -1;
}

#ifdef MUSL
static int syscall_sendmmsg(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags) {
    return syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
}
#else
#define syscall_sendmmsg sendmmsg
#endif

static int userspace_sendmmsg(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags) {
    unlikely_if (vlen <= 0) {
        errno = EINVAL;
        return -1;
    }

    int nsent = 0;

    for (uint i = 0; i < vlen; ++i) {
        ssize_t res = SENDMSG(sockfd, &msgvec[i].msg_hdr, flags);
        if (res < 0) break;

        msgvec[i].msg_len = res;
        ++nsent;
    }

    return nsent ?: -1;
}

void net_init(void) {
    int res = syscall_recvmmsg(-1, NULL, 0, 0, NULL);
    assert(res == -1);
    (void)res;

    if (errno != ENOSYS) {
        RECVMMSG = (__typeof__(RECVMMSG))syscall_recvmmsg;
    } else {
        log_info("recvmmsg not implemented, use recvmsg to simulate");
        RECVMMSG = userspace_recvmmsg;
    }

    res = syscall_sendmmsg(-1, NULL, 0, 0);
    assert(res == -1);
    (void)res;

    if (errno != ENOSYS) {
        SENDMMSG = (__typeof__(SENDMMSG))syscall_sendmmsg;
    } else {
        log_info("sendmmsg not implemented, use sendmsg to simulate");
        SENDMMSG = userspace_sendmmsg;
    }
}

/* setsockopt(IPV6_V6ONLY) */
static inline void set_ipv6_only(int sockfd, int value) {
    unlikely_if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)))
        log_error("setsockopt(%d, IPV6_V6ONLY, %d): (%d) %s", sockfd, value, errno, strerror(errno));
}

/* setsockopt(SO_REUSEADDR) */
static inline void set_reuse_addr(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)))
        log_error("setsockopt(%d, SO_REUSEADDR): (%d) %s", sockfd, errno, strerror(errno));
}

/* setsockopt(SO_REUSEPORT) */
static inline void set_reuse_port(int sockfd) {
    unlikely_if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)))
        log_error("setsockopt(%d, SO_REUSEPORT): (%d) %s", sockfd, errno, strerror(errno));
}

static void setup_listen_socket(int family, int sockfd, bool reuse_port) {
    if (family == AF_INET6)
        set_ipv6_only(sockfd, 0); /* allow msg from ipv4 when binding `::` */

    set_reuse_addr(sockfd);

    if (reuse_port)
        set_reuse_port(sockfd);
}

/* create non-blocking socket */
static int new_socket(int family, int socktype, bool for_listen, bool reuse_port) {
    int sockfd = socket(family, socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); /* since Linux 2.6.27 */
    unlikely_if (sockfd < 0) {
        log_error("failed to create %s%c socket: (%d) %s", 
            socktype == SOCK_STREAM ? "tcp" : "udp",
            family == AF_INET ? '4' : '6',
            errno, strerror(errno));
        return sockfd;
    }
    if (for_listen)
        setup_listen_socket(family, sockfd, reuse_port);
    return sockfd;
}

/* create a tcp socket (v4/v6) */
int new_tcp_socket(int family, bool for_listen, bool reuse_port) {
    return new_socket(family, SOCK_STREAM, for_listen, reuse_port);
}

/* create a udp socket (v4/v6) */
int new_udp_socket(int family, bool for_listen, bool reuse_port) {
    return new_socket(family, SOCK_DGRAM, for_listen, reuse_port);
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
void skaddr_from_text(union skaddr *noalias skaddr, const char *noalias ipstr, u16 portno) {
    memset(skaddr, 0, sizeof(*skaddr));
    int family = get_ipstr_family(ipstr);
    assert(family != -1);
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
void skaddr_to_text(const union skaddr *noalias skaddr, char *noalias ipstr, u16 *noalias portno) {
    if (skaddr_is_sin(skaddr)) {
        inet_ntop(AF_INET, &skaddr->sin.sin_addr, ipstr, INET_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin.sin_port);
    } else {
        inet_ntop(AF_INET6, &skaddr->sin6.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        *portno = ntohs(skaddr->sin6.sin6_port);
    }
}

u32 epev_get_events(const void *noalias ev) {
    return cast(const struct epoll_event *, ev)->events;
}

void *epev_get_ptrdata(const void *noalias ev) {
    return cast(const struct epoll_event *, ev)->data.ptr;
}

void epev_set_events(void *noalias ev, u32 events) {
    cast(struct epoll_event *, ev)->events = events;
}

void epev_set_ptrdata(void *noalias ev, const void *ptrdata) {
    cast(struct epoll_event *, ev)->data.ptr = (void *)ptrdata;
}
