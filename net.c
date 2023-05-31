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

int (*x_recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

int (*x_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);

static int my_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    unlikely_if (vlen <= 0 || timeout) {
        errno = EINVAL;
        return -1;
    }

    bool wait_for_one = flags & MSG_WAITFORONE;
    flags &= ~MSG_WAITFORONE;

    int nrecv = 0;

    for (uint i = 0; i < vlen; ++i) {
        ssize_t res = recvmsg(sockfd, &msgvec[i].msg_hdr, flags);
        if (res < 0) break;

        msgvec[i].msg_len = res;
        ++nrecv;

        if (wait_for_one)
            flags |= MSG_DONTWAIT;
    }

    return nrecv ?: -1;
}

static int my_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    unlikely_if (vlen <= 0) {
        errno = EINVAL;
        return -1;
    }

    int nsent = 0;

    for (uint i = 0; i < vlen; ++i) {
        ssize_t res = sendmsg(sockfd, &msgvec[i].msg_hdr, flags);
        if (res < 0) break;

        msgvec[i].msg_len = res;
        ++nsent;
    }

    return nsent ?: -1;
}

void net_init(void) {
    int res = recvmmsg(-1, NULL, 0, 0, NULL);
    assert(res == -1);
    (void)res;

    if (errno != ENOSYS) {
        x_recvmmsg = (__typeof__(x_recvmmsg))recvmmsg;
    } else {
        log_info("recvmmsg not implemented, use recvmsg to simulate");
        x_recvmmsg = my_recvmmsg;
    }

    res = sendmmsg(-1, NULL, 0, 0);
    assert(res == -1);
    (void)res;

    if (errno != ENOSYS) {
        x_sendmmsg = (__typeof__(x_sendmmsg))sendmmsg;
    } else {
        log_info("sendmmsg not implemented, use sendmsg to simulate");
        x_sendmmsg = my_sendmmsg;
    }
}

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
int new_udp_socket(int family, bool for_bind) {
    int sockfd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0); /* since Linux 2.6.27 */
    unlikely_if (sockfd < 0) {
        log_error("failed to create udp%c socket: (%d) %s", family == AF_INET ? '4' : '6', errno, strerror(errno));
        exit(errno);
    }
    if (for_bind) {
        if (family == AF_INET6) set_ipv6_only(sockfd);
        set_reuse_addr(sockfd);
    }
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
