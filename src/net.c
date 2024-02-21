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
