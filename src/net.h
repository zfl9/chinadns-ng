#pragma once

#include "misc.h"
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/epoll.h>

/* ipv4/ipv6 address length (binary) */
#define IPV4_LEN 4  /* 4byte, 32bit */
#define IPV6_LEN 16 /* 16byte, 128bit */

/* https://git.musl-libc.org/cgit/musl/tree/src/network/sendmmsg.c */
/* https://man7.org/linux/man-pages/man2/sendmsg.2.html */
#ifdef MUSL
typedef struct MSGHDR {
    void         *msg_name;       /* Optional address */
    socklen_t     msg_namelen;    /* Size of address */
    struct iovec *msg_iov;        /* Scatter/gather array */
    size_t        msg_iovlen;     /* # elements in msg_iov */
    void         *msg_control;    /* Ancillary data, see below */
    size_t        msg_controllen; /* Ancillary data buffer len */
    int           msg_flags;      /* Flags (unused) */
} MSGHDR;
typedef struct MMSGHDR {
    struct MSGHDR msg_hdr;  /* Message header */
    unsigned int  msg_len;  /* return value of recvmsg/sendmsg */
} MMSGHDR;
#else
typedef struct msghdr MSGHDR;
typedef struct mmsghdr MMSGHDR;
#endif

#ifdef MUSL
static inline ssize_t RECVMSG(int sockfd, MSGHDR *msg, int flags) {
    return syscall(SYS_recvmsg, sockfd, msg, flags);
}
static inline ssize_t SENDMSG(int sockfd, const MSGHDR *msg, int flags) {
    return syscall(SYS_sendmsg, sockfd, msg, flags);
}
#else
#define RECVMSG recvmsg
#define SENDMSG sendmsg
#endif

/* compatible with old kernel (runtime) */
extern int (*RECVMMSG)(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

/* compatible with old kernel (runtime) */
extern int (*SENDMMSG)(int sockfd, MMSGHDR *msgvec, unsigned int vlen, int flags);

void net_init(void);

u32 epev_get_events(const void *noalias ev);
void *epev_get_ptrdata(const void *noalias ev);

void epev_set_events(void *noalias ev, u32 events);
void epev_set_ptrdata(void *noalias ev, const void *ptrdata);

#define set_iov(iov, buf, sz) ({ \
    (iov)->iov_base = (buf); \
    (iov)->iov_len = (sz); \
})

#define set_MSGHDR(msg, iov, iovlen, name, namelen) ({ \
    STATIC_ASSERT(__builtin_types_compatible_p(MSGHDR *, __typeof__(msg))); \
    (msg)->msg_name = (name); \
    (msg)->msg_namelen = (namelen); \
    (msg)->msg_iov = (iov); \
    (msg)->msg_iovlen = (iovlen); \
    (msg)->msg_control = NULL; \
    (msg)->msg_controllen = 0; \
    (msg)->msg_flags = 0; /* set by recvmsg() | ignored by sendmsg() */ \
})
