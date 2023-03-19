#define _GNU_SOURCE
#include "nl.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int      s_sock  = -1;
static uint32_t s_seq   = 0;
static uint32_t s_pid   = 0; // sender port-id

void nl_init(void) {
    if (s_sock >= 0) return;

    s_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    unlikely_if (s_sock < 0) {
        LOGE("failed to create netlink socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    s_pid = getpid();

    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = s_pid, .nl_groups = 0};
    unlikely_if (bind(s_sock, (void *)&self_addr, sizeof(self_addr))) {
        LOGE("failed to bind address to socket: (%d) %s", errno, strerror(errno));
        exit(errno);
    }

    struct sockaddr_nl kernel_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    unlikely_if (connect(s_sock, (void *)&kernel_addr, sizeof(kernel_addr))) {
        LOGE("failed to connect to kernel: (%d) %s", errno, strerror(errno));
        exit(errno);
    }
}

bool nlmsg_send(struct nlmsghdr *noalias nlmsg) {
    nlmsg->nlmsg_seq = s_seq++;
    nlmsg->nlmsg_pid = s_pid;
    unlikely_if (send(s_sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
        LOGE("failed to send nlmsg: (%d) %s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool nlmsg_recv(void *noalias buf, ssize_t *noalias sz) {
    *sz = recv(s_sock, buf, *sz, 0);
    unlikely_if (*sz < 0) {
        LOGE("failed to recv nlmsg: (%d) %s", errno, strerror(errno));
        return false;
    }
    return true;
}
