#define _GNU_SOURCE
#include "nl.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

int nl_sock_create(int protocol, u32 *noalias src_portid) {
    int sock = socket(AF_NETLINK, SOCK_DGRAM, protocol);
    unlikely_if (sock < 0) {
        log_error("failed to create socket. protocol:%d errno:%d %s", protocol, errno, strerror(errno));
        exit(errno);
    }

    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = 0 /* random by kernel */, .nl_groups = 0};
    unlikely_if (bind(sock, (void *)&self_addr, sizeof(self_addr))) {
        log_error("failed to bind address. sock:%d protocol:%d errno:%d %s", sock, protocol, errno, strerror(errno));
        exit(errno);
    }

    /* get bound port-id */
    unlikely_if (getsockname(sock, (void *)&self_addr, &(socklen_t){sizeof(self_addr)})) {
        log_error("failed to get bound addr. sock:%d protocol:%d errno:%d %s", sock, protocol, errno, strerror(errno));
        exit(errno);
    }

    struct sockaddr_nl kernel_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    unlikely_if (connect(sock, (void *)&kernel_addr, sizeof(kernel_addr))) {
        log_error("failed to connect to kernel. sock:%d protocol:%d errno:%d %s", sock, protocol, errno, strerror(errno));
        exit(errno);
    }

    *src_portid = self_addr.nl_pid;
    return sock;
}
