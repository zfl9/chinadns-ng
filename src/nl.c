#define _GNU_SOURCE
#include "nl.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

int nl_sock_create(int protocol, u32 *noalias src_portid) {
    const char *err_op;

    int sock = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, protocol);
    unlikely_if (sock < 0) {
        err_op = "create_socket";
        goto err;
    }

    struct sockaddr_nl self_addr = {.nl_family = AF_NETLINK, .nl_pid = 0 /* random by kernel */, .nl_groups = 0};
    unlikely_if (bind(sock, (void *)&self_addr, sizeof(self_addr))) {
        err_op = "bind_address";
        goto err;
    }

    /* get bound port-id */
    unlikely_if (getsockname(sock, (void *)&self_addr, &(socklen_t){sizeof(self_addr)})) {
        err_op = "get_bound_address";
        goto err;
    }

    struct sockaddr_nl kernel_addr = {.nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0};
    unlikely_if (connect(sock, (void *)&kernel_addr, sizeof(kernel_addr))) {
        err_op = "connect_to_kernel";
        goto err;
    }

    *src_portid = self_addr.nl_pid;
    return sock;

err:
    log_error("%s(sock:%d, protocol:%d) failed: (%d) %m", err_op, sock, protocol, errno);
    exit(errno);
}
