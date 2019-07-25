#define _GNU_SOURCE
#include "logutils.h"
#include "netutils.h"
#include "dnsutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

int main() {
    printf("hello, world!\n");
    return 0;
}
