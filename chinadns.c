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

#define CHINADNS_VERSION "chinadns-ng v1.0.0"
#define SOCKBUFF_MAXSIZE 1024
#define UPSTREAM_MAXCOUNT 4
#define DEFAULT_BINDADDR "127.0.0.1"
#define DEFAULT_BINDPORT 65353
#define DEFAULT_SETNAME4 "chnroute"
#define DEFAULT_SETNAME6 "chnroute6"
#define DEFAULT_CHINADNS "114.114.114.114"
#define DEFAULT_TRUSTDNS "8.8.8.8"

#define BINDSOCK_INDEX -1
#define CHINADNS_INDEX1 0
#define CHINADNS_INDEX2 1
#define TRUSTDNS_INDEX1 2
#define TRUSTDNS_INDEX2 3

static const char   *g_bind_addr                             = DEFAULT_BINDADDR;
static sock_port_t   g_bind_port                             = DEFAULT_BINDPORT;
static int           g_local_socket                          = -1;
static int           g_remote_socket[UPSTREAM_MAXCOUNT]      = {-1, -1, -1, -1};
static const char   *g_remote_socket_name[UPSTREAM_MAXCOUNT] = {DEFAULT_CHINADNS, "", DEFAULT_TRUSTDNS, ""};
static char          g_socket_buffer[SOCKBUFF_MAXSIZE]       = {0};

int main() {
    printf("hello, world!\n");
    return 0;
}
