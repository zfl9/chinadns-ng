#define _GNU_SOURCE
#include "logutils.h"
#include "netutils.h"
#include "dnsutils.h"
#include "maputils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

#define CHINADNS_VERSION "chinadns-ng v1.0.0"

#define UPSTREAM_MAXCOUNT 4
#define SOCKBUFF_MAXSIZE 1024

#define BINDSOCK_INDEX -1 /* for marking only */
#define CHINADNS_INDEX1 0
#define CHINADNS_INDEX2 1
#define TRUSTDNS_INDEX1 2
#define TRUSTDNS_INDEX2 3

#define IF_VERBOSE if (g_verbose)

static bool        g_verbose                                               = false;
static bool        g_reuse_port                                            = false;
static char        g_setname4[IPSET_MAXNAMELEN]                            = "chnroute";
static char        g_setname6[IPSET_MAXNAMELEN]                            = "chnroute6";
static char        g_bind_addr[INET6_ADDRSTRLEN]                           = "127.0.0.1";
static sock_port_t g_bind_port                                             = 65353;
static int         g_local_socket                                          = -1;
static int         g_remote_sockets[UPSTREAM_MAXCOUNT]                     = {-1, -1, -1, -1};
static char        g_remote_names[UPSTREAM_MAXCOUNT][INET6_ADDRSTRLEN + 6] = {"114.114.114.114", "", "8.8.8.8", ""};
static char        g_socket_buffer[SOCKBUFF_MAXSIZE]                       = {0};
static uint16_t    g_current_message_id                                    = 1;
static hashmap_t  *g_message_id_hashmap                                    = NULL;

/* print command help information */
static void print_command_help(void) {
    printf("usage: chinadns-ng <options...>. the existing options are as follows:\n"
           " -b, --bind-addr <addr>               listen address, default: 127.0.0.1\n" 
           " -l, --bind-port <port>               listen port number, default: 65353\n"
           " -c, --china-dns <ip:port[,ip:port]>  china dns server, default: <114DNS>\n"
           " -t, --trust-dns <ip:port[,ip:port]>  trust dns server, default: <GoogleDNS>\n"
           " -4, --ipset-name4 <ipset-setname4>   ipset ipv4 set name, default: chnroute\n"
           " -6, --ipset-name6 <ipset-setname6>   ipset ipv6 set name, default: chnroute6\n"
           " -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>\n"
           " -v, --verbose                        print the verbose log, default: <disabled>\n"
           " -V, --version                        print `chinadns-ng` version number and exit\n"
           " -h, --help                           print `chinadns-ng` help information and exit\n"
           "bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)\n"
    );
}

/* parse and check command arguments */
static void parse_command_args(int argc, char *argv[]) {
    const char *optstr = ":b:l:c:t:4:6:rvVh";
    const struct option options[] = {
        {"bind-addr",   required_argument, NULL, 'b'},
        {"bind-port",   required_argument, NULL, 'l'},
        {"china-dns",   required_argument, NULL, 'c'},
        {"trust-dns",   required_argument, NULL, 't'},
        {"ipset-name4", required_argument, NULL, '4'},
        {"ipset-name6", required_argument, NULL, '6'},
        {"reuse-port",  no_argument,       NULL, 'r'},
        {"verbose",     no_argument,       NULL, 'v'},
        {"version",     no_argument,       NULL, 'V'},
        {"help",        no_argument,       NULL, 'h'},
    };
    opterr = 0;
    int optindex = -1;
    int shortopt = -1;
    char *chinadns_optarg = NULL;
    char *trustdns_optarg = NULL;
    while ((shortopt = getopt_long(argc, argv, optstr, options, &optindex)) != -1) {
        switch (shortopt) {
            case 'b':
                if (strlen(optarg) + 1 > INET6_ADDRSTRLEN) {
                    printf("ipaddr max len is 45: %zu\n", strlen(optarg));
                    print_command_help();
                    exit(1);
                }
                if (get_addrstr_family(optarg) == -1) {
                    printf("invalid bind addr: %s\n", optarg);
                    print_command_help();
                    exit(1);
                }
                strcpy(g_bind_addr, optarg);
                break;
            case 'l':
                g_bind_port = strtol(optarg, NULL, 10);
                if (g_bind_port == 0) {
                    printf("invalid bind port: %s\n", optarg);
                    print_command_help();
                    exit(1);
                }
                break;
            case 'c':
                chinadns_optarg = optarg;
                break;
            case 't':
                trustdns_optarg = optarg;
                break;
            case '4':
                if (strlen(optarg) + 1 > IPSET_MAXNAMELEN) {
                    printf("setname max len is 31: %zu\n", strlen(optarg));
                    print_command_help();
                    exit(1);
                }
                strcpy(g_setname4, optarg);
                break;
            case '6':
                if (strlen(optarg) + 1 > IPSET_MAXNAMELEN) {
                    printf("setname max len is 31: %zu\n", strlen(optarg));
                    print_command_help();
                    exit(1);
                }
                strcpy(g_setname6, optarg);
                break;
            case 'r':
                g_reuse_port = true;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(CHINADNS_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("missing optarg: '%s'\n", argv[optind - 1]);
                print_command_help();
                exit(1);
            case '?':
                if (optopt) {
                    printf("unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("unknown option: '%s'\n", longopt);
                }
                print_command_help();
                exit(1);
        }
    }
    const char *delimiters = ",";
    if (chinadns_optarg) {
    }
    if (trustdns_optarg) {
        // TODO
    }
}

/* handle local socket readable event */
static void handle_local_packet(void) {
    // TODO
}

/* handle remote socket readable event */
static void handle_remote_packet(int index) {
    // TODO
}

int main(int argc, char *argv[]) {
    print_command_help();
    return 0;
}
