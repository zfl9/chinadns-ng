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
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* left-16-bit:IDX/MARK; right-16-bit:MSGID/0 */
#define CHINADNS1_IDX 0
#define CHINADNS2_IDX 1
#define TRUSTDNS1_IDX 2
#define TRUSTDNS2_IDX 3
#define BINDSOCK_MARK 4
#define TIMER_FD_MARK 5
#define RIGHT_SHIFT_N 16
#define DNSMSGID_MASK 0xffff

/* constant macro definition */
#define SERVER_MAXCOUNT 4
#define SOCKBUFF_MAXSIZE 1024
#define PORTSTR_MAXLEN 5 /* "65535" (excluding '\0') */
#define ADDRPORT_STRLEN (INET6_ADDRSTRLEN + PORTSTR_MAXLEN + 1) /* "addr:port\0" */
#define CHINADNS_VERSION "ChinaDNS-NG v1.0-beta.1 <https://github.com/zfl9/chinadns-ng>"

/* whether it is a verbose mode */
#define IF_VERBOSE if (g_verbose)

/* static global variable declaration */
static bool            g_verbose                                          = false;
static bool            g_reuse_port                                       = false;
static char            g_setname4[IPSET_MAXNAMELEN]                       = "chnroute";
static char            g_setname6[IPSET_MAXNAMELEN]                       = "chnroute6";
static char            g_bind_addr[INET6_ADDRSTRLEN]                      = "127.0.0.1";
static sock_port_t     g_bind_port                                        = 65353;
static all_sockaddr_t  g_bind_skaddr                                      = {0};
static int             g_local_socket                                     = -1;
static int             g_remote_sockets[SERVER_MAXCOUNT]                  = {-1, -1, -1, -1};
static char            g_remote_servers[SERVER_MAXCOUNT][ADDRPORT_STRLEN] = {"114.114.114.114:53", "", "8.8.8.8:53", ""};
static all_sockaddr_t  g_remote_skaddrs[SERVER_MAXCOUNT]                  = {0};
static char            g_socket_buffer[SOCKBUFF_MAXSIZE]                  = {0};
static time_t          g_upstream_timeout_sec                             = 5;
static uint16_t        g_current_message_id                               = 0;
static hashmap_t      *g_message_id_hashmap                               = NULL;

/* print command help information */
static void print_command_help(void) {
    printf("usage: chinadns-ng <options...>. the existing options are as follows:\n"
           " -b, --bind-addr <ip-address>         listen address, default: 127.0.0.1\n" 
           " -l, --bind-port <port-number>        listen port number, default: 65353\n"
           " -c, --china-dns <ip[@port],...>      china dns server, default: <114DNS>\n"
           " -t, --trust-dns <ip[@port],...>      trust dns server, default: <GoogleDNS>\n"
           " -4, --ipset-name4 <ipv4-setname>     ipset ipv4 set name, default: chnroute\n"
           " -6, --ipset-name6 <ipv6-setname>     ipset ipv6 set name, default: chnroute6\n"
           " -o, --timeout-sec <query-timeout>    timeout of the upstream dns, default: 5\n"
           " -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>\n"
           " -v, --verbose                        print the verbose log, default: <disabled>\n"
           " -V, --version                        print `chinadns-ng` version number and exit\n"
           " -h, --help                           print `chinadns-ng` help information and exit\n"
           "bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)\n"
    );
}

/* parse and check dns server option */
static void parse_dns_server_opt(char *option_argval, bool is_chinadns) {
    size_t server_cnt = 0;
    for (char *server_str = strtok(option_argval, ","); server_str; server_str = strtok(NULL, ",")) {
        if (++server_cnt > 2) {
            printf("[parse_dns_server_opt] %s dns servers max count is 2\n", is_chinadns ? "china" : "trust");
            goto PRINT_HELP_AND_EXIT;
        }
        sock_port_t server_port = 53;
        char *atsign_ptr = strchr(server_str, '@');
        if (atsign_ptr) {
            *atsign_ptr = 0; ++atsign_ptr;
            if (strlen(atsign_ptr) > PORTSTR_MAXLEN) {
                printf("[parse_dns_server_opt] port number max length is 5: %s\n", atsign_ptr);
                goto PRINT_HELP_AND_EXIT;
            }
            server_port = strtol(atsign_ptr, NULL, 10);
            if (server_port == 0) {
                printf("[parse_dns_server_opt] invalid server port number: %s\n", atsign_ptr);
                goto PRINT_HELP_AND_EXIT;
            }
        }
        if (strlen(server_str) + 1 > INET6_ADDRSTRLEN) {
            printf("[parse_dns_server_opt] ip address max length is 45: %s\n", server_str);
            goto PRINT_HELP_AND_EXIT;
        }
        int index = is_chinadns ? server_cnt - 1 : server_cnt + 1;
        switch (get_addrstr_family(server_str)) {
            case AF_INET:
                build_ipv4_addr((void *)&g_remote_skaddrs[index], server_str, server_port);
                break;
            case AF_INET6:
                build_ipv6_addr((void *)&g_remote_skaddrs[index], server_str, server_port);
                break;
            default:
                printf("[parse_dns_server_opt] invalid server ip address: %s\n", server_str);
                goto PRINT_HELP_AND_EXIT;
        }
        sprintf(g_remote_servers[index], "%s:%hu", server_str, server_port);
    }
    return;
PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

/* parse and check command arguments */
static void parse_command_args(int argc, char *argv[]) {
    const char *optstr = ":b:l:c:t:4:6:o:rvVh";
    const struct option options[] = {
        {"bind-addr",   required_argument, NULL, 'b'},
        {"bind-port",   required_argument, NULL, 'l'},
        {"china-dns",   required_argument, NULL, 'c'},
        {"trust-dns",   required_argument, NULL, 't'},
        {"ipset-name4", required_argument, NULL, '4'},
        {"ipset-name6", required_argument, NULL, '6'},
        {"timeout-sec", required_argument, NULL, 'o'},
        {"reuse-port",  no_argument,       NULL, 'r'},
        {"verbose",     no_argument,       NULL, 'v'},
        {"version",     no_argument,       NULL, 'V'},
        {"help",        no_argument,       NULL, 'h'},
    };
    opterr = 0;
    int optindex = -1;
    int shortopt = -1;
    char *chinadns_optarg = "114.114.114.114";
    char *trustdns_optarg = "8.8.8.8";
    while ((shortopt = getopt_long(argc, argv, optstr, options, &optindex)) != -1) {
        switch (shortopt) {
            case 'b':
                if (strlen(optarg) + 1 > INET6_ADDRSTRLEN) {
                    printf("[parse_command_args] ip address max length is 45: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_addrstr_family(optarg) == -1) {
                    printf("[parse_command_args] invalid listen ip address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_addr, optarg);
                break;
            case 'l':
                if (strlen(optarg) > PORTSTR_MAXLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_bind_port = strtol(optarg, NULL, 10);
                if (g_bind_port == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
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
                    printf("[parse_command_args] ipset setname max length is 31: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_setname4, optarg);
                break;
            case '6':
                if (strlen(optarg) + 1 > IPSET_MAXNAMELEN) {
                    printf("[parse_command_args] ipset setname max length is 31: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_setname6, optarg);
                break;
            case 'o':
                g_upstream_timeout_sec = strtol(optarg, NULL, 10);
                if (g_upstream_timeout_sec <= 0) {
                    printf("[parse_command_args] invalid upstream timeout sec: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
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
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                goto PRINT_HELP_AND_EXIT;
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                goto PRINT_HELP_AND_EXIT;
        }
    }
    parse_dns_server_opt(chinadns_optarg, true);
    parse_dns_server_opt(trustdns_optarg, false);
    if (get_addrstr_family(g_bind_addr) == AF_INET) {
        build_ipv4_addr((void *)&g_bind_skaddr, g_bind_addr, g_bind_port);
    } else {
        build_ipv6_addr((void *)&g_bind_skaddr, g_bind_addr, g_bind_port);
    }
    return;
PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

/* handle local socket readable event */
static void handle_local_packet(void) {
    // TODO
}

/* handle remote socket readable event */
static void handle_remote_packet(int index) {
    // TODO
}

/* handle upstream reply timeout event */
static void handle_timeout_event(uint16_t msgid) {
    // TODO
}

int main(int argc, char *argv[]) {
    parse_command_args(argc, argv);
    return 0;
}
