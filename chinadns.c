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
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* left-16-bit:MSGID; right-16-bit:IDX/MARK */
#define CHINADNS1_IDX 0
#define CHINADNS2_IDX 1
#define TRUSTDNS1_IDX 2
#define TRUSTDNS2_IDX 3
#define BINDSOCK_MARK 4
#define TIMER_FD_MARK 5
#define BIT_SHIFT_LEN 16
#define IDX_MARK_MASK 0xffff

/* constant macro definition */
#define EPOLL_MAXEVENTS 64
#define SERVER_MAXCOUNT 4
#define SOCKBUFF_MAXSIZE 1024
#define PORTSTR_MAXLEN 5 /* "65535" (excluding '\0') */
#define ADDRPORT_STRLEN (INET6_ADDRSTRLEN + PORTSTR_MAXLEN + 1) /* "addr#port\0" */
#define CHINADNS_VERSION "ChinaDNS-NG v1.0-beta.1 <https://github.com/zfl9/chinadns-ng>"

/* whether it is a verbose mode */
#define IF_VERBOSE if (g_verbose)

/* static global variable declaration */
static int             g_epollfd                                          = -1;
static bool            g_verbose                                          = false;
static bool            g_reuse_port                                       = false;
static char            g_setname4[IPSET_MAXNAMELEN]                       = "chnroute";
static char            g_setname6[IPSET_MAXNAMELEN]                       = "chnroute6";
static char            g_bind_addr[INET6_ADDRSTRLEN]                      = "127.0.0.1";
static sock_port_t     g_bind_port                                        = 65353;
static inet6_skaddr_t  g_bind_skaddr                                      = {0};
static int             g_bind_socket                                      = -1;
static int             g_remote_sockets[SERVER_MAXCOUNT]                  = {-1, -1, -1, -1};
static char            g_remote_servers[SERVER_MAXCOUNT][ADDRPORT_STRLEN] = {"", "", "", ""};
static inet6_skaddr_t  g_remote_skaddrs[SERVER_MAXCOUNT]                  = {0};
static char            g_socket_buffer[SOCKBUFF_MAXSIZE]                  = {0};
static time_t          g_upstream_timeout_sec                             = 5;
static uint16_t        g_current_message_id                               = 0;
static hashmap_t      *g_message_id_hashmap                               = NULL;
static char            g_domain_name_buffer[DNS_DOMAIN_NAME_MAXLEN]       = {0};
static char            g_ipaddrstring_buffer[INET6_ADDRSTRLEN]            = {0};

/* print command help information */
static void print_command_help(void) {
    printf("usage: chinadns-ng <options...>. the existing options are as follows:\n"
           " -b, --bind-addr <ip-address>         listen address, default: 127.0.0.1\n" 
           " -l, --bind-port <port-number>        listen port number, default: 65353\n"
           " -c, --china-dns <ip[#port],...>      china dns server, default: <114DNS>\n"
           " -t, --trust-dns <ip[#port],...>      trust dns server, default: <GoogleDNS>\n"
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
        char *hashsign_ptr = strchr(server_str, '#');
        if (hashsign_ptr) {
            *hashsign_ptr = 0; ++hashsign_ptr;
            if (strlen(hashsign_ptr) > PORTSTR_MAXLEN) {
                printf("[parse_dns_server_opt] port number max length is 5: %s\n", hashsign_ptr);
                goto PRINT_HELP_AND_EXIT;
            }
            server_port = strtol(hashsign_ptr, NULL, 10);
            if (server_port == 0) {
                printf("[parse_dns_server_opt] invalid server port number: %s\n", hashsign_ptr);
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
        sprintf(g_remote_servers[index], "%s#%hu", server_str, server_port);
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
    inet6_skaddr_t source_addr = {0};
    socklen_t source_addrlen = sizeof(inet6_skaddr_t);
    ssize_t packet_len = recvfrom(g_bind_socket, g_socket_buffer, SOCKBUFF_MAXSIZE, 0, (void *)&source_addr, &source_addrlen);

    if (packet_len < 0) {
        if (errno == EAGAIN || errno == EINTR) return;
        LOGERR("[handle_local_packet] failed to recv data from bind socket: (%d) %s", errno, strerror(errno));
        return;
    }

    if (!dns_query_is_valid(g_socket_buffer, packet_len, g_verbose ? g_domain_name_buffer : NULL)) return;

    IF_VERBOSE {
        sock_port_t source_port = 0;
        if (source_addr.sin6_family == AF_INET) {
            parse_ipv4_addr((void *)&source_addr, g_ipaddrstring_buffer, &source_port);
        } else {
            parse_ipv6_addr((void *)&source_addr, g_ipaddrstring_buffer, &source_port);
        }
        LOGINF("[handle_local_packet] query [%s] from %s#%hu", g_domain_name_buffer, g_ipaddrstring_buffer, ntohs(source_port));
    }

    uint16_t unique_msgid = g_current_message_id++;
    uint16_t origin_msgid = ((dns_header_t *)g_socket_buffer)->id;
    ((dns_header_t *)g_socket_buffer)->id = unique_msgid; /* replace with new msgid */

    for (int i = 0; i < SERVER_MAXCOUNT; ++i) {
        if (g_remote_sockets[i] < 0) continue;
        if (send(g_remote_sockets[i], g_socket_buffer, packet_len, 0) < 0) {
            LOGERR("[handle_local_packet] failed to send dns query packet to %s: (%d) %s", g_remote_servers[i], errno, strerror(errno));
            return;
        }
    }

    int query_timerfd = new_once_timerfd(g_upstream_timeout_sec);
    struct epoll_event ev = {.events = EPOLLIN, .data.u32 = (unique_msgid << BIT_SHIFT_LEN) | TIMER_FD_MARK};
    if (epoll_ctl(g_epollfd, EPOLL_CTL_ADD, query_timerfd, &ev)) {
        LOGERR("[handle_local_packet] failed to register timeout event: (%d) %s", errno, strerror(errno));
        close(query_timerfd);
        return;
    }

    hashmap_put(&g_message_id_hashmap, unique_msgid, origin_msgid, query_timerfd, &source_addr);
}

/* handle remote socket readable event */
static void handle_remote_packet(int index) {
    int remote_socket = g_remote_sockets[index];
    const char *remote_servers = g_remote_servers[index];
    ssize_t packet_len = recv(remote_socket, g_socket_buffer, SOCKBUFF_MAXSIZE, 0);

    if (packet_len < 0) {
        if (errno == EAGAIN || errno == EINTR) return;
        LOGERR("[handle_remote_packet] failed to recv data from %s: (%d) %s", remote_servers, errno, strerror(errno));
        return;
    }

    bool is_trusted = false;
    if (index == TRUSTDNS1_IDX || index == TRUSTDNS2_IDX) is_trusted = true;
    bool is_valid = dns_reply_is_valid(g_socket_buffer, packet_len, g_verbose ? g_domain_name_buffer : NULL, is_trusted);
    IF_VERBOSE LOGINF("[handle_remote_packet] reply [%s] from %s, result: %s", g_domain_name_buffer, remote_servers, is_valid ? "pass" : "drop");
    if (!is_valid) return; /* let subsequent reply be processed */

    dns_header_t *dns_header = (dns_header_t *)g_socket_buffer;
    uint16_t unique_msgid = dns_header->id;
    hashentry_t *entry = hashmap_get(g_message_id_hashmap, unique_msgid);
    if (!entry) return; /* indicate that the request has been processed */
    dns_header->id = entry->origin_msgid; /* replace with old msgid */

    socklen_t source_addrlen = (entry->source_addr.sin6_family == AF_INET) ? sizeof(inet4_skaddr_t) : sizeof(inet6_skaddr_t);
    if (sendto(g_bind_socket, g_socket_buffer, packet_len, 0, (void *)&entry->source_addr, source_addrlen) < 0) {
        sock_port_t source_port = 0;
        if (entry->source_addr.sin6_family == AF_INET) {
            parse_ipv4_addr((void *)&entry->source_addr, g_ipaddrstring_buffer, &source_port);
        } else {
            parse_ipv6_addr((void *)&entry->source_addr, g_ipaddrstring_buffer, &source_port);
        }
        LOGERR("[handle_remote_packet] failed to send dns reply packet to %s#%hu: (%d) %s", g_ipaddrstring_buffer, source_port, errno, strerror(errno));
    }

    /* query is processed, clean up */
    close(entry->query_timerfd);
    hashmap_del(&g_message_id_hashmap, entry);
}

/* handle upstream reply timeout event */
static void handle_timeout_event(uint16_t msg_id) {
    LOGERR("[handle_timeout_event] upstream dns server reply timeout, unique msgid: %hu", msg_id);
    hashentry_t *entry = hashmap_get(g_message_id_hashmap, msg_id);
    close(entry->query_timerfd); /* epoll will automatically remove the associated event */
    hashmap_del(&g_message_id_hashmap, entry); /* delete and free the associated hash entry */
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 512);
    parse_command_args(argc, argv);

    /* show startup information */
    LOGINF("[main] local listen addr: %s#%hu", g_bind_addr, g_bind_port);
    if (strlen(g_remote_servers[CHINADNS1_IDX])) LOGINF("[main] chinadns server#1: %s", g_remote_servers[CHINADNS1_IDX]);
    if (strlen(g_remote_servers[CHINADNS2_IDX])) LOGINF("[main] chinadns server#2: %s", g_remote_servers[CHINADNS2_IDX]);
    if (strlen(g_remote_servers[TRUSTDNS1_IDX])) LOGINF("[main] trustdns server#1: %s", g_remote_servers[TRUSTDNS1_IDX]);
    if (strlen(g_remote_servers[TRUSTDNS2_IDX])) LOGINF("[main] trustdns server#2: %s", g_remote_servers[TRUSTDNS2_IDX]);
    LOGINF("[main] ipset ip4 setname: %s", g_setname4);
    LOGINF("[main] ipset ip6 setname: %s", g_setname6);
    LOGINF("[main] dns query timeout: %ld seconds", g_upstream_timeout_sec);
    if (g_reuse_port) LOGINF("[main] enable `SO_REUSEPORT` feature");
    if (g_verbose) LOGINF("[main] print the verbose running log");

    /* init ipset netlink socket */
    ipset_init_nlsocket(g_setname4, g_setname6);

    /* create listen socket */
    g_bind_socket = (g_bind_skaddr.sin6_family == AF_INET) ? new_udp4_socket() : new_udp6_socket();
    if (g_bind_skaddr.sin6_family == AF_INET6) set_ipv6_only(g_bind_socket);
    if (g_reuse_port) set_reuse_port(g_bind_socket);
    set_reuse_addr(g_bind_socket);

    /* create remote socket */
    for (int i = 0; i < SERVER_MAXCOUNT; ++i) {
        if (!strlen(g_remote_servers[i])) continue;
        g_remote_sockets[i] = (g_remote_skaddrs[i].sin6_family == AF_INET) ? new_udp4_socket() : new_udp6_socket();
        if (g_remote_skaddrs[i].sin6_family == AF_INET6) set_ipv6_only(g_remote_sockets[i]);
        set_reuse_addr(g_remote_sockets[i]);
    }

    /* bind address to listen socket */
    if (bind(g_bind_socket, (void *)&g_bind_skaddr, (g_bind_skaddr.sin6_family == AF_INET) ? sizeof(inet4_skaddr_t) : sizeof(inet6_skaddr_t))) {
        LOGERR("[main] failed to bind address to socket: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* connect to remote dns servers */
    for (int i = 0; i < SERVER_MAXCOUNT; ++i) {
        if (g_remote_sockets[i] < 0) continue;
        if (connect(g_remote_sockets[i], (void *)&g_remote_skaddrs[i], (g_remote_skaddrs[i].sin6_family == AF_INET) ? sizeof(inet4_skaddr_t) : sizeof(inet6_skaddr_t))) {
            LOGERR("[main] failed to connect to upstream(%s): (%d) %s", g_remote_servers[i], errno, strerror(errno));
            return errno;
        }
    }

    /* create epoll fd */
    if ((g_epollfd = epoll_create1(0)) < 0) {
        LOGERR("[main] failed to create epoll fd: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* register epoll event */
    struct epoll_event ev, events[EPOLL_MAXEVENTS];

    /* listen socket readable event */
    ev.events = EPOLLIN;
    ev.data.u32 = BINDSOCK_MARK; /* don't care about msg id */
    if (epoll_ctl(g_epollfd, EPOLL_CTL_ADD, g_bind_socket, &ev)) {
        LOGERR("[main] failed to register epoll event: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* remote socket readable event */
    for (int i = 0; i < SERVER_MAXCOUNT; ++i) {
        if (g_remote_sockets[i] < 0) continue;
        ev.events = EPOLLIN;
        ev.data.u32 = i; /* don't care about msg id */
        if (epoll_ctl(g_epollfd, EPOLL_CTL_ADD, g_remote_sockets[i], &ev)) {
            LOGERR("[main] failed to register epoll event: (%d) %s", errno, strerror(errno));
            return errno;
        }
    }

    /* run event loop (blocking here) */
    while (true) {
        int event_count = epoll_wait(g_epollfd, events, EPOLL_MAXEVENTS, -1);

        if (event_count < 0) {
            LOGERR("[main] epoll_wait() reported an error: (%d) %s", errno, strerror(errno));
            continue;
        }

        for (int i = 0; i < event_count; ++i) {
            uint32_t curr_event = events[i].events;
            uint32_t curr_data = events[i].data.u32;

            /* an error occurred */
            if (curr_event & EPOLLERR) {
                switch (curr_data & IDX_MARK_MASK) {
                    case CHINADNS1_IDX:
                        LOGERR("[main] upstream server socket error(%s): (%d) %s", g_remote_servers[CHINADNS1_IDX], errno, strerror(errno));
                        break;
                    case CHINADNS2_IDX:
                        LOGERR("[main] upstream server socket error(%s): (%d) %s", g_remote_servers[CHINADNS2_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS1_IDX:
                        LOGERR("[main] upstream server socket error(%s): (%d) %s", g_remote_servers[TRUSTDNS1_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS2_IDX:
                        LOGERR("[main] upstream server socket error(%s): (%d) %s", g_remote_servers[TRUSTDNS2_IDX], errno, strerror(errno));
                        break;
                    case BINDSOCK_MARK:
                        LOGERR("[main] local udp listen socket error: (%d) %s", errno, strerror(errno));
                        break;
                    case TIMER_FD_MARK:
                        LOGERR("[main] query timeout timer fd error: (%d) %s", errno, strerror(errno));
                        break;
                }
                continue;
            }

            /* ignore other events */
            if (!(curr_event & EPOLLIN)) continue;

            /* handle readable event */
            switch (curr_data & IDX_MARK_MASK) {
                case CHINADNS1_IDX:
                    handle_remote_packet(CHINADNS1_IDX);
                    break;
                case CHINADNS2_IDX:
                    handle_remote_packet(CHINADNS2_IDX);
                    break;
                case TRUSTDNS1_IDX:
                    handle_remote_packet(TRUSTDNS1_IDX);
                    break;
                case TRUSTDNS2_IDX:
                    handle_remote_packet(TRUSTDNS2_IDX);
                    break;
                case BINDSOCK_MARK:
                    handle_local_packet();
                    break;
                case TIMER_FD_MARK:
                    handle_timeout_event(curr_data >> BIT_SHIFT_LEN);
                    break;
            }
        }
    }

    return 0;
}
