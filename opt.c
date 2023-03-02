#define _GNU_SOURCE
#include "opt.h"
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHINADNS_VERSION "ChinaDNS-NG 2023.03.02 <https://github.com/zfl9/chinadns-ng>"

/* limits.h */
#ifndef PATH_MAX
  #define PATH_MAX 4096 /* include \0 */
#endif

bool    g_verbose       = false;
bool    g_reuse_port    = false;
bool    g_fair_mode     = false; /* default: fast-mode */
bool    g_noip_as_chnip = false; /* default: see as not-china-ip */
uint8_t g_noaaaa_query  = 0; /* disable AAAA query (bit flags) */

const char *g_gfwlist_fname = NULL; /* gfwlist filename */
const char *g_chnlist_fname = NULL; /* chnlist filename */
bool        g_gfwlist_first = true; /* match gfwlist first */

char g_ipset_setname4[IPSET_MAXNAMELEN] = "chnroute"; /* ipset setname for ipv4 */
char g_ipset_setname6[IPSET_MAXNAMELEN] = "chnroute6"; /* ipset setname for ipv6 */

char     g_bind_ipstr[INET6_ADDRSTRLEN] = "127.0.0.1";
portno_t g_bind_portno                  = 65353;
skaddr_u g_bind_skaddr                  = {{0}};

char     g_remote_ipports[SERVER_MAXCNT][ADDRPORT_STRLEN] = {[CHINADNS1_IDX] = "114.114.114.114", [TRUSTDNS1_IDX] = "8.8.8.8"};
skaddr_u g_remote_skaddrs[SERVER_MAXCNT]                  = {{{0}}};
int      g_upstream_timeout_sec                           = 5;
uint8_t  g_repeat_times                                   = 1; /* used by trust-dns only */

typedef struct {
    char c;
    uint8_t f;
} nov6_opt_s;

static const nov6_opt_s s_nov6_opts[] = {
    {'a', NOAAAA_ALL},
    {'g', NOAAAA_TAG_GFW},
    {'m', NOAAAA_TAG_CHN},
    {'n', NOAAAA_TAG_NONE},
    {'c', NOAAAA_CHINA_DNS},
    {'t', NOAAAA_TRUST_DNS},
    {0, 0},
};

#define OPT_BIND_ADDR 'b'
#define OPT_BIND_PORT 'l'
#define OPT_CHINA_DNS 'c'
#define OPT_TRUST_DNS 't'
#define OPT_IPSET_NAME4 '4'
#define OPT_IPSET_NAME6 '6'
#define OPT_GFWLIST_FILE 'g'
#define OPT_CHNLIST_FILE 'm'
#define OPT_TIMEOUT_SEC 'o'
#define OPT_REPEAT_TIMES 'p'
#define OPT_CHNLIST_FIRST 'M'
#define OPT_NO_IPV6 'N'
#define OPT_FAIR_MODE 'f'
#define OPT_REUSE_PORT 'r'
#define OPT_NOIP_AS_CHNIP 'n'
#define OPT_VERBOSE 'v'
#define OPT_VERSION 'V'
#define OPT_HELP 'h'

static const char s_shortopts[] = {
    ':', /* return ':' if argument missing */
    OPT_BIND_ADDR, ':', /* required_argument */
    OPT_BIND_PORT, ':', /* required_argument */
    OPT_CHINA_DNS, ':', /* required_argument */
    OPT_TRUST_DNS, ':', /* required_argument */
    OPT_IPSET_NAME4, ':', /* required_argument */
    OPT_IPSET_NAME6, ':', /* required_argument */
    OPT_GFWLIST_FILE, ':', /* required_argument */
    OPT_CHNLIST_FILE, ':', /* required_argument */
    OPT_TIMEOUT_SEC, ':', /* required_argument */
    OPT_REPEAT_TIMES, ':', /* required_argument */
    OPT_NO_IPV6, ':', ':', /* optional_argument */
    OPT_CHNLIST_FIRST, /* no_argument */
    OPT_FAIR_MODE, /* no_argument */
    OPT_REUSE_PORT, /* no_argument */
    OPT_NOIP_AS_CHNIP, /* no_argument */
    OPT_VERBOSE, /* no_argument */
    OPT_VERSION, /* no_argument */
    OPT_HELP, /* no_argument */
    '\0',
};

static const struct option s_options[] = {
    {"bind-addr",     required_argument, NULL, OPT_BIND_ADDR},
    {"bind-port",     required_argument, NULL, OPT_BIND_PORT},
    {"china-dns",     required_argument, NULL, OPT_CHINA_DNS},
    {"trust-dns",     required_argument, NULL, OPT_TRUST_DNS},
    {"ipset-name4",   required_argument, NULL, OPT_IPSET_NAME4},
    {"ipset-name6",   required_argument, NULL, OPT_IPSET_NAME6},
    {"gfwlist-file",  required_argument, NULL, OPT_GFWLIST_FILE},
    {"chnlist-file",  required_argument, NULL, OPT_CHNLIST_FILE},
    {"timeout-sec",   required_argument, NULL, OPT_TIMEOUT_SEC},
    {"repeat-times",  required_argument, NULL, OPT_REPEAT_TIMES},
    {"no-ipv6",       optional_argument, NULL, OPT_NO_IPV6},
    {"chnlist-first", no_argument,       NULL, OPT_CHNLIST_FIRST},
    {"fair-mode",     no_argument,       NULL, OPT_FAIR_MODE},
    {"reuse-port",    no_argument,       NULL, OPT_REUSE_PORT},
    {"noip-as-chnip", no_argument,       NULL, OPT_NOIP_AS_CHNIP},
    {"verbose",       no_argument,       NULL, OPT_VERBOSE},
    {"version",       no_argument,       NULL, OPT_VERSION},
    {"help",          no_argument,       NULL, OPT_HELP},
    {NULL,            0,                 NULL, 0},
};

static void show_help(void) {
    printf("usage: chinadns-ng <options...>. the existing options are as follows:\n"
           " -b, --bind-addr <ip-address>         listen address, default: 127.0.0.1\n"
           " -l, --bind-port <port-number>        listen port number, default: 65353\n"
           " -c, --china-dns <ip[#port],...>      china dns server, default: <114DNS>\n"
           " -t, --trust-dns <ip[#port],...>      trust dns server, default: <GoogleDNS>\n"
           " -4, --ipset-name4 <ipv4-setname>     ipset ipv4 set name, default: chnroute\n"
           " -6, --ipset-name6 <ipv6-setname>     ipset ipv6 set name, default: chnroute6\n"
           " -g, --gfwlist-file <file-path>       filepath of gfwlist, '-' indicate stdin\n"
           " -m, --chnlist-file <file-path>       filepath of chnlist, '-' indicate stdin\n"
           " -o, --timeout-sec <query-timeout>    timeout of the upstream dns, default: 5\n"
           " -p, --repeat-times <repeat-times>    it is only used for trustdns, default: 1\n"
           " -N, --no-ipv6=[rules]                filter AAAA query, rules can be a seq of:\n"
           "                                      rule a: filter all domain name (default)\n"
           "                                      rule g: filter the name with tag gfw\n"
           "                                      rule m: filter the name with tag chn\n"
           "                                      rule n: filter the name with tag none\n"
           "                                      rule c: do not forward to china upstream\n"
           "                                      rule t: do not forward to trust upstream\n"
           "                                      if no rules is given, it defaults to a\n"
           " -M, --chnlist-first                  match chnlist first, default: <disabled>\n"
           " -f, --fair-mode                      enable `fair` mode, default: <fast-mode>\n"
           " -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>\n"
           " -n, --noip-as-chnip                  accept reply without ipaddr (A/AAAA query)\n"
           " -v, --verbose                        print the verbose log, default: <disabled>\n"
           " -V, --version                        print `chinadns-ng` version number and exit\n"
           " -h, --help                           print `chinadns-ng` help information and exit\n"
           "bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)\n"
    );
}

#define err_exit(fmt, args...) ({ \
    printf("[%s] " fmt "\n", __func__, ##args); \
    show_help(); \
    exit(1); \
})

static void parse_upstream_addrs(char *arg, bool is_chinadns) {
    int cnt = 0;

    for (char *ipstr = strtok(arg, ","); ipstr; ipstr = strtok(NULL, ",")) {
        if (++cnt > SERVER_GROUP_CNT)
            err_exit("%s dns servers max count is %d", is_chinadns ? "china" : "trust", SERVER_GROUP_CNT);

        portno_t port = 53;
        char *port_str = strchr(ipstr, '#');
        if (port_str) {
            *port_str++ = 0;
            if (strlen(port_str) + 1 > PORTSTR_MAXLEN)
                err_exit("port number max length is %d: %s", PORTSTR_MAXLEN - 1, port_str);
            port = strtoul(port_str, NULL, 10);
            if (port == 0)
                err_exit("invalid server port number: %s", port_str);
        }

        if (strlen(ipstr) + 1 > INET6_ADDRSTRLEN)
            err_exit("ip address max length is %d: %s", INET6_ADDRSTRLEN - 1, ipstr);

        int family = get_ipstr_family(ipstr);
        if (family == -1)
            err_exit("invalid server ip address: %s", ipstr);

        int idx = (is_chinadns ? CHINADNS1_IDX : TRUSTDNS1_IDX) + cnt - 1;
        sprintf(g_remote_ipports[idx], "%s#%u", ipstr, (uint)port);
        build_socket_addr(family, &g_remote_skaddrs[idx], ipstr, port);
    }
}

void opt_parse(int argc, char *argv[]) {
    opterr = 0; /* disable default error msg */

    int optindex = -1;
    int shortopt = -1;

    const char *chinadns_optarg = NULL;
    const char *trustdns_optarg = NULL;

    while ((shortopt = getopt_long(argc, argv, s_shortopts, s_options, &optindex)) != -1) {
        switch (shortopt) {
            case OPT_BIND_ADDR:
                if (strlen(optarg) + 1 > INET6_ADDRSTRLEN)
                    err_exit("ip address max length is %d: %s", INET6_ADDRSTRLEN - 1, optarg);
                if (get_ipstr_family(optarg) == -1)
                    err_exit("invalid listen ip address: %s", optarg);
                strcpy(g_bind_ipstr, optarg);
                break;
            case OPT_BIND_PORT:
                if (strlen(optarg) + 1 > PORTSTR_MAXLEN)
                    err_exit("port number max length is %d: %s", PORTSTR_MAXLEN - 1, optarg);
                g_bind_portno = strtoul(optarg, NULL, 10);
                if (g_bind_portno == 0)
                    err_exit("invalid listen port number: %s", optarg);
                break;
            case OPT_CHINA_DNS:
                chinadns_optarg = optarg;
                break;
            case OPT_TRUST_DNS:
                trustdns_optarg = optarg;
                break;
            case OPT_IPSET_NAME4:
                if (strlen(optarg) + 1 > IPSET_MAXNAMELEN)
                    err_exit("ipset setname max length is %d: %s", IPSET_MAXNAMELEN - 1, optarg);
                strcpy(g_ipset_setname4, optarg);
                break;
            case OPT_IPSET_NAME6:
                if (strlen(optarg) + 1 > IPSET_MAXNAMELEN)
                    err_exit("ipset setname max length is %d: %s", IPSET_MAXNAMELEN - 1, optarg);
                strcpy(g_ipset_setname6, optarg);
                break;
            case OPT_GFWLIST_FILE:
                if (strlen(optarg) + 1 > PATH_MAX)
                    err_exit("file path max length is %d: %s", PATH_MAX - 1, optarg);
                g_gfwlist_fname = optarg;
                break;
            case OPT_CHNLIST_FILE:
                if (strlen(optarg) + 1 > PATH_MAX)
                    err_exit("file path max length is %d: %s", PATH_MAX - 1, optarg);
                g_chnlist_fname = optarg;
                break;
            case OPT_TIMEOUT_SEC:
                g_upstream_timeout_sec = strtoul(optarg, NULL, 10);
                if (g_upstream_timeout_sec <= 0)
                    err_exit("invalid upstream timeout sec: %s", optarg);
                break;
            case OPT_REPEAT_TIMES:
                g_repeat_times = strtoul(optarg, NULL, 10);
                if (g_repeat_times == 0)
                    err_exit("invalid trustdns repeat times: %s", optarg);
                break;
            case OPT_NO_IPV6:
                if (!optarg) {
                    g_noaaaa_query = NOAAAA_ALL;
                } else {
                    for (const nov6_opt_s *opt = s_nov6_opts; opt->c; ++opt) {
                        if (strchr(optarg, opt->c))
                            g_noaaaa_query |= opt->f;
                    }
                    /* try simplify to NOAAAA_ALL */
                    if (!is_filter_all_v6(g_noaaaa_query)) {
                        const uint8_t flags = g_noaaaa_query;
                        if ((flags & NOAAAA_TAG_GFW) && (flags & NOAAAA_TAG_CHN) && (flags & NOAAAA_TAG_NONE))
                            g_noaaaa_query = NOAAAA_ALL;
                        else if ((flags & NOAAAA_CHINA_DNS) && (flags & NOAAAA_TRUST_DNS))
                            g_noaaaa_query = NOAAAA_ALL;
                    }
                }
                break;
            case OPT_CHNLIST_FIRST:
                g_gfwlist_first = false;
                break;
            case OPT_FAIR_MODE:
                g_fair_mode = true;
                break;
            case OPT_REUSE_PORT:
                g_reuse_port = true;
                break;
            case OPT_NOIP_AS_CHNIP:
                g_noip_as_chnip = true;
                break;
            case OPT_VERBOSE:
                g_verbose = true;
                break;
            case OPT_VERSION:
                printf(CHINADNS_VERSION "\n");
                exit(0);
                break;
            case OPT_HELP:
                show_help();
                exit(0);
                break;
            case ':':
                /* missing argument */
                err_exit("missing optarg: '%s'", argv[optind - 1]);
                break;
            case '?':
                /* unknown option */
                if (optopt) {
                    /* short opt */
                    err_exit("unknown option: '-%c'", (char)optopt);
                } else {
                    /* long opt */
                    const char *longopt = argv[optind - 1];
                    const char *p = strchr(longopt, '=');
                    int len = p ? p - longopt : (int)strlen(longopt);
                    err_exit("unknown option: '%.*s'", len, longopt);
                }
                break;
        }
    }

    if (g_gfwlist_fname && g_chnlist_fname && strcmp(g_gfwlist_fname, "-") == 0 && strcmp(g_chnlist_fname, "-") == 0)
        err_exit("gfwlist:%s and chnlist:%s are both STDIN", g_gfwlist_fname, g_chnlist_fname);

    build_socket_addr(get_ipstr_family(g_bind_ipstr), &g_bind_skaddr, g_bind_ipstr, g_bind_portno);

    if (chinadns_optarg) {
        char buf[strlen(chinadns_optarg) + 1];
        strcpy(buf, chinadns_optarg);
        parse_upstream_addrs(buf, true);
    } else {
        build_socket_addr(AF_INET, &g_remote_skaddrs[CHINADNS1_IDX], "114.114.114.114", 53);
    }

    if (trustdns_optarg) {
        char buf[strlen(trustdns_optarg) + 1];
        strcpy(buf, trustdns_optarg);
        parse_upstream_addrs(buf, false);
    } else {
        build_socket_addr(AF_INET, &g_remote_skaddrs[TRUSTDNS1_IDX], "8.8.8.8", 53);
    }
}
