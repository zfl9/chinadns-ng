#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "net.h"

/* socket idx/mark */
#define CHINADNS1_IDX 0
#define CHINADNS2_IDX 1
#define TRUSTDNS1_IDX 2
#define TRUSTDNS2_IDX 3
#define BINDSOCK_MARK 4

#define is_chinadns_idx(idx) ((idx) == CHINADNS1_IDX || (idx) == CHINADNS2_IDX)

/* no-ipv6 bit flag */
#define NOAAAA_ALL       (-1) /* max value of unsigned integer of any width, all bits are 1 */
#define NOAAAA_TAG_GFW   (1U)
#define NOAAAA_TAG_CHN   (1U << 1)
#define NOAAAA_TAG_NONE  (1U << 2)
#define NOAAAA_CHINA_DNS (1U << 3)
#define NOAAAA_TRUST_DNS (1U << 4)

#define is_filter_all_v6(flags) ((flags) == (__typeof__(flags))NOAAAA_ALL)

/* upstream max count */
#define SERVER_MAXCOUNT 4

/* setname max len (include \0) */
#define IPSET_MAXNAMELEN 32

/* port string max len (include \0) | "65535" */
#define PORTSTR_MAXLEN 6

/* addr+port string max len (include \0) | "addr#port" */
#define ADDRPORT_STRLEN (INET6_ADDRSTRLEN + PORTSTR_MAXLEN)

/* is enable verbose logging */
#define IF_VERBOSE if (g_verbose)

extern bool        g_verbose;
extern bool        g_reuse_port;
extern bool        g_fair_mode;
extern bool        g_noip_as_chnip;
extern uint8_t     g_noaaaa_query;

extern const char *g_gfwlist_fname;
extern const char *g_chnlist_fname;
extern bool        g_gfwlist_first;

extern char        g_ipset_setname4[IPSET_MAXNAMELEN];
extern char        g_ipset_setname6[IPSET_MAXNAMELEN];

extern char        g_bind_ipstr[INET6_ADDRSTRLEN];
extern portno_t    g_bind_portno;
extern skaddr_u    g_bind_skaddr;

extern char        g_remote_ipports[SERVER_MAXCOUNT][ADDRPORT_STRLEN];
extern skaddr_u    g_remote_skaddrs[SERVER_MAXCOUNT];
extern int         g_upstream_timeout_sec;
extern uint8_t     g_repeat_times;

void opt_parse(int argc, char *argv[]);
