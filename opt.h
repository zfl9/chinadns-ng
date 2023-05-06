#pragma once

#include <stdbool.h>
#include "misc.h"
#include "net.h"

/* socket idx/mark */
#define CHINADNS1_IDX 0
#define CHINADNS2_IDX 1
#define TRUSTDNS1_IDX 2
#define TRUSTDNS2_IDX 3
#define SERVER_MAXIDX TRUSTDNS2_IDX
#define SERVER_MAXCNT (SERVER_MAXIDX + 1)
#define BINDSOCK_MARK (SERVER_MAXIDX + 1)

/* max number of chinadns or trustdns */
#define SERVER_GROUP_CNT 2

#define is_chinadns_idx(idx) ((idx) <= CHINADNS2_IDX)

/* no-ipv6 bit flag (u8) */
#define NOAAAA_ALL         (-1) /* max value of unsigned integer of any width, all bits are 1 */
#define NOAAAA_TAG_GFW     (1U)
#define NOAAAA_TAG_CHN     (1U << 1)
#define NOAAAA_TAG_NONE    (1U << 2)
#define NOAAAA_CHINA_DNS   (1U << 3)
#define NOAAAA_TRUST_DNS   (1U << 4)
#define NOAAAA_CHINA_IPCHK (1U << 5)
#define NOAAAA_TRUST_IPCHK (1U << 6)

#define is_filter_all_v6(flags) ((flags) == (__typeof__(flags))NOAAAA_ALL)

/* g_repeat_times, too large may cause stack overflow */
#define MAX_REPEAT_TIMES 5

/* is enable verbose logging */
#define if_verbose unlikely_if (g_verbose)

extern bool        g_verbose;
extern bool        g_reuse_port;
extern bool        g_noip_as_chnip;
extern u8          g_noaaaa_query;
extern u8          g_default_tag;

extern const char *g_gfwlist_fname;
extern const char *g_chnlist_fname;
extern bool        g_gfwlist_first;

extern const char *g_ipset_name4;
extern const char *g_ipset_name6;
extern const char *g_add_tagchn_ip;
extern const char *g_add_taggfw_ip;

extern const char  *g_bind_ip;
extern u16          g_bind_port;
extern union skaddr g_bind_skaddr;

extern const char   *g_upstream_addrs[SERVER_MAXCNT];
extern union skaddr  g_upstream_skaddrs[SERVER_MAXCNT];
extern int           g_upstream_timeout_sec;
extern u8            g_repeat_times;

void opt_parse(int argc, char *argv[]);
