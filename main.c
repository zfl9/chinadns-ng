#define _GNU_SOURCE
#include "opt.h"
#include "log.h"
#include "net.h"
#include "dns.h"
#include "dnl.h"
#include "misc.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define EPOLL_MAXEVENTS 8

typedef struct u16_buf {
    uint16_t len;
    char buf[];
} u16_buf_s;

typedef struct queryctx {
    uint16_t           unique_msgid;  /* [key] globally unique msgid */
    uint16_t           origin_msgid;  /* [value] associated original msgid */
    int                request_time;  /* [value] query request timestamp */
    u16_buf_s *noalias trustdns_buf;  /* [value] {uint16_t len; char buf[];} */
    bool               chinadns_got;  /* [value] received reply from china-dns */
    uint8_t            name_tag;      /* [value] domain name tag: gfw|chn|none */
    skaddr_u           source_addr;   /* [value] associated client socket addr */
    myhash_hh          hh;            /* [metadata] used internally by `uthash` */
} queryctx_t;

static int s_epollfd          = -1;
static int s_bind_sockfd      = -1;
static int s_remote_sockfds[] = {[0 ... SERVER_MAXIDX] = -1};

static uint16_t    s_unique_msgid = 0;
static queryctx_t *s_context_list = NULL;

static void *noalias s_packet_buf                    = (char [DNS_PACKET_MAXSIZE]){0};
static char          s_name_buf[DNS_NAME_MAXLEN + 1] = {0};
static char          s_ipstr_buf[INET6_ADDRSTRLEN]   = {0};

#define free_context(ctx) ({ \
    MYHASH_DEL(s_context_list, ctx); \
    free((ctx)->trustdns_buf); \
    free(ctx); \
})

/* handle local socket readable event */
static void handle_local_packet(void) {
    unlikely_if (MYHASH_CNT(s_context_list) >= 65536U) { /* range:0~65535, count:65536 */
        LOGE("unique_msg_id is not enough, refused to serve");
        return;
    }

    skaddr_u source_addr = {{0}};
    socklen_t source_addrlen = sizeof(source_addr);
    ssize_t packet_len = recvfrom(s_bind_sockfd, s_packet_buf, DNS_PACKET_MAXSIZE, 0, &source_addr.sa, &source_addrlen);

    if (packet_len < 0) {
        unlikely_if (errno != EAGAIN && errno != EWOULDBLOCK)
            LOGE("failed to recv data from bind socket: (%d) %s", errno, strerror(errno));
        return;
    }

    char *name_buf = (g_verbose || g_dnl_nitems) ? s_name_buf : NULL;
    int namelen = 0;
    unlikely_if (!dns_query_check(s_packet_buf, packet_len, name_buf, &namelen)) return;

    uint16_t qtype = dns_qtype(s_packet_buf, namelen);
    int ascii_namelen = dns_ascii_namelen(namelen);
    uint8_t name_tag = (ascii_namelen > 0 && g_dnl_nitems)
        ? get_name_tag(s_name_buf, ascii_namelen) : NAME_TAG_NONE;

    IF_VERBOSE {
        portno_t port = 0;
        parse_socket_addr(&source_addr, s_ipstr_buf, &port);
        LOGI("query [%s] from %s#%u (%u)", s_name_buf, s_ipstr_buf, (uint)port, (uint)s_unique_msgid);
    }

    if (g_noaaaa_query & (NOAAAA_TAG_GFW | NOAAAA_TAG_CHN | NOAAAA_TAG_NONE) && qtype == DNS_RECORD_TYPE_AAAA) {
        bool filter = false;
        const char *rule = "(null)";
        if (is_filter_all_v6(g_noaaaa_query)) {
            filter = true;
            rule = "all";
        } else {
            switch (name_tag) {
                case NAME_TAG_GFW:
                    filter = g_noaaaa_query & NOAAAA_TAG_GFW;
                    rule = "tag_gfw";
                    break;
                case NAME_TAG_CHN:
                    filter = g_noaaaa_query & NOAAAA_TAG_CHN;
                    rule = "tag_chn";
                    break;
                case NAME_TAG_NONE:
                    filter = g_noaaaa_query & NOAAAA_TAG_NONE;
                    rule = "tag_none";
                    break;
            }
        }
        if (filter) {
            LOGV("filter [%s] AAAA query, rule: %s", s_name_buf, rule);
            dns_header_t *header = s_packet_buf;
            header->qr = DNS_QR_REPLY;
            header->rcode = DNS_RCODE_NOERROR;
            unlikely_if (sendto(s_bind_sockfd, s_packet_buf, packet_len, 0, &source_addr.sa, source_addrlen) < 0) {
                portno_t port = 0;
                parse_socket_addr(&source_addr, s_ipstr_buf, &port);
                LOGE("failed to send dns reply packet to %s#%u: (%d) %s", s_ipstr_buf, (uint)port, errno, strerror(errno));
            }
            return;
        }
    }

    uint16_t unique_msgid = s_unique_msgid++;
    dns_header_t *dns_header = s_packet_buf;
    uint16_t origin_msgid = dns_header->id;
    dns_header->id = unique_msgid; /* replace with new msgid */

    for (int i = 0; i <= SERVER_MAXIDX; ++i) {
        if (s_remote_sockfds[i] < 0) continue;
        uint8_t send_times = 1;
        if (is_chinadns_idx(i)) {
            if (name_tag == NAME_TAG_GFW) continue;
            if (g_noaaaa_query & NOAAAA_CHINA_DNS && qtype == DNS_RECORD_TYPE_AAAA) continue;
        } else {
            if (name_tag == NAME_TAG_CHN) continue;
            if (g_noaaaa_query & NOAAAA_TRUST_DNS && qtype == DNS_RECORD_TYPE_AAAA) continue;
            send_times = g_repeat_times;
        }
        const skaddr_u *addr = &g_remote_skaddrs[i];
        socklen_t addrlen = skaddr_size(addr);
        for (int j = 0; j < send_times; ++j) {
            LOGV("forward [%s] to %s (%s)", s_name_buf, g_remote_ipports[i], is_chinadns_idx(i) ? "chinadns" : "trustdns");
            unlikely_if (sendto(s_remote_sockfds[i], s_packet_buf, packet_len, 0, &addr->sa, addrlen) < 0)
                LOGE("failed to send dns query packet to %s: (%d) %s", g_remote_ipports[i], errno, strerror(errno));
        }
    }

    queryctx_t *context = malloc(sizeof(queryctx_t));
    context->unique_msgid = unique_msgid;
    context->origin_msgid = origin_msgid;
    context->request_time = time(NULL);
    context->trustdns_buf = NULL;
    context->chinadns_got = !g_fair_mode;
    context->name_tag = name_tag;
    memcpy(&context->source_addr, &source_addr, sizeof(source_addr));
    MYHASH_ADD(s_context_list, context, &context->unique_msgid, sizeof(context->unique_msgid));
}

static inline bool accept_chinadns_reply(const void *noalias packet_buf, ssize_t packet_len, int namelen) {
    uint16_t qtype = dns_qtype(packet_buf, namelen);
    if (qtype != DNS_RECORD_TYPE_A && qtype != DNS_RECORD_TYPE_AAAA)
        return true; /* only filter A/AAAA reply */

    int res = dns_chnip_check(packet_buf, packet_len, namelen);
    if (res == DNS_IPCHK_IS_CHNIP)
        return true;
    if (res == DNS_IPCHK_NOT_FOUND) {
        LOGV("no ip found in reply, see as %s", g_noip_as_chnip ? "chnip" : "non-chnip");
        return g_noip_as_chnip;
    }
    return false;
}

/* handle remote socket readable event */
static void handle_remote_packet(int index) {
    int remote_sockfd = s_remote_sockfds[index];
    const char *remote_ipport = g_remote_ipports[index];
    ssize_t packet_len = recvfrom(remote_sockfd, s_packet_buf, DNS_PACKET_MAXSIZE, 0, NULL, NULL);

    if (packet_len < 0) {
        unlikely_if (errno != EAGAIN && errno != EWOULDBLOCK)
            LOGE("failed to recv data from %s: (%d) %s", remote_ipport, errno, strerror(errno));
        return;
    }

    char *name_buf = g_verbose ? s_name_buf : NULL;
    int namelen = 0;
    unlikely_if (!dns_reply_check(s_packet_buf, packet_len, name_buf, &namelen)) return;

    queryctx_t *context = NULL;
    dns_header_t *dns_header = s_packet_buf;
    MYHASH_GET(s_context_list, context, &dns_header->id, sizeof(dns_header->id));
    if (!context) {
        LOGV("reply [%s] from %s (%u), result: ignore", s_name_buf, remote_ipport, (uint)dns_header->id);
        return;
    }

    void *reply_buffer = s_packet_buf;
    size_t reply_length = packet_len;

    if (is_chinadns_idx(index)) {
        if (context->name_tag == NAME_TAG_CHN || accept_chinadns_reply(s_packet_buf, packet_len, namelen)) {
            LOGV("reply [%s] from %s (%u), result: accept", s_name_buf, remote_ipport, (uint)dns_header->id);
            if (context->trustdns_buf)
                LOGV("reply [%s] from <previous-trustdns> (%u), result: filter", s_name_buf, (uint)dns_header->id);
        } else {
            LOGV("reply [%s] from %s (%u), result: filter", s_name_buf, remote_ipport, (uint)dns_header->id);
            if (context->trustdns_buf) {
                LOGV("reply [%s] from <previous-trustdns> (%u), result: accept", s_name_buf, (uint)dns_header->id);
                reply_buffer = context->trustdns_buf->buf;
                reply_length = context->trustdns_buf->len;
            } else {
                context->chinadns_got = true;
                return;
            }
        }
    } else {
        if (context->name_tag == NAME_TAG_GFW || context->chinadns_got) {
            LOGV("reply [%s] from %s (%u), result: accept", s_name_buf, remote_ipport, (uint)dns_header->id);
        } else {
            /* trustdns returns before chinadns */
            if (context->trustdns_buf) {
                LOGV("reply [%s] from %s (%u), result: ignore", s_name_buf, remote_ipport, (uint)dns_header->id);
            } else {
                LOGV("reply [%s] from %s (%u), result: delay", s_name_buf, remote_ipport, (uint)dns_header->id);
                context->trustdns_buf = malloc(sizeof(*context->trustdns_buf) + packet_len);
                context->trustdns_buf->len = packet_len; /* dns reply length */
                memcpy(context->trustdns_buf->buf, s_packet_buf, packet_len);
            }
            return;
        }
    }

    dns_header = reply_buffer;
    dns_header->id = context->origin_msgid; /* replace with old msgid */
    socklen_t source_addrlen = skaddr_size(&context->source_addr);
    unlikely_if (sendto(s_bind_sockfd, reply_buffer, reply_length, 0, &context->source_addr.sa, source_addrlen) < 0) {
        portno_t port = 0;
        parse_socket_addr(&context->source_addr, s_ipstr_buf, &port);
        LOGE("failed to send dns reply packet to %s#%u: (%d) %s", s_ipstr_buf, (uint)port, errno, strerror(errno));
    }
    free_context(context);
}

/* handle upstream reply timeout event */
static void handle_timeout_event(queryctx_t *context) {
    LOGE("upstream dns server reply timeout, unique msgid: %u", (uint)context->unique_msgid);
    free_context(context);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    opt_parse(argc, argv);

    /* show startup information */
    LOGI("local listen addr: %s#%u", g_bind_ipstr, (uint)g_bind_portno);

    if (*g_remote_ipports[CHINADNS1_IDX]) LOGI("chinadns server#1: %s", g_remote_ipports[CHINADNS1_IDX]);
    if (*g_remote_ipports[CHINADNS2_IDX]) LOGI("chinadns server#2: %s", g_remote_ipports[CHINADNS2_IDX]);
    if (*g_remote_ipports[TRUSTDNS1_IDX]) LOGI("trustdns server#1: %s", g_remote_ipports[TRUSTDNS1_IDX]);
    if (*g_remote_ipports[TRUSTDNS2_IDX]) LOGI("trustdns server#2: %s", g_remote_ipports[TRUSTDNS2_IDX]);

    LOGI("ipset ip4 setname: %s", g_ipset_setname4);
    LOGI("ipset ip6 setname: %s", g_ipset_setname6);

    dnl_init();

    LOGI("cur judgment mode: %s mode", g_fair_mode ? "fair" : "fast");
    LOGI("%s reply without ip addr", g_noip_as_chnip ? "accept" : "filter");
    LOGI("dns query timeout: %d seconds", g_upstream_timeout_sec);

    if (is_filter_all_v6(g_noaaaa_query))
        LOGI("filter AAAA for all name");
    else if (g_noaaaa_query != 0) {
        if (g_noaaaa_query & NOAAAA_TAG_GFW)
            LOGI("filter AAAA for gfwlist name");
        if (g_noaaaa_query & NOAAAA_TAG_CHN)
            LOGI("filter AAAA for chnlist name");
        if (g_noaaaa_query & NOAAAA_TAG_NONE)
            LOGI("filter AAAA for tag_none name");
        if (g_noaaaa_query & NOAAAA_CHINA_DNS)
            LOGI("filter AAAA for china upstream");
        if (g_noaaaa_query & NOAAAA_TRUST_DNS)
            LOGI("filter AAAA for trust upstream");
    }

    if (g_repeat_times > 1) LOGI("enable repeat mode, times: %u", (uint)g_repeat_times);
    if (g_reuse_port) LOGI("enable `SO_REUSEPORT` feature");
    LOGV("print the verbose running log");

    /* init ipset netlink socket */
    ipset_init_nlsocket();

    /* create listen socket */
    s_bind_sockfd = new_udp_socket(skaddr_family(&g_bind_skaddr));
    if (g_reuse_port) set_reuse_port(s_bind_sockfd);

    /* create remote socket */
    for (int i = 0; i <= SERVER_MAXIDX; ++i) {
        if (*g_remote_ipports[i])
            s_remote_sockfds[i] = new_udp_socket(skaddr_family(&g_remote_skaddrs[i]));
    }

    /* bind address to listen socket */
    unlikely_if (bind(s_bind_sockfd, &g_bind_skaddr.sa, skaddr_size(&g_bind_skaddr))) {
        LOGE("failed to bind address to socket: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* create epoll fd */
    unlikely_if ((s_epollfd = epoll_create1(0)) < 0) {
        LOGE("failed to create epoll fd: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* register epoll event */
    struct epoll_event ev, events[EPOLL_MAXEVENTS];

    /* listen socket readable event */
    ev.events = EPOLLIN;
    ev.data.u32 = BINDSOCK_MARK;
    unlikely_if (epoll_ctl(s_epollfd, EPOLL_CTL_ADD, s_bind_sockfd, &ev)) {
        LOGE("failed to register epoll event: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* remote socket readable event */
    for (int i = 0; i <= SERVER_MAXIDX; ++i) {
        if (s_remote_sockfds[i] < 0) continue;
        ev.events = EPOLLIN;
        ev.data.u32 = i;
        unlikely_if (epoll_ctl(s_epollfd, EPOLL_CTL_ADD, s_remote_sockfds[i], &ev)) {
            LOGE("failed to register epoll event: (%d) %s", errno, strerror(errno));
            return errno;
        }
    }

    /* run event loop (blocking here) */
    int timeout_ms = -1;

    for (;;) {
        int event_count = epoll_wait(s_epollfd, events, EPOLL_MAXEVENTS, timeout_ms);

        unlikely_if (event_count < 0)
            LOGE("epoll_wait() reported an error: (%d) %s", errno, strerror(errno));

        /* handle socket event */
        for (int i = 0; i < event_count; ++i) {
            uint32_t ev = events[i].events;
            uint32_t data = events[i].data.u32;

            unlikely_if (ev & EPOLLERR) {
                /* an error occurred */
                switch (data) {
                    case CHINADNS1_IDX:
                        LOGE("upstream server socket error(%s): (%d) %s", g_remote_ipports[CHINADNS1_IDX], errno, strerror(errno));
                        break;
                    case CHINADNS2_IDX:
                        LOGE("upstream server socket error(%s): (%d) %s", g_remote_ipports[CHINADNS2_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS1_IDX:
                        LOGE("upstream server socket error(%s): (%d) %s", g_remote_ipports[TRUSTDNS1_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS2_IDX:
                        LOGE("upstream server socket error(%s): (%d) %s", g_remote_ipports[TRUSTDNS2_IDX], errno, strerror(errno));
                        break;
                    case BINDSOCK_MARK:
                        LOGE("local udp listen socket error: (%d) %s", errno, strerror(errno));
                        break;
                }
            } else if (ev & EPOLLIN) {
                /* handle readable event */
                switch (data) {
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
                }
            }
        }

        /* handle timeout event */
        queryctx_t *cur, *tmp;
        int now = time(NULL), remain_sec;
        MYHASH_FOR(s_context_list, cur, tmp) {
            remain_sec = cur->request_time + g_upstream_timeout_sec - now;
            if (remain_sec <= 0) {
                handle_timeout_event(cur); //remove current entry
            } else {
                timeout_ms = remain_sec * 1000;
                break;
            }
        }
        if (MYHASH_CNT(s_context_list) <= 0U) timeout_ms = -1;
    }

    return 0;
}
