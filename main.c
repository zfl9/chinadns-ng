#define _GNU_SOURCE
#include "opt.h"
#include "log.h"
#include "net.h"
#include "ipset.h"
#include "dns.h"
#include "dnl.h"
#include "misc.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define MAX_EVENTS 8

#define PACKET_BUFSZ DNS_PACKET_MAXSIZE

#define SOCK_LIFETIME 60 /* for upstream socket */

struct u16_buf {
    u16 len;
    char buf[];
};

struct queryctx {
    u16                     unique_msgid;  /* [key] globally unique msgid */
    u16                     origin_msgid;  /* [value] associated original msgid */
    int                     request_time;  /* [value] query request timestamp */
    struct u16_buf *noalias trustdns_buf;  /* [value] {u16 len; char buf[];} */
    bool                    chinadns_got;  /* [value] received reply from china-dns */
    u8                      name_tag;      /* [value] domain name tag: gfw|chn|none */
    union skaddr            source_addr;   /* [value] associated client socket addr */
    myhash_hh               hh;            /* [metadata] used internally by `uthash` */
};

static int s_epollfd            = -1;
static int s_bind_sockfd        = -1;
static int s_upstream_sockfds[] = {[0 ... SERVER_MAXIDX] = -1};
static int s_sock_create_time   = 0; /* for upstream socket */

static u16              s_unique_msgid = 0;
static struct queryctx *s_context_list = NULL;

static void *noalias s_packet_buf                    = (char [PACKET_BUFSZ]){0};
static char          s_name_buf[DNS_NAME_MAXLEN + 1] = {0};
static char          s_ipstr_buf[INET6_ADDRSTRLEN]   = {0};

#define free_context(ctx) ({ \
    MYHASH_DEL(s_context_list, ctx); \
    free((ctx)->trustdns_buf); \
    free(ctx); \
})

static inline const char *filter_aaaa_by_tag(u8 name_tag) {
    if (is_filter_all_v6(g_noaaaa_query))
        return "all";

    switch (name_tag) {
        case NAME_TAG_GFW:
            return (g_noaaaa_query & NOAAAA_TAG_GFW) ? "tag_gfw" : NULL;
        case NAME_TAG_CHN:
            return (g_noaaaa_query & NOAAAA_TAG_CHN) ? "tag_chn" : NULL;
        case NAME_TAG_NONE:
            return (g_noaaaa_query & NOAAAA_TAG_NONE) ? "tag_none" : NULL;
        default:
            assert(0);
            return NULL;
    }
}

static inline void reply_with_no_answer(const union skaddr *noalias addr, socklen_t addrlen, void *noalias query, size_t querylen) {
    struct dns_header *header = query;
    header->qr = DNS_QR_REPLY;
    header->rcode = DNS_RCODE_NOERROR;
    unlikely_if (sendto(s_bind_sockfd, query, querylen, 0, &addr->sa, addrlen) < 0) {
        u16 port = 0;
        skaddr_parse(addr, s_ipstr_buf, &port);
        log_error("failed to send reply to %s#%u: (%d) %s", s_ipstr_buf, (uint)port, errno, strerror(errno));
    }
}

static void update_upstream_sock(int now) {
    likely_if (s_sock_create_time && now - s_sock_create_time < SOCK_LIFETIME)
        return;

    if (s_sock_create_time)
        log_verbose("create new socket, old socket is used for %d seconds", now - s_sock_create_time);

    if (MYHASH_CNT(s_context_list) > 0U) {
        log_verbose("there are %u unfinished queries, continue to use the old", MYHASH_CNT(s_context_list));
        assert(s_sock_create_time);
        return;
    }

    s_sock_create_time = now;

    /* create upstream socket */
    for (int i = 0; i <= SERVER_MAXIDX; ++i) {
        if (!g_upstream_addrs[i]) continue;

        if (s_upstream_sockfds[i] >= 0)
            close(s_upstream_sockfds[i]); /* fd will be auto removed from the interest-list when it is closed */

        s_upstream_sockfds[i] = new_udp_socket(skaddr_family(&g_upstream_skaddrs[i]), false);

        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.u32 = i,
        };
        unlikely_if (epoll_ctl(s_epollfd, EPOLL_CTL_ADD, s_upstream_sockfds[i], &ev)) {
            log_error("failed to register epoll event: (%d) %s", errno, strerror(errno));
            exit(errno);
        }
    }
}

static void handle_local_packet(void) {
    unlikely_if (MYHASH_CNT(s_context_list) >= 65536U) { /* range:0~65535, count:65536 */
        log_warning("unique_msg_id is not enough, refused to serve");
        return;
    }

    union skaddr source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    socklen_t source_addrlen = sizeof(source_addr);
    ssize_t packet_len = recvfrom(s_bind_sockfd, s_packet_buf, PACKET_BUFSZ, 0, &source_addr.sa, &source_addrlen);

    if (packet_len < 0) {
        unlikely_if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_error("failed to recv from bind socket: (%d) %s", errno, strerror(errno));
        return;
    }

    char *name_buf = (g_verbose || g_dnl_nitems) ? s_name_buf : NULL;
    int namelen = 0;
    unlikely_if (!dns_check_query(s_packet_buf, packet_len, name_buf, &namelen)) return;

    u16 qtype = dns_qtype(s_packet_buf, namelen);
    int ascii_namelen = dns_ascii_namelen(namelen);
    u8 name_tag = (ascii_namelen > 0 && g_dnl_nitems)
        ? get_name_tag(s_name_buf, ascii_namelen) : g_default_tag;

    if_verbose {
        u16 port = 0;
        skaddr_parse(&source_addr, s_ipstr_buf, &port);
        log_info("query [%s] from %s#%u (%u)", s_name_buf, s_ipstr_buf, (uint)port, (uint)s_unique_msgid);
    }

    if (g_noaaaa_query & (NOAAAA_TAG_GFW | NOAAAA_TAG_CHN | NOAAAA_TAG_NONE) && qtype == DNS_RECORD_TYPE_AAAA) {
        const char *rule = filter_aaaa_by_tag(name_tag);
        if (rule) {
            log_verbose("filter [%s] AAAA query, rule: %s", s_name_buf, rule);
            reply_with_no_answer(&source_addr, source_addrlen, s_packet_buf, packet_len);
            return;
        }
    }

    int now = time(NULL);
    update_upstream_sock(now);

    u16 unique_msgid = s_unique_msgid++;
    struct dns_header *dns_header = s_packet_buf;
    u16 origin_msgid = dns_header->id;
    dns_header->id = unique_msgid; /* replace with new msgid */

    bool sent = false;

    struct iovec iov;
    struct mmsghdr msgv[MAX_REPEAT_TIMES];
    set_iov(&iov, s_packet_buf, packet_len);

    for (int i = 0; i <= SERVER_MAXIDX; ++i) {
        if (s_upstream_sockfds[i] < 0) continue;

        u8 msg_n = 1;
        if (is_chinadns_idx(i)) {
            if (name_tag == NAME_TAG_GFW) continue;
            if (g_noaaaa_query & NOAAAA_CHINA_DNS && qtype == DNS_RECORD_TYPE_AAAA) continue;
        } else {
            if (name_tag == NAME_TAG_CHN) continue;
            if (g_noaaaa_query & NOAAAA_TRUST_DNS && qtype == DNS_RECORD_TYPE_AAAA) continue;
            msg_n = g_repeat_times;
        }

        /* for no-aaaa, don't care about the result of `sendmmsg` */
        sent = true;

        union skaddr *addr = &g_upstream_skaddrs[i];
        socklen_t addrlen = skaddr_size(addr);

        set_msghdr(&msgv[0].msg_hdr, &iov, 1, &addr->sa, addrlen);
        for (u8 msg_i = 1; msg_i < msg_n; ++msg_i) msgv[msg_i] = msgv[0];

        log_verbose("forward [%s] to %s (%s)", s_name_buf, g_upstream_addrs[i], is_chinadns_idx(i) ? "chinadns" : "trustdns");

        int n_sent = x_sendmmsg(s_upstream_sockfds[i], msgv, msg_n, 0);
        unlikely_if (n_sent != msg_n) {
            if (n_sent < 0)
                log_error("failed to send query to %s: (%d) %s", g_upstream_addrs[i], errno, strerror(errno));
            else
                log_warning("send query to %s: %d != %u (kernel buffer may not be enough)", g_upstream_addrs[i], n_sent, (uint)msg_n);
        }
    }

    if (!sent) { /* caused by no aaaa query (china or trust) */
        dns_header->id = origin_msgid;
        assert(g_noaaaa_query & (NOAAAA_CHINA_DNS | NOAAAA_TRUST_DNS));
        log_verbose("filter [%s] AAAA query, rule: %s", s_name_buf, (g_noaaaa_query & NOAAAA_CHINA_DNS) ? "chinadns" : "trustdns");
        reply_with_no_answer(&source_addr, source_addrlen, s_packet_buf, packet_len);
        return;
    }

    struct queryctx *context = malloc(sizeof(*context));
    context->unique_msgid = unique_msgid;
    context->origin_msgid = origin_msgid;
    context->request_time = now;
    context->trustdns_buf = NULL;
    context->chinadns_got = false;
    context->name_tag = name_tag;
    memcpy(&context->source_addr, &source_addr, sizeof(source_addr));
    MYHASH_ADD(s_context_list, context, &context->unique_msgid, sizeof(context->unique_msgid));
}

static inline void remove_answer(void *noalias packet_buf, ssize_t *noalias packet_len, int namelen) {
    struct dns_header *h = packet_buf;
    h->rcode = DNS_RCODE_NOERROR;
    h->answer_count = 0;
    h->authority_count = 0;
    h->additional_count = 0;
    *packet_len = sizeof(struct dns_header) + namelen + sizeof(struct dns_query);
}

/* name_tag: NAME_TAG_NONE */
static inline bool use_china_reply(void *noalias packet_buf, ssize_t *noalias packet_len, int namelen) {
    u16 qtype = dns_qtype(packet_buf, namelen);
    if (qtype != DNS_RECORD_TYPE_A && qtype != DNS_RECORD_TYPE_AAAA)
        return true; /* only filter A/AAAA reply */

    /* handle no-aaaa filter */
    bool only_chinadns = g_noaaaa_query & NOAAAA_TRUST_DNS && qtype == DNS_RECORD_TYPE_AAAA;
    if (only_chinadns && !(g_noaaaa_query & NOAAAA_CHINA_IPCHK))
        return true;

    switch (dns_test_ip(packet_buf, *packet_len, namelen)) {
        case DNS_IPCHK_IS_CHNIP:
            return true;

        case DNS_IPCHK_NOT_CHNIP:
            if (only_chinadns) {
                log_verbose("answer ip is not china ip, change to no-answer (AAAA)");
                remove_answer(packet_buf, packet_len, namelen);
                return true;
            }
            return false;

        case DNS_IPCHK_NOT_FOUND:
            if (only_chinadns) return true;
            log_verbose("no ip found in reply, see as %s", g_noip_as_chnip ? "chnip (accept)" : "non-chnip (drop)");
            return g_noip_as_chnip;

        case DNS_IPCHK_BAD_PACKET:
            return false;

        default:
            assert(0);
            return false;
    }
}

/* name_tag: NAME_TAG_NONE && !chinadns_got */
static inline bool use_trust_reply(void *noalias packet_buf, ssize_t *noalias packet_len, int namelen) {
    u16 qtype = dns_qtype(packet_buf, namelen);

    bool only_trustdns = g_noaaaa_query & NOAAAA_CHINA_DNS && qtype == DNS_RECORD_TYPE_AAAA;
    if (!only_trustdns)
        return false; /* waiting for chinadns return */

    if (g_noaaaa_query & NOAAAA_TRUST_IPCHK && dns_test_ip(packet_buf, *packet_len, namelen) == DNS_IPCHK_NOT_CHNIP) {
        log_verbose("answer ip is not china ip, change to no-answer (AAAA)");
        remove_answer(packet_buf, packet_len, namelen);
    }
    return true;
}

static void handle_remote_packet(int index) {
    int sockfd = s_upstream_sockfds[index];
    const char *addr = g_upstream_addrs[index];
    ssize_t packet_len = recvfrom(sockfd, s_packet_buf, PACKET_BUFSZ, 0, NULL, NULL);

    if (packet_len < 0) {
        unlikely_if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_error("failed to recv from %s: (%d) %s", addr, errno, strerror(errno));
        return;
    }

    char *name_buf = g_verbose ? s_name_buf : NULL;
    int namelen = 0;
    unlikely_if (!dns_check_reply(s_packet_buf, packet_len, name_buf, &namelen)) return;

    struct queryctx *context = NULL;
    struct dns_header *dns_header = s_packet_buf;
    MYHASH_GET(s_context_list, context, &dns_header->id, sizeof(dns_header->id));
    if (!context) {
        log_verbose("reply [%s] from %s (%u), result: ignore", s_name_buf, addr, (uint)dns_header->id);
        return;
    }

    void *reply_buffer = s_packet_buf;
    ssize_t reply_length = packet_len;

    if (is_chinadns_idx(index)) {
        if (context->name_tag == NAME_TAG_CHN || use_china_reply(reply_buffer, &reply_length, namelen)) {
            log_verbose("reply [%s] from %s (%u), result: accept", s_name_buf, addr, (uint)dns_header->id);
            if (context->trustdns_buf)
                log_verbose("reply [%s] from <previous-trustdns> (%u), result: filter", s_name_buf, (uint)dns_header->id);
            if (g_add_tagchn_ip && context->name_tag == NAME_TAG_CHN) {
                log_verbose("add the answer ip of name-tag:chn [%s] to ipset", s_name_buf);
                dns_add_ip(reply_buffer, reply_length, namelen, true);
            }
        } else {
            log_verbose("reply [%s] from %s (%u), result: filter", s_name_buf, addr, (uint)dns_header->id);
            if (context->trustdns_buf) { /* trustdns returns before chinadns */
                log_verbose("reply [%s] from <previous-trustdns> (%u), result: accept", s_name_buf, (uint)dns_header->id);
                reply_buffer = context->trustdns_buf->buf;
                reply_length = context->trustdns_buf->len;
            } else {
                context->chinadns_got = true;
                return;
            }
        }
    } else {
        if (context->name_tag == NAME_TAG_GFW || context->chinadns_got || use_trust_reply(reply_buffer, &reply_length, namelen)) {
            log_verbose("reply [%s] from %s (%u), result: accept", s_name_buf, addr, (uint)dns_header->id);
            if (g_add_taggfw_ip && context->name_tag == NAME_TAG_GFW) {
                log_verbose("add the answer ip of name-tag:gfw [%s] to ipset", s_name_buf);
                dns_add_ip(reply_buffer, reply_length, namelen, false);
            }
        } else {
            /* trustdns returns before chinadns */
            if (!context->trustdns_buf) {
                log_verbose("reply [%s] from %s (%u), result: delay", s_name_buf, addr, (uint)dns_header->id);
                context->trustdns_buf = malloc(sizeof(*context->trustdns_buf) + packet_len);
                context->trustdns_buf->len = packet_len; /* dns reply length */
                memcpy(context->trustdns_buf->buf, s_packet_buf, packet_len);
            } else {
                log_verbose("reply [%s] from %s (%u), result: ignore", s_name_buf, addr, (uint)dns_header->id);
            }
            return;
        }
    }

    dns_header = reply_buffer;
    dns_header->id = context->origin_msgid; /* replace with old msgid */
    socklen_t source_addrlen = skaddr_size(&context->source_addr);
    unlikely_if (sendto(s_bind_sockfd, reply_buffer, reply_length, 0, &context->source_addr.sa, source_addrlen) < 0) {
        u16 port = 0;
        skaddr_parse(&context->source_addr, s_ipstr_buf, &port);
        log_error("failed to send reply to %s#%u: (%d) %s", s_ipstr_buf, (uint)port, errno, strerror(errno));
    }
    free_context(context);
}

static void handle_timeout_event(struct queryctx *context) {
    log_verbose("upstream reply timeout, unique msgid: %u", (uint)context->unique_msgid);
    free_context(context);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    opt_parse(argc, argv);

    net_init();

    log_info("local listen addr: %s#%u", g_bind_ip, (uint)g_bind_port);

    if (g_upstream_addrs[CHINADNS1_IDX])
        log_info("chinadns server#1: %s", g_upstream_addrs[CHINADNS1_IDX]);
    if (g_upstream_addrs[CHINADNS2_IDX])
        log_info("chinadns server#2: %s", g_upstream_addrs[CHINADNS2_IDX]);
    if (g_upstream_addrs[TRUSTDNS1_IDX])
        log_info("trustdns server#1: %s", g_upstream_addrs[TRUSTDNS1_IDX]);
    if (g_upstream_addrs[TRUSTDNS2_IDX])
        log_info("trustdns server#2: %s", g_upstream_addrs[TRUSTDNS2_IDX]);

    dnl_init();
    log_info("default domain name tag: %s", nametag_val2name(g_default_tag));

    bool need_ipset = g_add_tagchn_ip || g_add_taggfw_ip || g_default_tag == NAME_TAG_NONE;
    if (need_ipset) ipset_init();

    if (is_filter_all_v6(g_noaaaa_query))
        log_info("filter AAAA for all name");
    else if (g_noaaaa_query != 0) {
        if (g_noaaaa_query & NOAAAA_TAG_CHN)
            log_info("filter AAAA for tag_chn name");
        if (g_noaaaa_query & NOAAAA_TAG_GFW)
            log_info("filter AAAA for tag_gfw name");
        if (g_noaaaa_query & NOAAAA_TAG_NONE)
            log_info("filter AAAA for tag_none name");
        if (g_noaaaa_query & NOAAAA_CHINA_DNS)
            log_info("filter AAAA for china upstream");
        if (g_noaaaa_query & NOAAAA_TRUST_DNS)
            log_info("filter AAAA for trust upstream");
        if (g_noaaaa_query & NOAAAA_CHINA_IPCHK)
            log_info("filter AAAA, check ip for chinadns");
        if (g_noaaaa_query & NOAAAA_TRUST_IPCHK)
            log_info("filter AAAA, check ip for trustdns");
    }

    log_info("dns query timeout: %d seconds", g_upstream_timeout_sec);

    if (g_repeat_times > 1) log_info("enable repeat mode, times: %u", (uint)g_repeat_times);

    log_info("%s no-ip reply from chinadns", g_noip_as_chnip ? "accept" : "filter");

    if (g_reuse_port) log_info("enable `SO_REUSEPORT` feature");

    log_verbose("print the verbose running log");

    /* create listen socket */
    s_bind_sockfd = new_udp_socket(skaddr_family(&g_bind_skaddr), true);
    if (g_reuse_port) set_reuse_port(s_bind_sockfd);

    /* bind address to listen socket */
    unlikely_if (bind(s_bind_sockfd, &g_bind_skaddr.sa, skaddr_size(&g_bind_skaddr))) {
        log_error("failed to bind address to socket: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* create epoll fd */
    unlikely_if ((s_epollfd = epoll_create1(0)) < 0) {
        log_error("failed to create epoll fd: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* register epoll event */
    struct epoll_event ev, events[MAX_EVENTS];

    /* listen socket readable event */
    ev.events = EPOLLIN;
    ev.data.u32 = BINDSOCK_MARK;
    unlikely_if (epoll_ctl(s_epollfd, EPOLL_CTL_ADD, s_bind_sockfd, &ev)) {
        log_error("failed to register epoll event: (%d) %s", errno, strerror(errno));
        return errno;
    }

    /* run event loop (blocking here) */
    int timeout_ms = -1;

    for (;;) {
        int event_count = retry_EINTR(epoll_wait(s_epollfd, events, MAX_EVENTS, timeout_ms));

        unlikely_if (event_count < 0)
            log_error("epoll_wait() reported an error: (%d) %s", errno, strerror(errno));

        /* handle socket event */
        for (int i = 0; i < event_count; ++i) {
            u32 ev = events[i].events;
            u32 data = events[i].data.u32;

            unlikely_if (ev & EPOLLERR) {
                /* an error occurred */
                switch (data) {
                    case CHINADNS1_IDX:
                        log_error("upstream socket error %s: (%d) %s", g_upstream_addrs[CHINADNS1_IDX], errno, strerror(errno));
                        break;
                    case CHINADNS2_IDX:
                        log_error("upstream socket error %s: (%d) %s", g_upstream_addrs[CHINADNS2_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS1_IDX:
                        log_error("upstream socket error %s: (%d) %s", g_upstream_addrs[TRUSTDNS1_IDX], errno, strerror(errno));
                        break;
                    case TRUSTDNS2_IDX:
                        log_error("upstream socket error %s: (%d) %s", g_upstream_addrs[TRUSTDNS2_IDX], errno, strerror(errno));
                        break;
                    case BINDSOCK_MARK:
                        log_error("listen socket error: (%d) %s", errno, strerror(errno));
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
        struct queryctx *cur, *tmp;
        int now = time(NULL), remain_sec;

        MYHASH_FOR(s_context_list, cur, tmp) {
            remain_sec = cur->request_time + g_upstream_timeout_sec - now;
            if (remain_sec <= 0) {
                handle_timeout_event(cur); /* remove current entry */
            } else {
                timeout_ms = remain_sec * 1000;
                break;
            }
        }

        if (MYHASH_CNT(s_context_list) <= 0U)
            timeout_ms = -1;
    }

    return 0;
}
