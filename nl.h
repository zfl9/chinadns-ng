#pragma once

#include "misc.h"
#include "log.h"
#include <string.h>
#include <assert.h>
#include <linux/netlink.h>

/* create netlink-socket (blocking mode) */
int nl_sock_create(int protocol, u32 *noalias src_portid);

#define nlmsg_len_inc(nlmsg, bufsz, datalen) ({ \
    (nlmsg)->nlmsg_len += NLMSG_ALIGN(datalen); \
    unlikely_if ((nlmsg)->nlmsg_len > (bufsz)) { \
        log_fatal("nlmsg_len:%lu > bufsz:%lu", \
            (ulong)(nlmsg)->nlmsg_len, (ulong)(bufsz)); \
    } \
})

/* start address of data */
#define nlmsg_data(nlmsg) \
    NLMSG_DATA(nlmsg)

/* end address of data */
#define nlmsg_dataend(nlmsg) \
    ((void *)(nlmsg) + (nlmsg)->nlmsg_len)

static inline void *nlmsg_add_data(
    struct nlmsghdr *noalias nlmsg, size_t bufsz,
    const void *noalias data, size_t datalen)
{
    void *p = nlmsg_dataend(nlmsg);
    nlmsg_len_inc(nlmsg, bufsz, datalen);
    if (data) memcpy(p, data, datalen);
    return p;
}

#define nla_len_calc(datalen) \
    (NLA_HDRLEN + (datalen))

#define nla_size_calc(datalen) \
    (NLA_HDRLEN + NLA_ALIGN(datalen))

#define nla_data(nla) \
    ((void *)(nla) + NLA_HDRLEN)

static inline struct nlattr *nlmsg_add_nla(
    struct nlmsghdr *noalias nlmsg, size_t bufsz,
    u16 attrtype, const void *noalias data, size_t datalen)
{
    struct nlattr *nla = nlmsg_add_data(nlmsg, bufsz, NULL, nla_size_calc(datalen));
    nla->nla_len = nla_len_calc(datalen);
    nla->nla_type = attrtype;
    if (data) memcpy(nla_data(nla), data, datalen);
    return nla;
}

#define nlmsg_add_nest_nla(nlmsg, bufsz, attrtype) \
    nlmsg_add_nla(nlmsg, bufsz, (attrtype) | NLA_F_NESTED, NULL, 0)

#define nlmsg_end_nest_nla(nlmsg, nest_nla) \
    ((nest_nla)->nla_len = nlmsg_dataend(nlmsg) - (void *)(nest_nla))

/* nlmsgerr */
#define nlmsg_errcode(nlmsg) ({ \
    assert((nlmsg)->nlmsg_type == NLMSG_ERROR); \
    -cast(const struct nlmsgerr *, nlmsg_data(nlmsg))->error; \
})
