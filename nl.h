#pragma once

#include "misc.h"
#include "log.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>

/* #include <linux/netfilter/ipset/ip_set.h> */
#define NFNETLINK_V0 0 /* nfgenmsg.version */

/* #include <linux/netfilter/nfnetlink.h> */
struct nfgenmsg {
    uint8_t     nfgen_family;   /* AF_xxx */
    uint8_t     version;        /* nfnetlink version */
    uint16_t    res_id;         /* resource id */
};

void nl_init(void);

/* nl_header:{data_type} | data_header | data_nlattrs... */

#define nlmsg_set_hdr(nlmsg, msglen, datatype, flags) ({ \
    (nlmsg)->nlmsg_len = (msglen); \
    (nlmsg)->nlmsg_type = (datatype); \
    (nlmsg)->nlmsg_flags = (flags); \
    (nlmsg); \
})

#define nlmsg_init_hdr(nlmsg, datatype, flags) \
    nlmsg_set_hdr(nlmsg, NLMSG_HDRLEN, datatype, flags)

#define nlmsg_space_ok(nlmsg, bufsz, datalen) \
    ((nlmsg)->nlmsg_len + NLMSG_ALIGN(datalen) <= (bufsz))

#define nlmsg_inc_len(nlmsg, bufsz, datalen) ({ \
    ((nlmsg)->nlmsg_len += NLMSG_ALIGN(datalen)); \
    unlikely_if ((nlmsg)->nlmsg_len > (bufsz)) { \
        LOGE("BUG: nlmsg_len:%lu > bufsz:%lu\n", \
            (ulong)(nlmsg)->nlmsg_len, (ulong)(bufsz)); \
        abort(); \
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
    nlmsg_inc_len(nlmsg, bufsz, datalen);
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
    uint16_t attrtype, const void *noalias data, size_t datalen)
{
    struct nlattr *nla = nlmsg_add_data(nlmsg, bufsz, NULL, nla_size_calc(datalen));
    nla->nla_len = nla_len_calc(datalen);
    nla->nla_type = (attrtype);
    if (data) memcpy(nla_data(nla), data, datalen);
    return nla;
}

#define nlmsg_add_nest_nla(nlmsg, bufsz, attrtype) \
    nlmsg_add_nla(nlmsg, bufsz, (attrtype) | NLA_F_NESTED, NULL, 0)

#define nlmsg_end_nest_nla(nlmsg, nest_nla) \
    ((nest_nla)->nla_len = nlmsg_dataend(nlmsg) - (void *)(nest_nla))

bool nlmsg_send(struct nlmsghdr *noalias nlmsg);

bool nlmsg_recv(void *noalias buf, ssize_t *noalias sz);

/* nlmsgerr */
#define nlmsg_errcode(nlmsg) \
    (((struct nlmsgerr *)NLMSG_DATA(nlmsg))->error)
