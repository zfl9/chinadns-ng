#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

#define MSG_BUFFER_SIZE 1024
#define QUERY_IPSET_SETNAME "chnroute"
#define QUERY_IPSET_IPADDR "114.114.114.114"

int main() {
    /* create netlink socket */
    int sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
    if (sockfd < 0) {
        perror("socket() failed");
        return errno;
    }

    /* declare src & dest addr */
    struct sockaddr_nl src_addr = {.nl_family = AF_NETLINK, .nl_pid = getpid()};
    struct sockaddr_nl dest_addr = {.nl_family = AF_NETLINK, .nl_pid = 0}; // to kernel

    /* bind src addr for self */
    if (bind(sockfd, (void *)&src_addr, sizeof(src_addr))) {
        perror("bind() failed");
        return errno;
    }

    /* msg buffer (array) */
    char msg_buffer[MSG_BUFFER_SIZE] = {0};
    void *buffer = msg_buffer;

    /* netlink msg */
    struct nlmsghdr *nlmsg_ptr = buffer;
    nlmsg_ptr->nlmsg_len = NLMSG_ALIGN(sizeof(struct nlmsghdr));
    nlmsg_ptr->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST;
    nlmsg_ptr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlmsg_ptr->nlmsg_seq = 0; // msg seqId
    nlmsg_ptr->nlmsg_pid = 0; // to kernel

    /* netfilter msg */
    struct nfgenmsg *nfgenmsg_ptr = buffer + nlmsg_ptr->nlmsg_len;
    nfgenmsg_ptr->nfgen_family = AF_INET;
    nfgenmsg_ptr->version = NFNETLINK_V0;
    nfgenmsg_ptr->res_id = htons(0);
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(sizeof(struct nfgenmsg));

    /* netlink msg attr [IPSET_PROTOCOL] */
    struct nlattr *nlattr_ptr = buffer + nlmsg_ptr->nlmsg_len;
    nlattr_ptr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + sizeof(uint8_t);
    nlattr_ptr->nla_type = IPSET_ATTR_PROTOCOL;
    *(uint8_t *)((void *)nlattr_ptr + NLMSG_ALIGN(sizeof(struct nlattr))) = IPSET_PROTOCOL;
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(nlattr_ptr->nla_len);

    /* netlink msg attr [IPSET_SETNAME] */
    size_t setname_datalen = strlen(QUERY_IPSET_SETNAME) + 1;
    nlattr_ptr = buffer + nlmsg_ptr->nlmsg_len;
    nlattr_ptr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + setname_datalen;
    nlattr_ptr->nla_type = IPSET_ATTR_SETNAME;
    memcpy((void *)nlattr_ptr + NLMSG_ALIGN(sizeof(struct nlattr)), QUERY_IPSET_SETNAME, setname_datalen);
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(nlattr_ptr->nla_len);

    /* netlink msg_attr [IPSET_DATA_NESTED] */
    struct nlattr *nlattr_ptr0 = buffer + nlmsg_ptr->nlmsg_len;
    nlattr_ptr0->nla_type = NLA_F_NESTED | IPSET_ATTR_DATA;
    nlattr_ptr0->nla_len = NLMSG_ALIGN(sizeof(struct nlattr));
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(sizeof(struct nlattr));

    /* netlink msg_attr [IPSET_IP_NESTED] */
    struct nlattr *nlattr_ptr1 = buffer + nlmsg_ptr->nlmsg_len;
    nlattr_ptr1->nla_type = NLA_F_NESTED | IPSET_ATTR_IP;
    nlattr_ptr1->nla_len = NLMSG_ALIGN(sizeof(struct nlattr));
    nlattr_ptr0->nla_len += NLMSG_ALIGN(sizeof(struct nlattr));
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(sizeof(struct nlattr));

    /* netlink msg_attr [IPSET_IP_DATA] */
    uint32_t query_addr = 0; inet_pton(AF_INET, QUERY_IPSET_IPADDR, &query_addr);
    nlattr_ptr = buffer + nlmsg_ptr->nlmsg_len;
    nlattr_ptr->nla_len = NLMSG_ALIGN(sizeof(struct nlattr)) + sizeof(uint32_t);
    nlattr_ptr->nla_type = IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER;
    *(uint32_t *)((void *)nlattr_ptr + NLMSG_ALIGN(sizeof(struct nlattr))) = query_addr;
    nlattr_ptr1->nla_len += NLMSG_ALIGN(nlattr_ptr->nla_len);
    nlattr_ptr0->nla_len += NLMSG_ALIGN(nlattr_ptr->nla_len);
    nlmsg_ptr->nlmsg_len += NLMSG_ALIGN(nlattr_ptr->nla_len);

    clock_t beg = clock();

    /* send netlink msg to ipset module */
    if (sendto(sockfd, nlmsg_ptr, nlmsg_ptr->nlmsg_len, 0, (void *)&dest_addr, sizeof(dest_addr)) == -1) {
        perror("sendto() failed");
        return errno;
    }

    /* recv netlink msg from ipset module */
    socklen_t addrlen = sizeof(dest_addr);
    if (recvfrom(sockfd, buffer, MSG_BUFFER_SIZE, 0, (void *)&dest_addr, &addrlen) == -1) {
        perror("recvfrom() failed");
        return errno;
    }

    clock_t end = clock();
    printf("execute time: %.5f ms\n", (double) (end - beg) / CLOCKS_PER_SEC * 1000);

    /* show ipset test result */
    nlmsg_ptr = buffer;
    if (nlmsg_ptr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *nlmsgerr_ptr = NLMSG_DATA(nlmsg_ptr);
        if (nlmsgerr_ptr->error == 0) {
            printf("ip(%s) exists in set(%s)\n", QUERY_IPSET_IPADDR, QUERY_IPSET_SETNAME);
        } else {
            printf("ip(%s) does not exists in set(%s)\n", QUERY_IPSET_IPADDR, QUERY_IPSET_SETNAME);
        }
    }

    return 0;
}
