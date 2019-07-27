# ChinaDNS-NG
A new version of [ChinaDNS](https://github.com/shadowsocks/ChinaDNS), refactoring with `epoll` and `ipset(netlink)`.
- It is much faster than the original version.
- Full support for ipv4 and ipv6.
- Compatible with EDNS requests and responses.
- Manually specify upstream dns instead of automatic identification.
- Can handle the reserved ip address correctly.
- Finally, it works better with [ss-tproxy](https://github.com/zfl9/ss-tproxy).

// TODO
