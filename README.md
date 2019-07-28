# ChinaDNS-NG
A new version of [ChinaDNS](https://github.com/shadowsocks/ChinaDNS), refactoring with `epoll` and `ipset(netlink)`.
- It is much faster than the original version.
- Full support for ipv4 and ipv6.
- Compatible with EDNS requests and responses.
- Manually specify upstream dns instead of automatic identification.
- Can handle the reserved ip address correctly.
- Finally, it works better with [ss-tproxy](https://github.com/zfl9/ss-tproxy).

> Although there have been many changes, the core judgment mechanism has not changed.

# Compile
Enter to the source directory, execute `make && sudo make install`, the default installation path is `/usr/local/bin`, you can also install to other directories, such as `sudo make install DESTDIR=/opt/local/bin`.

# Options
```
$ chinadns-ng --help
usage: chinadns-ng <options...>. the existing options are as follows:
 -b, --bind-addr <ip-address>         listen address, default: 127.0.0.1
 -l, --bind-port <port-number>        listen port number, default: 65353
 -c, --china-dns <ip[#port],...>      china dns server, default: <114DNS>
 -t, --trust-dns <ip[#port],...>      trust dns server, default: <GoogleDNS>
 -4, --ipset-name4 <ipv4-setname>     ipset ipv4 set name, default: chnroute
 -6, --ipset-name6 <ipv6-setname>     ipset ipv6 set name, default: chnroute6
 -o, --timeout-sec <query-timeout>    timeout of the upstream dns, default: 5
 -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
 -v, --verbose                        print the verbose log, default: <disabled>
 -V, --version                        print `chinadns-ng` version number and exit
 -h, --help                           print `chinadns-ng` help information and exit
bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
```

- The default port number of the upstream dns server is `53`.
- `china-dns` supports up to two upstream settings, `trust-dns` is also.
- `ipset-name4` is used to specify the ipv4 address/net of China.
- `ipset-name6` is used to specify the ipv6 address/net of China.
- `reuse-port` can be used to implement multi-process load balancing.
- `verbose` is disabled by default because it is faster.

# Principle
- After `chinadns-ng` starts, it will create a `listening socket`, N `upstream sockets` (N: number of upstream servers).
- The `listening socket` is used to receive the `dns query` of the local client and send the verified upstream `dns reply`.
- The `upstream socket` is used for data interaction with the upstream server. ie send `dns query` and receive `dns reply`.
- When the `listening socket` receives the `dns query`, it performs a basic check and sends it to all upstream servers.
- When receiving a `dns reply` from the upstream of the `china-dns`, it checks whether the ipv4/ipv6 address contained in it is in `chnroute/chnroute6`. If it matches, the check passes and sends it to the requesting client. If it does not match , discard it directly, and then wait for the `dns reply` of the `trust-dns`.
- When receiving a `dns reply` from the upstream of the `trust-dns`, perform a simple dns header check and then send it to the requesting client.
- So here are a few things to pay special attention to:
  - The `dns reply` of the `trust-dns` must be sufficiently trusted. Since the domestic network environment is too complicated, it is recommended to always let the `trust-dns` pass the `proxy`. If you are using `ss-tproxy`, then there is no problem, `ss-tproxy` will do it for you.
  - In addition, if you need to make `chinadns` and `chinadns-ng` work properly, you need to make sure that the response upstream of `china-dns` always arrives earlier than the response upstream of `trust-dns`. This is usually not a problem because the `trust-dns` through the network proxy is slower than the direct access to `china-dns`.
