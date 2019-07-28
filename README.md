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
Go to the source directory, execute `make`, or execute the shell command:
```bash
gcc -std=c99 -Wall -Wextra -O3 -s -o chinadns-ng *.c
```

# Options
```
$ ./chinadns-ng --help
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
- `china-dns` supports up to two upstream settings, and `trust-dns` is the same.
- `ipset-name4` is used to specify the ipv4 address/net of China.
- `ipset-name6` is used to specify the ipv6 address/net of China.
- `reuse-port` can be used to implement multi-process load balancing.
- `verbose` is disabled by default because it is faster.
