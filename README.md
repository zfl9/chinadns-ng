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

# Running and testing
First, install the `ipset` and import the `chnroute` and `chnroute6` lists:
```bash
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset
```

Then, run `chinadns-ng` in the shell (note that you need to have the `trust-dns` pass the proxy):
```bash
$ chinadns-ng -v
2019-07-28 09:26:39 INF: [main] local listen addr: 127.0.0.1#65353
2019-07-28 09:26:39 INF: [main] chinadns server#1: 114.114.114.114#53
2019-07-28 09:26:39 INF: [main] trustdns server#1: 8.8.8.8#53
2019-07-28 09:26:39 INF: [main] ipset ip4 setname: chnroute
2019-07-28 09:26:39 INF: [main] ipset ip6 setname: chnroute6
2019-07-28 09:26:39 INF: [main] dns query timeout: 5 seconds
2019-07-28 09:26:39 INF: [main] print the verbose running log
```

Then, install the `dig` to test `chinadns-ng`, the simplest test is as follows
```bash
# query A record for www.baidu.com
$ dig @127.0.0.1 -p65353 www.baidu.com     

; <<>> DiG 9.14.3 <<>> @127.0.0.1 -p65353 www.baidu.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47610
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.baidu.com.			IN	A

;; ANSWER SECTION:
www.baidu.com.		3577	IN	CNAME	www.a.shifen.com.
www.a.shifen.com.	3577	IN	A	183.232.231.172
www.a.shifen.com.	3577	IN	A	183.232.231.174

;; Query time: 14 msec
;; SERVER: 127.0.0.1#65353(127.0.0.1)
;; WHEN: Sun Jul 28 09:31:11 CST 2019
;; MSG SIZE  rcvd: 104
```
```bash
# query AAAA record for ipv6.baidu.com
$ dig @127.0.0.1 -p65353 ipv6.baidu.com AAAA

; <<>> DiG 9.14.3 <<>> @127.0.0.1 -p65353 ipv6.baidu.com AAAA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17498
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ipv6.baidu.com.			IN	AAAA

;; ANSWER SECTION:
ipv6.baidu.com.		3559	IN	AAAA	2400:da00:2::29

;; Query time: 22 msec
;; SERVER: 127.0.0.1#65353(127.0.0.1)
;; WHEN: Sun Jul 28 09:31:15 CST 2019
;; MSG SIZE  rcvd: 71
```
```bash
# the output of chinadns-ng
2019-07-28 09:31:11 INF: [handle_local_packet] query [www.baidu.com] from 127.0.0.1#20942
2019-07-28 09:31:11 INF: [handle_remote_packet] reply [www.baidu.com] from 114.114.114.114#53, result: pass
2019-07-28 09:31:11 INF: [handle_remote_packet] reply [www.baidu.com] from 8.8.8.8#53, result: pass
2019-07-28 09:31:15 INF: [handle_local_packet] query [ipv6.baidu.com] from 127.0.0.1#40293
2019-07-28 09:31:15 INF: [handle_remote_packet] reply [ipv6.baidu.com] from 114.114.114.114#53, result: pass
2019-07-28 09:31:15 INF: [handle_remote_packet] reply [ipv6.baidu.com] from 8.8.8.8#53, result: pass
```

```bash
# query A record for www.google.com
$ dig @127.0.0.1 -p65353 www.google.com     

; <<>> DiG 9.14.3 <<>> @127.0.0.1 -p65353 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14754
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.google.com.            IN  A

;; ANSWER SECTION:
www.google.com.     3437    IN  A   74.125.24.147
www.google.com.     3437    IN  A   74.125.24.106
www.google.com.     3437    IN  A   74.125.24.105
www.google.com.     3437    IN  A   74.125.24.99
www.google.com.     3437    IN  A   74.125.24.103
www.google.com.     3437    IN  A   74.125.24.104

;; Query time: 60 msec
;; SERVER: 127.0.0.1#65353(127.0.0.1)
;; WHEN: Sun Jul 28 09:31:24 CST 2019
;; MSG SIZE  rcvd: 139
```
```bash
# query AAAA record for ipv6.google.com
$ dig @127.0.0.1 -p65353 ipv6.google.com AAAA

; <<>> DiG 9.14.3 <<>> @127.0.0.1 -p65353 ipv6.google.com AAAA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23590
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;ipv6.google.com.       IN  AAAA

;; ANSWER SECTION:
ipv6.google.com.    13733   IN  CNAME   ipv6.l.google.com.
ipv6.l.google.com.  178 IN  AAAA    2404:6800:4003:c02::66

;; Query time: 70 msec
;; SERVER: 127.0.0.1#65353(127.0.0.1)
;; WHEN: Sun Jul 28 09:31:34 CST 2019
;; MSG SIZE  rcvd: 93
```
```bash
# the output of chinadns-ng
2019-07-28 09:31:24 INF: [handle_local_packet] query [www.google.com] from 127.0.0.1#10598
2019-07-28 09:31:24 INF: [handle_remote_packet] reply [www.google.com] from 114.114.114.114#53, result: drop
2019-07-28 09:31:24 INF: [handle_remote_packet] reply [www.google.com] from 8.8.8.8#53, result: pass
2019-07-28 09:31:34 INF: [handle_local_packet] query [ipv6.google.com] from 127.0.0.1#36271
2019-07-28 09:31:34 INF: [handle_remote_packet] reply [ipv6.google.com] from 114.114.114.114#53, result: drop
2019-07-28 09:31:34 INF: [handle_remote_packet] reply [ipv6.google.com] from 8.8.8.8#53, result: pass
```

# FAQ
1. How to run `chinadns-ng` as a daemon?
```bash
(chinadns-ng </dev/null &>>/var/log/chinadns-ng.log &)
```

2. How to update the list of `chnroute` and `chnroute6`?
```bash
./update-chnroute.sh
./update-chnroute6.sh
ipset destroy chnroute
ipset destroy chnroute6
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset
```

Also see [ss-tproxy](https://github.com/zfl9/ss-tproxy).

Enjoy it!
