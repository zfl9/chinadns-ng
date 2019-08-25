# ChinaDNS-NG
[ChinaDNS](https://github.com/shadowsocks/ChinaDNS) 的个人重构版本，特点：
- 使用 epoll 和 ipset(netlink) 实现，性能更强。
- 完整支持 IPv4 和 IPv6 协议，兼容 EDNS 请求和响应。
- 手动指定国内 DNS 和可信 DNS，而非自动识别，更加可控。
- 修复原版对保留地址的处理问题，去除过时特性，只留核心功能。
- 当然，最关键的一点，ChinaDNS-NG 可以更好的与 ss-tproxy 工作。

# 快速编译
```bash
git clone https://github.com/zfl9/chinadns-ng
cd chinadns-ng
make && sudo make install
```
chinadns-ng 默认安装到 `/usr/local/bin` 目录，可安装到其它目录，如 `sudo make install DESTDIR=/opt/local/bin`。

# 命令选项
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

- 上游 DNS 服务器的默认端口号为 `53`，可手动指定其它端口号。
- `china-dns` 选项指定国内上游 DNS 服务器，最多两个，逗号隔开。
- `trust-dns` 选项指定可信上游 DNS 服务器，最多两个，逗号隔开。
- `ipset-name4` 选项指定一个 ipset，该 ipset 存储中国大陆 IPv4 地址。
- `ipset-name6` 选项指定一个 ipset，该 ipset 存储中国大陆 IPv6 地址。
- `reuse-port` 选项用于支持 chinadns-ng 多进程负载均衡，提升性能。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

> 可信 DNS 必须经过代理来访问，否则会导致 chinadns-ng 的判断完全失效。

# 工作原理
- chinadns-ng 启动后会创建一个监听套接字，N 个上游套接字，N 为上游 DNS 数量。
- 监听套接字用于处理本地请求客户端的 DNS 请求，以及向请求客户端发送 DNS 响应。
- 上游套接字用于向上游 DNS 服务器发送 DNS 请求，以及接收来自上游的 DNS 回复包。
- 当监听套接字收到请求客户端的 DNS 查询后，会将该 DNS 查询包同时发送给所有上游。
- 当收到上游 DNS 服务器的响应包后，首先会判断该上游 DNS 是国内 DNS 还是可信 DNS：
  - 国内 DNS：检查结果 IP 是否为大陆地址（查询 ipset），如果是则检查通过，返回给请求客户端，关联的请求处理完毕，不再考虑其它上游的结果；如果不是，则丢弃该回复，继续等待其它上游的响应。
  - 可信 DNS：进行基本的 DNS 包结构检查，只要不是坏包就算检查通过，返回给请求客户端，关联的请求处理完毕，不再考虑其它上游的结果；如果检查不通过，则丢弃该回复，继续等待其它上游的响应。
- 这实际上是 DNS 抢答模式，正常情况下，肯定是国内 DNS 先返回的，因为经过代理的可信 DNS 响应肯定比直连访问的国内 DNS 慢，这是没问题的，判断正常生效。而非正常情况是可信 DNS 先返回，这就有问题了，这会导致请求客户端收到的查询结果都是可信 DNS 返回的，这样国内 CDN 就全失效了，解析出来的 IP 都是国外的 IP，绕了一大圈，出现这种情况的原因可能是你错误的给可信 DNS 配置了 DNS 缓存。

# 简单测试
安装 ipset 命令，导入项目根目录下的 `chnroute.ipset` 和 `chnroute6.ipset`：
```bash
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset
```

然后在 shell 中运行 chinadns-ng，注意你需要先确保可信 DNS 的访问会走代理：
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

然后安装 dig 命令，用于测试 chinadns-ng 的工作是否正常，当然其它 dns 工具也可以：
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

可以看到，对于国内 DNS 返回非国内 IP 的响应都正常过滤了，无论是 A 记录响应还是 AAAA 记录响应。

# 常见问题
1. 如何以守护进程形式在后台运行 chinadns-ng？
```bash
(chinadns-ng </dev/null &>>/var/log/chinadns-ng.log &)
```

2. 如何更新 chnroute.ipset 和 chnroute6.ipset？
```bash
./update-chnroute.sh
./update-chnroute6.sh
ipset -F chnroute
ipset -F chnroute6
ipset -R -exist <chnroute.ipset
ipset -R -exist <chnroute6.ipset
```

3. chinadns-ng 并不读取 `chnroute.ipset`、`chnroute6.ipset` 文件，启动时也不会检查这些 ipset 集合是否存在，它只是通过 netlink 套接字询问 ipset 模块，指定 ip 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它会立即生效，不需要重启 chinadns-ng。使用 ipset 存储地址段除了性能好之外，还能与 iptables 规则更好的契合，因为不需要维护两份独立的列表。对于 `chnroute6.ipset`，你也可以不导入，这没什么大问题，只不过对于国内 DNS 返回 IPv6 地址的解析结果都会过滤罢了。

另外，chinadns-ng 是专门为 [ss-tproxy](https://github.com/zfl9/ss-tproxy) v4.0 编写的，欢迎使用。
