# ChinaDNS-NG
[ChinaDNS](https://github.com/shadowsocks/ChinaDNS) 的个人重构版本，功能简述：
- 使用 epoll 和 ipset(netlink) 实现，性能更强。
- 完整支持 IPv4 和 IPv6 协议，兼容 EDNS 请求和响应。
- 手动指定国内 DNS 和可信 DNS，而非自动识别，更加可控。
- 修复原版对保留地址的处理问题，去除过时特性，只留核心功能。
- 修复原版对可信 DNS 先于国内 DNS 返回而导致判断失效的问题。
- 支持 `gfwlist/chnlist` 黑/白名单匹配模式，效率比 dnsmasq 更高。

# 快速编译
```bash
git clone https://github.com/zfl9/chinadns-ng
cd chinadns-ng
make && sudo make install
```
chinadns-ng 默认安装到 `/usr/local/bin` 目录，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。<br>
交叉编译时只需指定 CC 变量，如 `make CC=aarch64-linux-gnu-gcc`（如有问题，请执行 `make clean`，然后再试）。

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
 -g, --gfwlist-file <file-path>       filepath of gfwlist, '-' indicate stdin
 -m, --chnlist-file <file-path>       filepath of chnlist, '-' indicate stdin
 -o, --timeout-sec <query-timeout>    timeout of the upstream dns, default: 5
 -p, --repeat-times <repeat-times>    it is only used for trustdns, default: 1
 -M, --chnlist-first                  match chnlist first, default: <disabled>
 -f, --fair-mode                      enable `fair` mode, default: <fast-mode>
 -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
 -n, --noip-as-chnip                  accept reply without ipaddr (A/AAAA query)
 -v, --verbose                        print the verbose log, default: <disabled>
 -V, --version                        print `chinadns-ng` version number and exit
 -h, --help                           print `chinadns-ng` help information and exit
bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
```

- 上游 DNS 服务器的默认端口号为 `53`，可手动指定其它端口号。
- `china-dns` 选项指定国内上游 DNS 服务器，最多两个，逗号隔开。
- `trust-dns` 选项指定可信上游 DNS 服务器，最多两个，逗号隔开。
- `ipset-name4` 选项指定存储中国大陆 IPv4 地址的 ipset 集合的名称。
- `ipset-name6` 选项指定存储中国大陆 IPv6 地址的 ipset 集合的名称。
- `gfwlist-file` 选项指定黑名单域名文件，命中的域名只走可信 DNS。
- `chnlist-file` 选项指定白名单域名文件，命中的域名只走国内 DNS。
- `chnlist-first` 选项表示优先匹配 chnlist，默认是优先匹配 gfwlist。
- `reuse-port` 选项用于支持 chinadns-ng 多进程负载均衡，提升性能。
- `repeat-times` 选项表示向可信 DNS 发送几个 dns 查询包，默认为 1。
- `fair-mode` 选项表示启用"公平模式"而非默认的"抢答模式"，见后文。
- `noip-as-chnip` 选项表示接受 qtype 为 A/AAAA 但却没有 IP 的 reply。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

# 工作原理
- chinadns-ng 启动后会创建一个监听套接字，N 个上游套接字，N 为上游 DNS 数量。
- 监听套接字用于处理本地请求客户端的 DNS 请求，以及向请求客户端发送 DNS 响应。
- 上游套接字用于向上游 DNS 服务器发送 DNS 请求，以及从上游服务器接收 DNS 响应。
- 当从监听套接字收到请求客户端的 DNS 查询时，将按照如下逻辑转发给对应上游 DNS：
  - 如果启用了黑名单(gfwlist)且查询的域名命中了黑名单，则将该请求转发给可信 DNS。
  - 如果启用了白名单(chnlist)且查询的域名命中了白名单，则将该请求转发给国内 DNS。
  - 如果未启用黑名单、白名单，或未命中黑名单、白名单，则将请求转发给所有上游 DNS。
- 当从上游套接字收到上游服务器的 DNS 响应时，将按照如下逻辑过滤收到的上游 DNS 响应：
  - 如果关联的查询是命中了黑白名单的，则直接将其转发给请求客户端，并释放相关上下文。
  - 如果关联的查询是未命中黑白名单的，则检查国内 DNS 返回的是否为国内 IP（即是否命中 chnroute/chnroute6）；如果是，则接收此响应，将其转发给请求客户端，并释放相关上下文；如果不是，则丢弃此响应，然后采用可信 DNS 的解析结果。如果可信 DNS 有一定概率会比国内 DNS 先返回的话，请务必启用"公平模式"（默认是"抢答模式"），也即指定选项 `-f/--fair-mode`。但也不是说无论何时都要启用公平模式，如果国内 DNS 绝大多数情况下都比可信 DNS 先返回的话，是不需要启用公平模式的，当然你启用公平模式也不会有任何问题以及性能损失。其实按理来说抢答模式是可以丢弃的，但考虑到一些特殊情况，还是打算留着抢答模式。
- 域名黑白名单允许同时启用，且如果条件允许建议同时启用黑白名单。不必担心黑白名单的查询效率问题，条目数量的多少只会影响一点儿内存占用，对查询速度是没有影响的，另外也不必担心内存占用会很多，我在`CentOS7`上实测的数据是：加载`5000+`条黑名单和`70000+`条白名单后，`chinadns-ng`占用`6.4M`内存，如果仅加载黑名单的话则只占用了`1.1M`内存。当然如果内存确实比较吃紧，那么仅加载黑名单也是没有问题的。
- 如果一个域名在黑名单和白名单中都能匹配成功，那么你可能需要注意一下优先级问题，默认是先匹配黑名单(gfwlist)，若命中，则标记命中黑名单并返回函数，若未命中，则接着匹配白名单(chnlist)，若命中，则标记命中白名单并返回函数，若未命中，则标记未命中任何名单并返回函数。也就是说黑名单的优先级是比白名单的优先级高的，如果想让白名单的优先级比黑名单的优先级高，指定选项 `-M/--chnlist-first` 即可。
- 域名黑白名单文件是按行分隔的域名模式，所谓域名模式其实就是普通的域名后缀，格式如：`baidu.com`、`www.google.com`、`www.google.com.hk`，注意不要以`.`开头或结尾，另外域名的`label`数量也是做了人为限制的，最少要有`2`个，最多只能`4`个，过短的会被忽略（如`net`），过长的会被截断（如`test.www.google.com.hk`截断为`www.google.com.hk`），当然这么做的目的还是为了尽量提高域名的匹配性能。
- 光靠 `chinadns-ng` 其实是做不到防 DNS 污染的，防 DNS 污染应该是可信 DNS 上游的任务，`chinadns-ng` 只负责 DNS 查询和 DNS 响应的简单处理，不修改任何 dns-query、dns-reply。同理，`chinadns-ng` 只是兼容 EDNS 请求和响应，并不提供 EDNS 的任何相关特性，任何 DNS 特性都是由上游 DNS 来实现的，请务必理解这一点。所以通常 `chinadns-ng` 都是与其它 dns 工具或代理工具一起使用的，具体与什么搭配，以及如何搭配，这里不展开讨论，由各位自由发挥。

# 简单测试
使用 ipset 工具导入项目根目录下的 `chnroute.ipset` 和 `chnroute6.ipset`：
```bash
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset
```
> 只要没有显式的从内核删除 ipset 集合，那么下次运行时就不需要再次导入了。

然后运行 chinadns-ng，注意我是配置了全局代理的，所以 `8.8.8.8` 会走代理出去。
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
1、如何以守护进程形式在后台运行 chinadns-ng？
```bash
(chinadns-ng </dev/null &>>/var/log/chinadns-ng.log &)
```

2、如何更新 chnroute.ipset 和 chnroute6.ipset？
```bash
./update-chnroute.sh
./update-chnroute6.sh
ipset -F chnroute
ipset -F chnroute6
ipset -R -exist <chnroute.ipset
ipset -R -exist <chnroute6.ipset
```

3、注意，chinadns-ng 并不读取 `chnroute.ipset`、`chnroute6.ipset` 文件，启动时也不会检查这些 ipset 集合是否存在，它只是在收到 dns 响应时通过 netlink 套接字询问 ipset 模块，指定 ip 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它会立即生效，不需要重启 chinadns-ng。使用 ipset 存储地址段除了性能好之外，还能与 iptables 规则更好的契合，因为不需要维护两份独立的 chnroute 列表。

4、如果你指定的 china-dns 上游为个人、组织内部的 DNS 服务器，且该 DNS 服务器会返回某些特殊的解析记录（即：包含保留地址的解析记录，比如使用内网 DNS 服务器作为国内上游 DNS），且你希望 chinadns-ng 会接受这些特殊的 DNS 响应（即将它们判定为国内 IP），那么你需要将对应的保留地址段加入到 `chnroute`、`chnroute6` ipset 中。注意：chinadns-ng 判断是否为"国内 IP"的核心就是查询 chnroute、chnroute6 这两个 ipset 集合，程序内部没有任何隐含的判断规则。

5、`received an error code from kernel: (-2) No such file or directory`<br>
意思是指定的 ipset 不存在；如果是 `[ipset_addr4_is_exists]` 函数提示此错误，说明没有导入 `chnroute` ipset（IPv4）；如果是 `[ipset_addr6_is_exists]` 函数提示此错误，说明没有导入 `chnroute6` ipset（IPv6）。要解决此问题，请导入项目根目录下 `chnroute.ipset`、`chnroute6.ipset` 文件。需要提示的是：chinadns-ng 在查询 ipset 集合时，如果遇到类似的 ipset 错误，都会将给定 IP 视为国外 IP。因此如果你因为各种原因不想导入 `chnroute6.ipset`，那么产生的效果就是：当客户端查询 IPv6 域名时（即 AAAA 查询），会导致所有国内 DNS 返回的解析结果都被过滤，然后采用可信 DNS 的解析结果。

6、如果想通过 TCP 协议来访问上游 DNS（原生只支持 UDP 访问），可以使用 [dns2tcp](https://github.com/zfl9/dns2tcp) 这个小工具将 chinadns-ng 向上游发出的 DNS 查询从 UDP 转换为 TCP，`dns2tcp` 是个人利用业余时间写的一个 DNS 实用小工具，专门用于实现 dns 的 udp2tcp 功能（虽然能实现类似功能的工具有很多，但它们大多都附带了我不想要的功能，还是比较喜欢简单专一点的东西）。
```bash
# 运行 dns2tcp
dns2tcp -L"127.0.0.1#5353" -R"8.8.8.8#53"

# 运行 chinadns-ng
chinadns-ng -c 114.114.114.114 -t '127.0.0.1#5353'
```

7、如果 trust-dns 上游存在丢包的情况（特别是 udp-based 类型的代理隧道），可以使用 `--repeat-times` 选项进行一定的缓解。比如设置为 3，则表示：chinadns-ng 从客户端收到一个 query 包后，会同时向 trust-dns 发送 3 个相同的 query 包，向 china-dns 发送 1 个 query 包（所以该选项仅针对 trust-dns）。也就是所谓的 **多倍发包**、**重复发包**，并没有其它魔力。

8、chinadns-ng 原则上只为替代原版 chinadns，非必要的新功能暂不打算实现；目前个人的用法是：dnsmasq 在前，chinadns-ng 在后；dnsmasq 做 DNS 缓存、ipset（将特定域名解析出来的 IP 动态添加至 ipset 集合，便于 iptables 操作）、以及相关附加服务（如 DHCP）；chinadns-ng 则作为 dnsmasq 的上游服务器，配合 ss-tproxy 透明代理，提供无污染的 DNS 解析服务。

9、如何更新 gfwlist.txt？进入项目根目录执行 `./update-gfwlist.sh` 脚本，脚本内部会使用 perl 进行一些复杂的正则表达式替换，请先检查当前系统是否已安装 perl5。脚本执行完毕后，检查 `gfwlist.txt` 文件的行数，一般有 5000+ 行，然后重新启动 chinadns-ng 生效。chnlist.txt 的更新处理也是一样的，也可以自己定制 gfwlist.txt 和 chnlist.txt，具体看个人喜好。

10、`--noip-as-chnip` 选项的作用？首先解释一下什么是：**qtype 为 A/AAAA 但却没有 IP 的 reply**。qtype 即 query type，常见的有 A（查询给定域名的 IPv4 地址）、AAAA（查询给定域名的 IPv6 地址）、CNAME（查询给定域名的别名）、MX（查询给定域名的邮件服务器）；chinadns-ng 实际上只关心 A/AAAA 类型的查询和回复，因此这里强调 qtype 为 A/AAAA；A/AAAA 查询显然是想获得给定域名的 IP 地址，但是某些解析结果中却并不没有任何 IP 地址，比如 `yys.163.com` 的 A 记录查询有 IPv4 地址，但是 AAAA 记录查询却没有 IPv6 地址（见下面的演示）；默认情况下，chinadns-ng 会拒绝接受这种没有 IP 地址的 reply（此处的拒绝仅针对国内 DNS，可信 DNS 不存在任何过滤），如果你希望 chinadns-ng 接受这种 reply，那么请指定 `--noip-as-chnip` 选项。
```bash
$ dig @114.114.114.114 yys.163.com A

; <<>> DiG 9.14.4 <<>> @114.114.114.114 yys.163.com A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12564
;; flags: qr rd ra cd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 8f1a39d62a7d93bb (echoed)
;; QUESTION SECTION:
;yys.163.com.           IN  A

;; ANSWER SECTION:
yys.163.com.        30  IN  CNAME   game-cache.nie.163.com.
game-cache.nie.163.com. 30  IN  A   106.2.95.6
game-cache.nie.163.com. 30  IN  A   59.111.137.212

;; Query time: 48 msec
;; SERVER: 114.114.114.114#53(114.114.114.114)
;; WHEN: Sat Oct 05 10:51:46 CST 2019
;; MSG SIZE  rcvd: 113
```
```bash
$ dig @114.114.114.114 yys.163.com AAAA

; <<>> DiG 9.14.4 <<>> @114.114.114.114 yys.163.com AAAA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39681
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 2c562920a6d4ad18 (echoed)
;; QUESTION SECTION:
;yys.163.com.           IN  AAAA

;; ANSWER SECTION:
yys.163.com.        1776    IN  CNAME   game-cache.nie.163.com.

;; Query time: 47 msec
;; SERVER: 114.114.114.114#53(114.114.114.114)
;; WHEN: Sat Oct 05 10:51:48 CST 2019
;; MSG SIZE  rcvd: 81
```

11、如何以普通用户身份运行 chinadns-ng？如果你尝试使用非 root 用户运行 chinadns-ng，那么在查询 ipset 集合时，会得到 `Operation not permitted` 错误，因为向内核查询 ipset 集合是需要 `CAP_NET_ADMIN` 特权的，所以默认情况下，你只能使用 root 用户来运行 chinadns-ng。那么有办法突破这个限制吗？其实是有的，使用 `setcap` 命令即可（见下），如此操作后，即可使用非 root 用户运行 chinadns-ng。如果还想让 chinadns-ng 监听 1024 以下的端口，那么执行下面那条命令即可。
```shell
# 授予 CAP_NET_ADMIN 特权
sudo setcap cap_net_admin+ep /usr/local/bin/chinadns-ng

# 授予 CAP_NET_ADMIN + CAP_NET_BIND_SERVICE 特权
sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/chinadns-ng
```

另外，chinadns-ng 是专门为 [ss-tproxy](https://github.com/zfl9/ss-tproxy) v4.x 编写的，欢迎使用。
