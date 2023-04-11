## 简介

[ChinaDNS](https://github.com/shadowsocks/ChinaDNS) 的个人重构版本，功能简述：

- 使用 epoll 和 ipset(netlink) 实现，性能更强。
- 完整支持 IPv4 和 IPv6 协议，兼容 EDNS 请求和响应。
- 手动指定国内 DNS 和可信 DNS，而非自动识别，更加可控。
- 修复原版对保留地址的处理问题，去除过时特性，只留核心功能。
- 修复原版对可信 DNS 先于国内 DNS 返回而导致判断失效的问题。
- 支持 `gfwlist/chnlist` 黑/白名单模式，并对 **时空效率** 进行了优化。
- 支持纯域名分流：要么走china上游，要么走trust上游，不依赖ipset。
- 可动态添加大陆域名结果IP至`ipset/nftset`，实现完美chnroute分流。
- 支持`nftables set`，并针对 add 操作进行了性能优化，避免操作延迟。
- 更加细致的 no-ipv6(AAAA) 控制，可根据域名类型，上游类型进行过滤。

## 编译

> 不想编译的，可以去 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载编译好的可执行文件（静态链接musl）。

```bash
git clone https://github.com/zfl9/chinadns-ng
cd chinadns-ng
make && sudo make install
```

相关`make`变量：

- `CC`：指定编译器，默认是`gcc`，如交叉编译 `make clean all CC=/path/to/aarch64-linux-gnu-gcc`
- `DEBUG`：编译`debug`版本（`gdb`调试信息），如 `make clean all DEBUG=1`
- `STATIC`：生成静态链接（包括`libc`）的可执行文件，如 `make clean all STATIC=1`
- `LDDIRS`：库文件搜索路径，通常用不到，格式 `make clean all LDDIRS=-L/path/to/libs`
- `MAIN`：可执行文件名，默认是`chinadns-ng`
- `DESTDIR`：指定安装目录，默认是`/usr/local/bin`

> 如果是版本升级（或者为不同架构交叉编译），建议先 `make clean`，避免出现奇怪的问题。

## 交叉编译

这里推荐两种方法，支持静态链接(musl)，方便部署，避免glibc版本兼容问题：

- <https://ziglang.org>：将 zig 作为 C 编译器来使用，即 `zig cc`（基于`clang/llvm`）
- <https://musl.cc>：提供了预先构建好`gcc`工具链（linux x86 hosted），下载解压即可使用

> musl 性能表现在**低端设备/嵌入式环境**下通常比 glibc 更优，但在 x86 架构（aarch64 不确定）可能不如 glibc。

这里以`musl.cc`为例（`releases`的二进制就是用它编译的），为`aarch64`编译静态链接的`chinadns-ng`：

```shell
cd /opt

# 获取下载地址
curl https://musl.cc # 所有(native + cross)
curl https://musl.cc | grep cross | grep aarch64 # aarch64

# 下载工具链
wget https://musl.cc/aarch64-linux-musl-cross.tgz

# 解压工具链
tar xvf aarch64-linux-musl-cross.tgz

# 编译静态版本
cd /path/to/chinadns-ng
make clean all CC='/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc' STATIC=1

# 然后使用 file 命令检查 chinadns-ng 可执行文件
file ./chinadns-ng
chinadns-ng: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped

# 可以使用 qemu-user-static 工具包来检查是否可运行
pacman -S qemu-user-static # archlinux
qemu-aarch64-static ./chinadns-ng -v -l53 -g ./gfwlist.txt -m ./chnlist.txt
```

## Docker

由于运行时会访问内核 ipset/nft 子系统，所以 docker run 时请带上 `--privileged`。

建议去 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载编译好的musl静态链接二进制，这样就不需要 build 了。

## 命令选项

```console
$ chinadns-ng --help
usage: chinadns-ng <options...>. the existing options are as follows:
 -b, --bind-addr <ip-address>         listen address, default: 127.0.0.1
 -l, --bind-port <port-number>        listen port number, default: 65353
 -c, --china-dns <ip[#port],...>      china dns server, default: <114DNS>
 -t, --trust-dns <ip[#port],...>      trust dns server, default: <GoogleDNS>
 -4, --ipset-name4 <ipv4-setname>     ipset ipv4 set name, default: chnroute
 -6, --ipset-name6 <ipv6-setname>     ipset ipv6 set name, default: chnroute6
                                      if it contains @, then use nftables set
                                      format: family_name@table_name@set_name
 -g, --gfwlist-file <path,...>        path(s) of gfwlist, '-' indicate stdin
 -m, --chnlist-file <path,...>        path(s) of chnlist, '-' indicate stdin
 -d, --default-tag <name-tag>         domain default tag: gfw,chn,none(default)
 -o, --timeout-sec <query-timeout>    timeout of the upstream dns, default: 5
 -p, --repeat-times <repeat-times>    only used for trustdns, default:1, max:5
 -N, --no-ipv6=[rules]                filter AAAA query, rules can be a seq of:
                                      rule a: filter all domain name (default)
                                      rule g: filter the name with tag gfw
                                      rule m: filter the name with tag chn
                                      rule n: filter the name with tag none
                                      rule c: do not forward to china upstream
                                      rule t: do not forward to trust upstream
                                      rule C: check answer ip of china upstream
                                      rule T: check answer ip of trust upstream
                                      if no rules is given, it defaults to 'a'
 -M, --chnlist-first                  match chnlist first, default: <disabled>
 -a, --add-tagchn-ip                  add the ip of name-tag:chn to ipset/nftset
 -f, --fair-mode                      enable fair mode (nop, only fair mode now)
 -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
 -n, --noip-as-chnip                  accept reply without ipaddr (A/AAAA query)
 -v, --verbose                        print the verbose log, default: <disabled>
 -V, --version                        print `chinadns-ng` version number and exit
 -h, --help                           print `chinadns-ng` help information and exit
bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
```

---

- `china-dns` 选项指定国内上游 DNS 服务器，最多两个，逗号隔开。
- `trust-dns` 选项指定可信上游 DNS 服务器，最多两个，逗号隔开。
- 上游 DNS 服务器的默认端口号为 `53`，可手动指定其它端口号。

---

- `ipset-name4` 选项指定存储中国大陆 IPv4 地址的 ipset/nft 集合名。
- `ipset-name6` 选项指定存储中国大陆 IPv6 地址的 ipset/nft 集合名。
- nft 也是用这两选项，名称格式为：`family名@table名@set名`，自带的 nft 数据文件使用如下名称：
  - 大陆 IPv4 地址集合：`inet@global@chnroute`
  - 大陆 IPv6 地址集合：`inet@global@chnroute6`

---

- `gfwlist-file` 选项指定黑名单域名文件，命中的域名只走可信 DNS。
- `chnlist-file` 选项指定白名单域名文件，命中的域名只走国内 DNS。
- 可指定多个文件路径，使用英文逗号隔开，如 `-g a.txt,b.txt,c.txt`。
- `chnlist-first` 选项表示优先匹配 chnlist，默认是优先匹配 gfwlist。

---

- `default-tag` 用来实现"纯域名分流"，可提供比`dnsmasq`更优秀的匹配性能。
- 通常与`-g`或`-m`选项一起用，纯域名分流模式下不执行 ipset/nftset 逻辑，如：
  - `-g gfwlist.txt -d chn`：gfw列表的域名走可信上游，其他走国内上游。
  - `-m chnlist.txt -d gfw`：chn列表的域名走国内上游，其他走可信上游。
  
---

- `no-ipv6` 选项表示过滤 IPv6-Address(AAAA) 查询，默认不设置此选项。
  - `2023.02.27`版本开始，允许指定一个可选的"规则串"，目前有如下规则：
  - `a`：过滤所有域名的v6查询，同之前
  - `g`：过滤gfwlist域名的v6查询
  - `m`：过滤chnlist域名的v6查询
  - `n`：过滤非gfwlist、非chnlist域名的v6查询
  - `c`：禁止向chinadns上游转发v6查询
  - `t`：禁止向trustdns上游转发v6查询
  - `C`：若一个AAAA查询只转发给了china上游(非gfw域名 && 非chn域名 && trust被禁用v6)，是否过滤非大陆ip的响应；默认不过滤，除非设置此规则
  - `T`：若一个AAAA查询只转发给了trust上游(非gfw域名 && 非chn域名 && china被禁用v6)，是否过滤非大陆ip的响应；默认不过滤，除非设置此规则
  - 如`-N=gt`/`--no-ipv6=gt`：过滤gfwlist域名的v6、禁止向trustdns转发v6

---

- `add-tagchn-ip` 用于动态添加 大陆域名的解析结果ip 到 ipset/nftset。
- `reuse-port` 选项用于支持 chinadns-ng 多进程负载均衡，提升性能。
- `timeout-sec` 选项用于指定上游的响应超时时长，单位秒，默认5秒。
- `repeat-times` 选项表示向可信 DNS 发送几个 dns 查询包，默认为 1。
- `fair-mode` 从`2023.03.06`版本开始，只有公平模式，指不指定都一样。
- `noip-as-chnip` 选项表示接受 qtype 为 A/AAAA 但却没有 IP 的 reply。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

## 工作原理

- chinadns-ng 启动后会创建一个监听套接字，N 个上游套接字，N 为上游 DNS 数量。

- 监听套接字用于处理本地请求客户端的 DNS 请求，以及向请求客户端发送 DNS 响应。

- 上游套接字用于向上游 DNS 服务器发送 DNS 请求，以及从上游服务器接收 DNS 响应。

- 当从监听套接字收到请求客户端的 DNS 查询时，将按照如下逻辑转发给对应上游 DNS：
  - 如果启用了黑名单(gfwlist)且查询的域名命中了黑名单，则将该请求转发给可信 DNS。
  - 如果启用了白名单(chnlist)且查询的域名命中了白名单，则将该请求转发给国内 DNS。
  - 如果未启用黑名单、白名单，或未命中黑名单、白名单，则将请求转发给所有上游 DNS。

- 当从上游套接字收到上游服务器的 DNS 响应时，将按照如下逻辑过滤收到的上游 DNS 响应：
  - 如果关联的查询是命中了黑白名单的，则直接将其转发给请求客户端，并释放相关上下文。
  - 如果关联的查询是未命中黑白名单的，则检查国内 DNS 返回的是否为 `chnroute/chnroute6` IP：
    - 如果是，则接收此响应，将其转发给请求客户端，并释放相关上下文；
    - 如果不是，则丢弃此响应，然后采用可信 DNS 的解析结果；
    - ~~如果可信 DNS 可能会比国内 DNS 先返回，请启用"公平模式"（默认"抢答模式"），即选项 `-f/--fair-mode`。按理来说抢答模式是可以丢弃的，但考虑到一些特殊情况，还是打算留着抢答模式~~。从`2023.03.06`版本开始，只存在公平模式。

- 域名黑白名单允许同时启用，且如果条件允许建议同时启用黑白名单。不必担心查询效率，条目数量只会影响一点内存占用，对查询速度没影响，另外也不必担心内存占用，我在`Linux x86-64 (CentOS 7)`上的实测数据如下：
  - 没有黑白名单时，内存为`140`KB；
  - 加载 5700+ 条`gfwlist`时，内存为`304`KB；
  - 加载 5700+ 条`gfwlist`以及 73300+ 条`chnlist`时，内存为`2424`KB；
  - 注：这些内存占用未计算`libc.so`、`libm.so`，因为这些共享库实际上是所有进程共享一份内存；另外也没有计算stack的虚拟内存占用，因为linux默认stack大小为8MB，但实际上根本用不了这么多。
  - 如果确实内存吃紧，那只加载`gfwlist`就ok了，绝对能满足日常需求，因为`chnlist`更多的我觉得是寻求一个心里安慰。或者你也可以寻找更加精简的chnlist替代源。
  - 2023.04.11 版本针对域名列表内存占用做了进一步优化，因此内存占用会更少，这里就不贴测试数据了。

- 如果一个域名在黑名单和白名单中都能匹配成功，那么你可能需要注意一下优先级问题，默认是优先黑名单(gfwlist)，如果希望优先白名单(chnlist)，请指定选项 `-M/--chnlist-first`。

- 域名黑白名单文件是按行分隔的**域名后缀**，格式：`baidu.com`、`www.google.com`、`www.google.com.hk`，注意不要以`.`开头或结尾，另外域名的`label`数量也是做了人为限制的，最多只能`4`个，过长的会被截断（如`test.www.google.com.hk`截断为`www.google.com.hk`），这么做是为了尽量减少域名匹配次数。如果需要，可以修改源码的`LABEL_MAXCNT`常量来调整最大`label`数。

- 光靠 `chinadns-ng` 无法防止 DNS 污染，防污染是**可信DNS上游**的任务，`chinadns-ng` 只负责 DNS 查询和 DNS 响应的简单处理，不修改任何 dns-query、dns-reply。同理，`chinadns-ng` 只是兼容 EDNS 请求和响应，并不提供 EDNS 的任何相关特性，任何 DNS 特性都是由上游 DNS 来实现的，请务必理解这一点。所以通常 `chinadns-ng` 都是与其它 dns 工具或代理工具一起使用的，具体与什么搭配，以及如何搭配，这里不展开讨论，由各位自由发挥（保证**可信DNS上游**的结果没有被污染即可，比如过墙时套上代理，如`ss-tunnel`）。

## 简单测试

导入项目根目录下的 `chnroute*.ipset` 或 `chnroute*.nftset`：

```bash
# 使用 ipset
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset

# 使用 nft
nft -f chnroute.nftset
nft -f chnroute6.nftset
```

> 只要没有显式的从内核删除 ipset/nft 集合，那么下次运行时就不需要再次导入了。

然后运行 chinadns-ng，注意我是配置了全局代理的，所以 `8.8.8.8` 会走代理出去。

```console
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

```shell
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

```shell
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

```shell
# the output of chinadns-ng
2019-07-28 09:31:11 INF: [handle_local_packet] query [www.baidu.com] from 127.0.0.1#20942
2019-07-28 09:31:11 INF: [handle_remote_packet] reply [www.baidu.com] from 114.114.114.114#53, result: pass
2019-07-28 09:31:11 INF: [handle_remote_packet] reply [www.baidu.com] from 8.8.8.8#53, result: pass
2019-07-28 09:31:15 INF: [handle_local_packet] query [ipv6.baidu.com] from 127.0.0.1#40293
2019-07-28 09:31:15 INF: [handle_remote_packet] reply [ipv6.baidu.com] from 114.114.114.114#53, result: pass
2019-07-28 09:31:15 INF: [handle_remote_packet] reply [ipv6.baidu.com] from 8.8.8.8#53, result: pass
```

```shell
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

```shell
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

```shell
# the output of chinadns-ng
2019-07-28 09:31:24 INF: [handle_local_packet] query [www.google.com] from 127.0.0.1#10598
2019-07-28 09:31:24 INF: [handle_remote_packet] reply [www.google.com] from 114.114.114.114#53, result: drop
2019-07-28 09:31:24 INF: [handle_remote_packet] reply [www.google.com] from 8.8.8.8#53, result: pass
2019-07-28 09:31:34 INF: [handle_local_packet] query [ipv6.google.com] from 127.0.0.1#36271
2019-07-28 09:31:34 INF: [handle_remote_packet] reply [ipv6.google.com] from 114.114.114.114#53, result: drop
2019-07-28 09:31:34 INF: [handle_remote_packet] reply [ipv6.google.com] from 8.8.8.8#53, result: pass
```

可以看到，对于国内 DNS 返回非国内 IP 的响应都正常过滤了，无论是 A 记录响应还是 AAAA 记录响应。

## 常见问题

### 如何以守护进程形式在后台运行 chinadns-ng

```bash
(chinadns-ng </dev/null &>>/var/log/chinadns-ng.log &)
```

---

### 如何更新 chnroute.ipset、chnroute6.ipset

```bash
./update-chnroute.sh
./update-chnroute6.sh
ipset -F chnroute
ipset -F chnroute6
ipset -R -exist <chnroute.ipset
ipset -R -exist <chnroute6.ipset
```

---

### 如何更新 chnroute.nftset、chnroute6.nftset

```bash
./update-chnroute-nft.sh
./update-chnroute6-nft.sh
nft flush set inet global chnroute
nft flush set inet global chnroute6
nft -f chnroute.nftset
nft -f chnroute6.nftset
```

---

### 如何更新 gfwlist.txt、chnlist.txt

```bash
./update-gfwlist.sh
./update-chnlist.sh
chinadns-ng -g gfwlist.txt -m chnlist.txt <args...> #重新运行chinadns-ng
```

---

### 如何使用 TCP 协议与 DNS 上游进行通信

如果想通过 TCP 协议来访问上游 DNS（原生只支持 UDP 访问），可以使用 [dns2tcp](https://github.com/zfl9/dns2tcp) 这个小工具将 chinadns-ng 向上游发出的 DNS 查询从 UDP 转换为 TCP，`dns2tcp` 是个人利用业余时间写的一个 DNS 实用小工具，专门用于实现 dns 的 udp2tcp 功能（虽然能实现类似功能的工具有很多，但它们大多都附带了我不想要的功能，还是比较喜欢简单专一点的东西）。

```bash
# 运行 dns2tcp
dns2tcp -L"127.0.0.1#5353" -R"8.8.8.8#53"

# 运行 chinadns-ng
chinadns-ng -c 114.114.114.114 -t '127.0.0.1#5353'
```

---

### chinadns-ng 并不读取 chnroute.ipset、chnroute6.ipset

启动时也不会检查这些 ipset 集合是否存在，它只是在收到 dns 响应时通过 netlink 套接字询问 ipset 模块，指定 ip 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它会立即生效，不需要重启 chinadns-ng。使用 ipset 存储地址段除了性能好之外，还能与 iptables 规则更好的契合，因为不需要维护两份独立的 chnroute 列表。~~TODO：支持`nftables sets`~~（已支持）。

---

### 接受 china 上游返回的 IP 为保留地址的解析记录

如果你指定的 china-dns 上游会返回 **IP为保留地址** 的记录，且你希望 chinadns-ng 接受此国内上游的响应（即判定为国内 IP），那么你需要将对应的保留地址段加入到 `chnroute`、`chnroute6` ipset 中。注意：chinadns-ng 判断是否为"国内 IP"的核心就是查询 chnroute、chnroute6 这两个 ipset 集合，程序内部没有任何隐含的判断规则。

---

### received an error code from kernel: (-2) No such file or directory

意思是指定的 ipset 集合不存在；如果是 `[ipset_addr4_is_exists]` 提示此错误，说明没有导入 `chnroute` ipset（IPv4）；如果是 `[ipset_addr6_is_exists]` 提示此错误，说明没有导入 `chnroute6` ipset（IPv6）。要解决此问题，请导入项目根目录下 `chnroute.ipset`、`chnroute6.ipset` 文件。

需要提示的是：chinadns-ng 在查询 ipset 集合时，如果遇到类似的 ipset 错误，都会将给定 IP 视为国外 IP。因此如果你因为各种原因不想导入 `chnroute6.ipset`，那么产生的效果就是：当客户端查询 IPv6 域名时（即 AAAA 查询），会导致所有国内 DNS 返回的解析结果都被过滤，然后采用可信 DNS 的解析结果。

---

### trust上游存在一定的丢包，怎么缓解

如果 trust-dns 上游存在丢包的情况（特别是 udp-based 类型的代理隧道），可以使用 `--repeat-times` 选项进行一定的缓解。比如设置为 3，则表示：chinadns-ng 从客户端收到一个 query 包后，会同时向 trust-dns 发送 3 个相同的 query 包，向 china-dns 发送 1 个 query 包（所以该选项仅针对 trust-dns）。也就是所谓的 **多倍发包**、**重复发包**，并没有其它魔力。

---

### 为何选择 ipset 来处理 chnroute 查询

有多种原因，一是因为使用 ipset 可以与 iptables 规则共用一份 chnroute；二是因为目前无法自己实现高效率的`ip(cidr)`查询，所以借助`ipset`内核模块。

---

### 是否支持 nftables 的 set 查询接口

~~目前还不支持，但已加入 TODO 列表，不出意外应该快了（主要是还在寻找不依赖任何库的情况下访问`nft set`）~~。2023.04.11 版本已支持。

---

### 是否打算支持 geoip.dat 等格式的 chnroute

目前没有这个计划，因为如果要自己实现 chnroute 集合，那就要实现高性能的数据结构和算法，这有点超出了我的能力范围。另外一个原因就是，chinadns-ng 通常与 iptables/nftables 一起使用（配合透明代理），若使用非 ipset/nft-set 实现，会导致两份重复的 chnroute。

---

### 是否打算支持 geosite.dat 等格式的 gfwlist/chnlist

目前也没有这个计划，这些二进制格式需要引入 protobuf 等库，我不是很想引入依赖，而且 geosite.dat 本身也大。

---

### chinadns-ng 原则上只为替代原版 chinadns，非必要功能暂不打算实现

目前个人的用法是：dnsmasq 在前，chinadns-ng 在后；dnsmasq 做 DNS 缓存、ipset（将特定域名解析出来的 IP 动态添加至 ipset 集合，便于 iptables 操作）、以及相关附加服务（如 DHCP）；chinadns-ng 则作为 dnsmasq 的上游服务器，配合 ss-tproxy 透明代理，提供无污染的 DNS 解析服务。

---

### --add-tagchn-ip 选项的作用

主要用于配合 chnroute 分流模式（透明代理），这样只要是 chnlist.txt 里面的域名，都必定走直连，不会走代理。

---

### --noip-as-chnip 选项的作用

首先解释一下什么是：**qtype 为 A/AAAA 但却没有 IP 的 reply**。

qtype 即 query type，常见的有 A（查询给定域名的 IPv4 地址）、AAAA（查询给定域名的 IPv6 地址）、CNAME（查询给定域名的别名）、MX（查询给定域名的邮件服务器）；

chinadns-ng 实际上只关心 A/AAAA 类型的查询和回复，因此这里强调 qtype 为 A/AAAA；A/AAAA 查询显然是想获得给定域名的 IP 地址，但是某些解析结果中却并不没有任何 IP 地址，比如 `yys.163.com` 的 A 记录查询有 IPv4 地址，但是 AAAA 记录查询却没有 IPv6 地址（见下面的演示）；

默认情况下，chinadns-ng 会拒绝接受这种没有 IP 地址的 reply（此处的拒绝仅针对**国内 DNS**，可信 DNS 不存在任何过滤；另外此过滤也仅针对`非gfwlist && 非chnlist`域名），如果你希望 chinadns-ng 接受这种 reply，那么请指定 `--noip-as-chnip` 选项。

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

---

### 如何以普通用户身份运行 chinadns-ng

如果你尝试使用非 root 用户运行 chinadns-ng，那么在查询 ipset 集合时，会得到 `Operation not permitted` 错误，因为向内核查询 ipset 集合需要 `CAP_NET_ADMIN` 能力，所以默认情况下，你只能使用 root 用户来运行 chinadns-ng。

那有办法突破这个限制吗？其实是有的，使用 `setcap` 命令即可（见下），如此操作后，即可使用非 root 用户运行 chinadns-ng。如果还想让 chinadns-ng 监听 1024 以下的端口，那么执行下面那条命令即可。

```shell
# 授予 CAP_NET_ADMIN 特权
sudo setcap cap_net_admin+ep /usr/local/bin/chinadns-ng

# 授予 CAP_NET_ADMIN + CAP_NET_BIND_SERVICE 特权
sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/chinadns-ng
```

---

另外，chinadns-ng 是专门为 [ss-tproxy](https://github.com/zfl9/ss-tproxy) v4.x 编写的，欢迎使用。
