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
- 可动态添加gfw域名结果IP至`ipset/nftset`，用于实现gfwlist透明代理。
- 支持`nftables set`，并针对 add 操作进行了性能优化，避免操作延迟。
- 更加细致的 no-ipv6(AAAA) 控制，可根据域名类型，上游类型进行过滤。

---

对于常规的使用模式，大致原理和流程可总结为：

- 两组DNS上游：china组(大陆DNS)、trust组(国外DNS)
- 两个域名列表：chnlist.txt(大陆域名)、gfwlist.txt(受污染域名)
- 两个ip地址集合：chnroute(大陆v4地址段)、chnroute6(大陆v6地址段)
- chnlist.txt域名，转发给china组，保证大陆域名不会被解析到国外，对大陆域名cdn友好
- gfwlist.txt域名，转发给trust组，trust需返回未受污染的结果，比如走代理(或透明代理)，具体方式不限
- 其他域名，转发给china组和trust组，如果china组解析结果(A/AAAA)是大陆ip，则采纳china组，否则采纳trust组
- 如果使用纯域名分流模式，则不存在"其他域名"，因此要么走china组，要么走trust组，可完全避免dns泄露问题
- 若启用`--add-tagchn-ip`，则chnlist.txt域名（准确来说是tag为chn的域名）的解析结果IP会被动态添加到ipset/nftset，配合chnroute透明代理分流时，可用于实现大陆域名必走直连（不被代理），使dns分流与ip分流一致；原理类似于 dnsmasq 的 ipset/nftset 功能
- 若启用`--add-taggfw-ip`，则gfwlist.txt域名（准确来说是tag为gfw的域名）的解析结果IP会被动态添加到ipset/nftset，可用来实现gfwlist透明代理分流；也可配合chnroute透明代理分流，用来收集黑名单域名的IP，用于iptables/nftables操作，比如确保黑名单域名必走代理，即使某些黑名单域名的IP是大陆IP

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

## OpenWrt

- 由 pexcn 维护：https://github.com/pexcn/openwrt-chinadns-ng
- 部分科学上网插件自带了 chinadns-ng，你也可以直接使用它们

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
                                      this ipset/nftset is used for tag:none
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
 -a, --add-tagchn-ip=[set4,set6]      add the ip of name-tag:chn to ipset/nft
                                      use '--ipset-name4/6' set-name if no arg
 -A, --add-taggfw-ip <set4,set6>      add the ip of name-tag:gfw to ipset/nft
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
- 该集合只用于 tag:none 域名，用于判定 china 上游的解析结果是否为大陆 IP。
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

- `add-tagchn-ip` 用于动态添加 白名单域名的解析结果ip 到 ipset/nftset。
  - 与`ipset-name4/6`用的是同一个集合(chnroute)，无需提供集合名（2023.04.20版本之前）。
  - 2023.04.20 版本开始，允许指定其他集合：`-a/--add-tagchn-ip=ipv4集合名,ipv6集合名`。
- `add-taggfw-ip` 用于动态添加 黑名单域名的解析结果ip 到 ipset/nftset。
  - 格式是：`ipv4集合名,ipv6集合名`，nftset格式同`ipset-name4/6`。
- 如果使用nftset，在创建set时，必须带上 `flags interval` 标志。
- 如果v6集合没用到（如使用-N屏蔽了AAAA），可以不创建v6集合，但参数中还是需要指定v6集合名。

---

- `reuse-port` 选项用于支持 chinadns-ng 多进程负载均衡，提升性能。
- `timeout-sec` 选项用于指定上游的响应超时时长，单位秒，默认5秒。
- `repeat-times` 选项表示向可信 DNS 发送几个 dns 查询包，默认为 1。
- `fair-mode` 从`2023.03.06`版本开始，只有公平模式，指不指定都一样。
- `noip-as-chnip` 选项表示接受 qtype 为 A/AAAA 但却没有 IP 的 reply。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

## 域名列表

- 域名列表文件格式是按行分隔的**域名后缀**，如`baidu.com`、`www.google.com`、`www.google.com.hk`，不要以`.`开头或结尾，出于性能考虑，域名`label`数量做了人为限制，最多只能`4`个，过长的会被截断，如`test.www.google.com.hk`截断为`www.google.com.hk`。如果需要，也可以修改源码的`LABEL_MAXCNT`常量来调整最大`label`数。

- 如果一个域名在黑名单和白名单中都能匹配成功，那么你可能需要注意一下优先级问题，默认是优先黑名单(gfwlist)，如果希望优先白名单(chnlist)，请指定选项 `-M/--chnlist-first`。

- 从 2023.04.17 版本开始，在匹配一个域名时，将优先考虑子域名模式而不是父域名模式，使匹配逻辑更加合理。举个例子，假设 gfwlist 中有 tw.iqiyi.com 模式，chnlist 中有 iqiyi.com 模式；则不论黑白名单哪个优先，查询 tw.iqiyi.com 和 *.tw.iqiyi.com 都是命中 gfwlist 列表。因此 gfwlist优先/chnlist优先 在新版本中只对完全相同的域名模式有影响。

- 建议同时启用黑名单和白名单，不必担心查询效率，条目数量只会影响一点内存占用，对查询速度没影响，也不必担心内存占用，我在`Linux x86-64 (CentOS 7)`上的实测数据如下：
  - 没有黑白名单时，内存为`140`KB；
  - 加载 5700+ 条`gfwlist`时，内存为`304`KB；
  - 加载 5700+ 条`gfwlist`以及 73300+ 条`chnlist`时，内存为`2424`KB；
  - 注：这些内存占用未计算`libc.so`，因为这些共享库实际上是所有进程共享一份内存；另外也没有计算stack的虚拟内存占用，因为linux默认stack大小为8MB，但实际上根本用不了这么多。
  - 如果确实内存吃紧，可以只加载`gfwlist`，或者使用更加精简的chnlist替代源。
  - 2023.04.11 版本针对域名列表的内存占用做了进一步优化，因此占用会更少，测试数据就不贴了。

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

> 只要没有从内核删除 ipset/nft 集合，下次运行就不需要再次导入了。

运行 chinadns-ng，我自己配了全局透明代理，所以访问 `8.8.8.8` 会走代理出去。

```bash
# 加载 gfwlist 和 chnlist，并动态添加 tag:chn 域名解析结果至 ipset/nftset
chinadns-ng -g gfwlist.txt -m chnlist.txt -a # 使用 ipset
chinadns-ng -g gfwlist.txt -m chnlist.txt -a -4 inet@global@chnroute -6 inet@global@chnroute6 # 使用 nft
```

chinadns-ng 默认监听 `127.0.0.1:65353/udp`，可以给 chinadns-ng 带上 -v 参数，使用 dig 测试，观察其日志。

## 常见问题

### tag:chn、tag:gfw、tag:none 是指什么

这是 chinadns-ng 对域名的一个简单分类：

- 被 chnlist.txt 匹配的域名归为 `tag:chn`
- 被 gfwlist.txt 匹配的域名归为 `tag:gfw`
- 其它未匹配的域名归为 `tag:none`

当使用纯域名分流模式时，不存在 `tag:none` 域名：

- 对于 `-m chnlist.txt -d gfw`，未被匹配的域名归为 `tag:gfw`
- 对于 `-g gfwlist.txt -d chn`，未被匹配的域名归为 `tag:chn`

因此分流的核心流程，可以用三句话来描述：

- `tag:chn` 域名：只走 china 上游，即单纯转发，没有 ipset/nftset test 逻辑
- `tag:gfw` 域名：只走 trust 上游，即单纯转发，没有 ipset/nftset test 逻辑
- `tag:none` 域名：同时走 china 和 trust，如果 china 上游返回国内 IP，则接受其结果，否则采纳 trust 结果

---

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

> 其他协议同理，比如 DoH/DoT/DoQ，你可以借助 https://github.com/AdguardTeam/dnsproxy 等实用工具。

---

### 为什么不内置 TCP、DoH、DoT 等协议的支持

并不是所有人都使用 DoH/DoT，如果要支持这些协议，必然要引入 openssl 等依赖，增加二进制体积（如果静态链接），但这不是主要原因，真正原因是代码复杂度，我想让代码保持简单，只做真正必要的事情，其他事情让专业的工具去干。简而言之，保持简单和愚蠢，只做一件事，并认真做好这件事。

---

### chinadns-ng 并不读取 chnroute.ipset、chnroute6.ipset

启动时也不会检查这些 ipset 集合是否存在，它只是在收到 dns 响应时通过 netlink 套接字询问 ipset 模块，指定 ip 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它会立即生效，不需要重启 chinadns-ng。使用 ipset 存储地址段除了性能好之外，还能与 iptables 规则更好的契合，因为不需要维护两份独立的 chnroute 列表。~~TODO：支持`nftables sets`~~（已支持）。

---

### 接受 china 上游返回的 IP为保留地址 的解析记录

如果 china 上游会返回 **IP为保留地址** 的记录，且你希望 chinadns-ng 接受其响应（判定为大陆IP），那么你需要将对应的保留地址段加入到 `chnroute`、`chnroute6` ipset/nftset。chinadns-ng 判断是否为"大陆IP"的核心就是查询 chnroute、chnroute6 这两个 ipset/nftset，程序内部没有任何隐含的判断规则。注意：只有 tag:none 域名需要这么做，对于 tag:chn 域名，chinadns-ng 只是单纯转发，不涉及 ipset/nftset 判定；所以你也可以将相关域名加入 chnlist（支持从多个文件加载域名列表）。

> 为什么没有默认将保留地址段加入 `chnroute*.ipset/nftset`？因为我担心 gfw 会给受污染域名返回保留地址，所以没放到 chnroute 去。虽然现在受污染域名都走 gfwlist.txt 机制了（只走 trust 上游），但谨慎起见，我建议只添加真正用到的保留地址到 chnroute/chnroute6，比如 192.168.0.0/16，而不是一把梭把它们全加进去，避免出问题。

---

### received an error code from kernel: (-2) No such file or directory

意思是指定的 ipset 集合不存在；如果是 `[ipset_addr4_is_exists]` 提示此错误，说明没有导入 `chnroute` ipset（IPv4）；如果是 `[ipset_addr6_is_exists]` 提示此错误，说明没有导入 `chnroute6` ipset（IPv6）。要解决此问题，请导入项目根目录下 `chnroute.ipset`、`chnroute6.ipset` 文件。

需要提示的是：chinadns-ng 在查询 ipset 集合时，如果遇到类似的 ipset 错误，都会将给定 IP 视为国外 IP。因此如果你因为各种原因不想导入 `chnroute6.ipset`，那么产生的效果就是：当客户端查询 IPv6 域名时（即 AAAA 查询），会导致所有国内 DNS 返回的解析结果都被过滤，然后采用可信 DNS 的解析结果

> 只有 tag:none 域名存在 ipset/nftset 判断&&过滤，tag:gfw 和 tag:chn 域名不会走 ip test 逻辑。

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

目前没有这个计划，因为如果要自己实现 chnroute 集合，那就要实现高性能的数据结构和算法，这有点超出了我的能力范围。但主要还是因为 chinadns-ng 通常与 iptables/nftables 一起使用（配合透明代理），若使用非 ipset/nftset 实现，会导致两份重复的 chnroute。

---

### 是否打算支持 geosite.dat 等格式的 gfwlist/chnlist

目前也没有这个计划，这些二进制格式需要引入 protobuf 等库，我不是很想引入依赖，而且 geosite.dat 本身也大。

---

### chinadns-ng 原则上只为替代原版 chinadns，复杂功能或者非核心功能不打算实现

目前个人用法：dnsmasq 做 DNS 缓存、ipset（处理某些特殊需求的域名，将其解析出来的 IP 动态添加至 ipset，便于 iptables 操作）、以及其他附加服务（如 DHCP）；chinadns-ng 则作为 dnsmasq 的上游服务器，配合 ss-tproxy 透明代理，提供无污染的 DNS 解析服务。

---

### --add-tagchn-ip 选项的作用

主要用于配合 chnroute 分流模式（透明代理），这样只要是 chnlist.txt 里面的域名，都必定走直连，不会走代理。在这之前，如果想实现类似功能，可能需要借助 dnsmasq，但 dnsmasq 不适合配置大量域名(server/ipset/nftset)，会影响解析性能。chinadns-ng 为此做了专门优化，以最大可能来降低开销。

---

### chinadns-ng 也可用于 gfwlist 透明代理分流

```bash
# 创建 ipset，用于存储 tag:gfw 域名的 IP (nftset 同理)
ipset create gfwlist hash:net family inet # ipv4
ipset create gfwlist6 hash:net family inet6 # ipv6

# 指定 gfwlist.txt，default-tag，add-taggfw-ip 选项
chinadns-ng -g gfwlist.txt -d chn -A gfwlist,gfwlist6
```

传统上，这是利用 dnsmasq 来实现的，但 dnsmasq 的 server/ipset/nftset 功能并不擅长处理大量域名，因此对性能有所影响，只是 gfwlist.txt 的域名数量比 chnlist.txt 少，所以影响比较小，但是如果你追求性能（比如低端路由器），我认为使用 chinadns-ng 来实现是有意义的。

---

### --noip-as-chnip 选项的作用

首先解释一下什么是：**qtype 为 A/AAAA 但却没有 IP 的 reply**。

qtype 即 query type，常见的有 A（查询给定域名的 IPv4 地址）、AAAA（查询给定域名的 IPv6 地址）、CNAME（查询给定域名的别名）、MX（查询给定域名的邮件服务器）；

chinadns-ng 实际上只关心 A/AAAA 类型的查询和回复，因此这里强调 qtype 为 A/AAAA；A/AAAA 查询显然是想获得给定域名的 IP 地址，但是某些解析结果中却并不没有任何 IP 地址，比如 `yys.163.com` 的 A 记录查询有 IPv4 地址，但是 AAAA 记录查询却没有 IPv6 地址（见下面的演示）；

默认情况下，chinadns-ng 会拒绝接受这种没有 IP 地址的 reply（此处的拒绝仅针对**国内 DNS**，可信 DNS 不存在任何过滤；另外此过滤也仅针对`非gfwlist && 非chnlist`域名），如果你希望 chinadns-ng 接受这种 reply，那么请指定 `--noip-as-chnip` 选项。

> 这里举的例子并没有体现该选项的真正目的，其实我本意是为了避开 gfw 污染，因为我担心 gfw 可能会对受污染域名返回空 answer（也就是没有 ip），所以默认情况下，chinadns-ng 并不接受 china 上游的这类响应（仅针对 tag:none 域名），我看很多人默认设置 --noip-as-chnip，我认为他们误解了这个选项的作用（当然还是我的锅，文档没写清楚）。

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

如果你尝试使用非 root 用户运行 chinadns-ng，那么在查询 ipset/nft 集合时，会得到 `Operation not permitted` 错误，因为向内核查询 ipset/nft 集合需要 `CAP_NET_ADMIN` 能力，所以默认情况下，你只能使用 root 用户来运行 chinadns-ng。

那有办法突破这个限制吗？其实是有的，使用 `setcap` 命令即可（见下），如此操作后，即可使用非 root 用户运行 chinadns-ng。如果还想让 chinadns-ng 监听 1024 以下的端口，那么执行下面那条命令即可。

```shell
# 授予 CAP_NET_ADMIN 特权
sudo setcap cap_net_admin+ep /usr/local/bin/chinadns-ng

# 授予 CAP_NET_ADMIN + CAP_NET_BIND_SERVICE 特权
sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/chinadns-ng
```

---

chinadns-ng 的诞生完全是因为 [ss-tproxy](https://github.com/zfl9/ss-tproxy)，由于原版 chinadns 的诸多痛点，我想寻找其替代品，但在 github 上看了看，都不是很满意，所以尝试写了此工具，并斗胆命名为 **下一代 chinadns**。
