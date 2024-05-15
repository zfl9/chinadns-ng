## 简介

[ChinaDNS](https://github.com/shadowsocks/ChinaDNS) 的个人重构版本，功能简述：

- 基于 epoll、netlink(ipset/nftset) 实现，性能更强。
- 完整支持 IPv4 和 IPv6 协议，兼容 EDNS 请求和响应。
- 手动指定国内 DNS 和可信 DNS，而非自动识别，更加可控。
- 修复原版对保留地址的处理问题，去除过时特性，只留核心功能。
- 修复原版对可信 DNS 先于国内 DNS 返回而导致判断失效的问题。
- 支持 `gfwlist/chnlist` 域名列表，并深度优化了性能以及内存占用。
- 支持纯域名分流：要么走china上游，要么走trust上游，不进行ip测试。
- 可动态添加大陆域名结果IP至`ipset/nftset`，实现完美chnroute分流。
- 可动态添加gfw域名结果IP至`ipset/nftset`，用于实现gfwlist透明代理。
- 支持`nftables set`，并针对 add 操作进行了性能优化，避免操作延迟。
- 更加细致的 no-ipv6(AAAA) 控制，可根据域名类型，IP测试结果进行过滤。
- DNS 缓存、stale 缓存模式、缓存预刷新、缓存忽略名单（不缓存的域名）。
- 支持 tag:none 域名的判定结果缓存，避免重复请求和判定，减少DNS泄露。
- 除默认的 china、trust 组外，还支持最多 6 个自定义组（上游DNS、ipset）。

---

对于常规的使用模式，大致原理和流程可总结为：

- 两组DNS上游：china组(大陆DNS)、trust组(国外DNS)。

- 两个域名列表：chnlist.txt(大陆域名)、gfwlist.txt(受污染域名)。

- chnlist.txt域名(tag:chn域名)，转发给china组，保证大陆域名不会被解析到国外，对大陆域名cdn友好。

- gfwlist.txt域名(tag:gfw域名)，转发给trust组，trust需返回未受污染的结果，比如走代理，具体方式不限。

- 其他域名(tag:none域名)，同时转发给china组和trust组，如果china组解析结果(A/AAAA)是大陆ip，则采纳china组，否则采纳trust组。是否为大陆ip的核心依据，就是测试ip是否位于`ipset-name4/6`指定的那个地址集合。

- 若启用了tag:none域名的判决缓存，则同一域名的后续请求只会转发给特定的上游组（china组或trust组，具体取决于之前的ip测试结果），建议启用此功能，避免重复请求、判定，减少DNS泄露。

- 如果使用纯域名分流模式，则不存在tag:none域名，因此要么走china组，要么走trust组，可避免dns泄露问题。

- 若启用`--add-tagchn-ip`，则tag:chn域名的解析结果IP会被动态添加到指定的ipset/nftset，配合chnroute透明代理分流时，可用于实现大陆域名必走直连，使dns分流与ip分流一致；类似 dnsmasq 的 ipset/nftset 功能。

- 若启用`--add-taggfw-ip`，则tag:gfw域名的解析结果IP会被动态添加到指定的ipset/nftset，可用来实现gfwlist透明代理分流；也可配合chnroute透明代理分流，用来收集黑名单域名的IP，用于iptables/nftables操作，比如确保黑名单域名必走代理，即使某些黑名单域名的IP是大陆IP。

> chinadns-ng 根据域名 tag 来执行不同逻辑，包括 ipset/nftset 的逻辑（test、add），见 [原理](#tagchntaggfwtagnone-%E6%98%AF%E6%8C%87%E4%BB%80%E4%B9%88)。

## 编译

> 不想编译或无法编译的，请前往 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载预编译的可执行文件（静态链接 musl）。

<details><summary><b>点我展开编译说明</b></summary><p>

---

**zig 工具链**

- 从 2024.03.07 版本起，程序使用 Zig + C 语言编写，`zig` 是唯一需要的工具链。
- 从 [ziglang.org](https://ziglang.org/download/) 下载 zig 0.10.1，请根据当前（编译）主机的架构来选择合适的版本。
- 将解压后的目录加入 PATH 环境变量，执行 `zig version`，检查是否有输出 `0.10.1`。
- 注意，目前必须使用 zig 0.10.1 版本，因为 0.11、master 版本暂时不支持 async 特性。

---

如果要构建 DoT 支持，请带上 `-Dwolfssl` 参数，构建过程需要以下依赖：
- `wget` 或 `curl` 用于下载 wolfssl 源码包；`tar` 用于解压缩
- `autoconf`、`automake`、`libtool`、`make` 用于构建 wolfssl

针对 x86_64(v3/v4)、aarch64 的 wolfssl 构建已默认启用硬件指令加速，若目标硬件(CPU)不支持相关指令（部分树莓派阉割了 aes 相关指令），请指定 `-Dwolfssl-noasm` 选项，避免运行 chinadns-ng 时出现 SIGILL 非法指令异常。

---

如果遇到编译错误，请先执行 `zig build clean-all`，然后重新执行相关构建命令。

可执行文件在 `./zig-out/bin` 目录，将文件安装（复制）到目标主机 PATH 路径下即可。

---

```bash
git clone https://github.com/zfl9/chinadns-ng
cd chinadns-ng

# 本机
zig build # 链接到glibc
zig build -Dtarget=native-native-musl # 静态链接到musl

# x86
zig build -Dtarget=i386-linux-musl -Dcpu=i686
zig build -Dtarget=i386-linux-musl -Dcpu=pentium4

# x86_64
zig build -Dtarget=x86_64-linux-musl -Dcpu=x86_64 # v1
zig build -Dtarget=x86_64-linux-musl -Dcpu=x86_64_v2
zig build -Dtarget=x86_64-linux-musl -Dcpu=x86_64_v3
zig build -Dtarget=x86_64-linux-musl -Dcpu=x86_64_v4

# arm
zig build -Dtarget=arm-linux-musleabi -Dcpu=generic+v5t+soft_float
zig build -Dtarget=arm-linux-musleabi -Dcpu=generic+v5te+soft_float
zig build -Dtarget=arm-linux-musleabi -Dcpu=generic+v6+soft_float
zig build -Dtarget=arm-linux-musleabi -Dcpu=generic+v6t2+soft_float
zig build -Dtarget=arm-linux-musleabi -Dcpu=generic+v7a # soft_float
zig build -Dtarget=arm-linux-musleabihf -Dcpu=generic+v7a # hard_float

# aarch64
zig build -Dtarget=aarch64-linux-musl -Dcpu=generic+v8a
zig build -Dtarget=aarch64-linux-musl -Dcpu=generic+v9a

# mips + soft_float
# 请先阅读 https://www.zfl9.com/zig-mips.html
ARCH=mips32 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r2 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r3 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r5 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH+soft_float

# mipsel + soft_float
# 请先阅读 https://www.zfl9.com/zig-mips.html
ARCH=mips32 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r2 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r3 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH+soft_float
ARCH=mips32r5 && MIPS_M_ARCH=$ARCH MIPS_SOFT_FP=1 zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH+soft_float

# mips + hard_float
# 请先阅读 https://www.zfl9.com/zig-mips.html
ARCH=mips32 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH
ARCH=mips32r2 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH
ARCH=mips32r3 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH
ARCH=mips32r5 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mips-linux-musl -Dcpu=$ARCH

# mipsel + hard_float
# 请先阅读 https://www.zfl9.com/zig-mips.html
ARCH=mips32 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH
ARCH=mips32r2 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH
ARCH=mips32r3 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH
ARCH=mips32r5 && MIPS_M_ARCH=$ARCH zig build -Dtarget=mipsel-linux-musl -Dcpu=$ARCH

# mips64、mips64el 暂不支持，需要等 zig 这边的版本更新
```

</p></details>

## Docker

由于运行时会访问内核 ipset/nft 子系统，所以 docker run 时请带上 `--privileged`。

建议去 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载预编译好的 musl 静态链接二进制，这样就不需要 build 了。

## OpenWrt

- pexcn：https://github.com/pexcn/openwrt-chinadns-ng
- 部分科学上网插件自带了 chinadns-ng，你也可以直接使用它们

## 命令选项

```console
$ chinadns-ng --help
usage: chinadns-ng <options...>. the existing options are as follows:
 -C, --config <path>                  format similar to the long option
 -b, --bind-addr <ip>                 listen address, default: 127.0.0.1
 -l, --bind-port <port[@proto]>       listen port number, default: 65353
 -c, --china-dns <upstreams>          china dns server, default: <114 DNS>
 -t, --trust-dns <upstreams>          trust dns server, default: <Google DNS>
 -m, --chnlist-file <paths>           path(s) of chnlist, '-' indicate stdin
 -g, --gfwlist-file <paths>           path(s) of gfwlist, '-' indicate stdin
 -M, --chnlist-first                  match chnlist first, default gfwlist first
 -d, --default-tag <tag>              chn or gfw or <user-tag> or none(default)
 -a, --add-tagchn-ip [set4,set6]      add the ip of name-tag:chn to ipset/nftset
                                      use '--ipset-name4/6' setname if no value
 -A, --add-taggfw-ip <set4,set6>      add the ip of name-tag:gfw to ipset/nftset
 -4, --ipset-name4 <set4>             ip test for tag:none, default: chnroute
 -6, --ipset-name6 <set6>             ip test for tag:none, default: chnroute6
                                      if setname contains @, then use nftset
                                      format: family_name@table_name@set_name
 --group <name>                       define rule group: {dnl, upstream, ipset}
 --group-dnl <paths>                  domain name list for the current group
 --group-upstream <upstreams>         upstream dns server for the current group
 --group-ipset <set4,set6>            add the ip of the current group to ipset
 -N, --no-ipv6 [rules]                rule: tag:<name>, ip:china, ip:non_china
                                      if no rules, then filter all AAAA queries
 --filter-qtype <qtypes>              filter queries with the given qtype (u16)
 --cache <size>                       enable dns caching, size 0 means disabled
 --cache-stale <N>                    use stale cache: expired time <= N(second)
 --cache-refresh <N>                  pre-refresh the cached data if TTL <= N(%)
 --cache-nodata-ttl <ttl>             TTL of the NODATA response, default is 60
 --cache-ignore <domain>              ignore the dns cache for this domain(suffix)
 --verdict-cache <size>               enable verdict caching for tag:none domains
 --hosts [path]                       load hosts file, default path is /etc/hosts
 --dns-rr-ip <names>=<ips>            define local resource records of type A/AAAA
 --cert-verify                        enable SSL certificate validation, default: no
 --ca-certs <path>                    CA certs path for SSL certificate validation
 --no-ipset-blacklist                 add-ip: don't enable built-in ip blacklist
                                      blacklist: 127.0.0.0/8, 0.0.0.0/8, ::1, ::
 -o, --timeout-sec <sec>              response timeout of upstream, default: 5
 -p, --repeat-times <num>             num of packets to trustdns, default:1, max:5
 -n, --noip-as-chnip                  allow no-ip reply from chinadns (tag:none)
 -f, --fair-mode                      enable fair mode (nop, only fair mode now)
 -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
 -v, --verbose                        print the verbose log, default: <disabled>
 -V, --version                        print `chinadns-ng` version number and exit
 -h, --help                           print `chinadns-ng` help information and exit
bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
```

### config

- 2024.03.07 版本起，开始支持 `-C/--config <path>` 选项。
- `config` 配置文件，一行一个，空行和`#`开头的行被忽略。
  - 格式 `optname [value]`，`optname` 是不带 `--` 的长命令行选项名。
  - 例如 `bind-addr 127.0.0.1`、`bind-port 65353`、`noip-as-chnip`。
  - 不支持行尾注释（如 `verbose # foo`），请使用单独的`#`开头行。
  - 配置文件内可使用 `config path/to/config` 实现文件包含的效果。
  - 命令行选项中也可以指定多个 `-C/--config` 来使用多个配置文件。
- `-C/--config/config` 只是从文件读取“命令行选项”并处理，无其他特别之处。
- `-C/--config` 与其他命令行选项可随意混用，不可重复的选项以最后一个为准。

### bind-addr、bind-port

- `bind-addr` 用于指定监听地址，默认为 127.0.0.1。
- `bind-port` 用于指定监听端口，默认为 65353。
- 2023.10.28 版本起，若监听地址为 `::`，则允许来自 IPv4/IPv6 的 DNS 查询。
- 2024.03.07 版本起，`bind-addr` 允许指定多次，以便监听多个不同的 ip 地址。
- 2024.03.07 版本起，将会同时监听 TCP 和 UDP 端口，之前只监听了 UDP 端口。
- 2024.03.25 版本起，可以给 `bind-port` 选项指定要监听的协议（TCP、UDP）：
  - `--bind-port 65353`：监听 TCP + UDP，默认值。
  - `--bind-port 65353@tcp+udp`：监听 TCP + UDP，同上。
  - `--bind-port 65353@tcp`：只监听 TCP。
  - `--bind-port 65353@udp`：只监听 UDP。

### china-dns、trust-dns

- `china-dns` 选项指定国内上游 DNS 服务器，多个用逗号隔开。
- `trust-dns` 选项指定可信上游 DNS 服务器，多个用逗号隔开。
- 国内上游默认为 `114.114.114.114`，可信上游默认为 `8.8.8.8`。
- 组内的多个上游服务器是并发查询的模式，采纳最先返回的那个结果。
- 上游服务器的地址格式是 `IP#端口`，如果只给出 IP，则端口默认为 53。
- 2024.03.07 版本起，允许多次指定 `china-dns`、`trust-dns` 选项/配置。
- 2024.03.07 版本起，每组上游的服务器数量不受限制（之前最多两个）。
- 2024.03.07 版本起，支持 UDP + TCP 上游（根据查询方的传入协议决定）。
- 2024.03.07 版本起，可在上游地址前加上 `tcp://` 来强制使用 TCP DNS。
- 2024.04.13 版本起，可在上游地址前加上 `udp://` 来强制使用 UDP DNS。
- 2024.04.27 版本起，支持 DoT 上游，`tls://域名@IP`，端口默认为 853。
- 2024.05.12 版本起，DoT 上游地址中，允许省略域名信息，即 `tls://IP`。

> 若上游不支持 TCP 查询，请带上 `udp://` 限定。

### chnlist-file、gfwlist-file、chnlist-first

- `chnlist-file` 选项指定白名单域名文件，命中的域名只走国内 DNS。
- `gfwlist-file` 选项指定黑名单域名文件，命中的域名只走可信 DNS。
- `chnlist-first` 选项表示优先匹配 chnlist，默认是优先匹配 gfwlist。
- 注意，只有 chnlist 和 gfwlist 文件都提供时，`*-first` 才有实际意义。
- 2023.04.01 版本起，可指定多个路径，逗号隔开，如 `-g a.txt,b.txt`。
- 2024.03.07 版本起，可多次指定 `chnlist-file`、`gfwlist-file` 选项。

### default-tag

- `default-tag` 可用于实现"纯域名分流"，也可用于实现 [gfwlist分流模式](#chinadns-ng-也可用于-gfwlist-透明代理分流)。
- 该选项的核心逻辑就是指定**不匹配任何列表的域名**的tag，并无特别之处。
- 通常与`-g`或`-m`选项一起使用，比如下述例子，实现了"纯域名分流"模式：
  - `-g gfwlist.txt -d chn`：gfw列表的域名走可信上游，其他走国内上游。
  - `-m chnlist.txt -d gfw`：chn列表的域名走国内上游，其他走可信上游。
- 如果想了解更多细节，建议看一下 [chinadns-ng 的核心处理流程](#tagchntaggfwtagnone-是指什么)。
  
### add-tagchn-ip、add-taggfw-ip

- `add-tagchn-ip` 用于动态添加 tag:chn域名 的解析结果ip 到 ipset/nftset。
  - 如果未给出集合名，则使用`ipset-name4/6`的那个集合。
- `add-taggfw-ip` 用于动态添加 tag:gfw域名 的解析结果ip 到 ipset/nftset。
- 参数格式：`ipv4集合名,ipv6集合名`，nftset 名称格式同 `ipset-name4/6`。
- 如果要使用 nftset，那么在创建 nftset 时，请记得带上 `flags interval` 标志。
- 如果 v6 集合没用到（如 -N 屏蔽了 AAAA），可以不创建，但参数中还是要指定。
- 2024.04.13 版本起，可使用特殊集合名 `null` 表示对应集合不会被使用：
  - `--add-tagchn-ip null,chnip6`：表示不需要收集 ipv4 地址
  - `--add-tagchn-ip chnip,null`：表示不需要收集 ipv6 地址
  - `--add-tagchn-ip chnip`：表示不需要收集 ipv6 地址
  - 注意：仅当 ipv6 集合为 `null` 时，才可被省略

### ipset-name4、ipset-name6

- `ipset-name4` 指定存储了大陆 IPv4 地址的 ipset/nftset 集合名，默认 chnroute。
- `ipset-name6` 指定存储了大陆 IPv6 地址的 ipset/nftset 集合名，默认 chnroute6。
- nftset 名称格式：`family名@table名@set名`，自带的 nftset 数据文件使用如下名称：
  - 大陆 IPv4 地址集合：`inet@global@chnroute`
  - 大陆 IPv6 地址集合：`inet@global@chnroute6`
- 这两个集合只用于 tag:none 域名，用于判定 china 上游的解析结果是否为大陆 IP。
- 2024.04.13 版本起，也用于 `--no-ipv6` 的 `ip:china`、`ip:non_china` 规则。
- 2024.04.13 版本起，可使用特殊集合名 `null` 表示对应集合不会被使用。

### group、group-*

- `group` 声明一个自定义组（tag），参数值是组（tag）的名字。
  - 支持最多 6 个自定义组，每个组都有 3 个信息可配置，其中 ipset 可选。
  - 在匹配域名时（获取所属tag），自定义组的优先级高于内置组（chn、gfw）。
  - 内置组的优先级逻辑没有改变，依旧默认 gfw 优先，使用 `-M` 切换为 chn 优先。
  - 对于多个自定义组，按照命令行参数/配置的顺序，后声明的组具有更高的优先级。
  - 用例 1：将 DDNS域名 划分出来，单独一个组，用域名提供商的 DNS 去解析。
  - 用例 2：将 公司域名 划分出来，单独一个组，用公司内网专用的 DNS 去解析。
- `group-dnl` 当前组的域名列表文件，多个用逗号隔开，可多次指定。
- `group-upstream` 当前组的上游 DNS，多个用逗号隔开，可多次指定。
- `group-ipset` 当前组的 ipset/nftset (可选)，用于收集解析出的结果 IP。
- 2024.04.27 版本起，使用 `null` 作为 group 名时，表示过滤该组的域名查询。
  - null 组只有 `group-dnl` 信息，查询相关域名时，将返回 NODATA 响应消息。

以配置文件举例：

```shell
# 声明自定义组 "foo"
group foo
group-dnl foo.txt
group-upstream 1.1.1.1,8.8.8.8
group-ipset fooip,fooip6

# 声明自定义组 "bar"
group bar
group-dnl bar.txt
group-upstream 192.168.1.1
# 没有 group-ipset，表示不需要 add ip
```

### no-ipv6

- `no-ipv6` 用于过滤 AAAA 查询（查询域名的 IPv6 地址），默认不设置此选项。
  - 未给出规则时，过滤所有 AAAA 查询。
  - 2023.02.27 版本起，允许指定一个"规则串"，有如下规则：
    - `a`：过滤 所有 域名的 AAAA 查询
    - `m`：过滤 tag:chn 域名的 AAAA 查询
    - `g`：过滤 tag:gfw 域名的 AAAA 查询
    - `n`：过滤 tag:none 域名的 AAAA 查询
    - `c`：禁止向 china 上游转发 AAAA 查询
    - `t`：禁止向 trust 上游转发 AAAA 查询
    - `C`：当 tag:none 域名的 AAAA 查询只存在 china 上游路径时，过滤 非大陆ip 响应
    - `T`：当 tag:none 域名的 AAAA 查询只存在 trust 上游路径时，过滤 非大陆ip 响应
    - 如`-N gt`：过滤 tag:gfw 域名的 AAAA 查询、禁止向 trust 上游转发 AAAA 查询
  - 2024.04.13 版本起，规则有修改（**不兼容旧版**），多个规则使用逗号隔开：
    - `tag:<name>`：按域名 tag 过滤，如 `tag:gfw`，支持自定义的 tag
    - `ip:china`：若响应的 answer 中有 china IP，则过滤（空响应）
    - `ip:non_china`：若响应的 answer 中有 non-china IP，则过滤（空响应）
    - `ip:*` 规则的测试数据库由 `--ipset-name6` 选项提供，默认为 chnroute6

### filter-qtype

- `filter-qtype` 过滤给定 qtype 的查询，多个用逗号隔开，可多次指定。
  - `--filter-qtype 64,65`：过滤 SVCB(64)、HTTPS(65) 查询

### cache、cache-*

- `cache` 启用 DNS 缓存，参数是缓存容量（最多缓存多少个请求的响应消息）。
- `cache-stale` 允许使用 TTL 已过期的（陈旧）缓存，参数是最大过期时长（秒）。
  - 向查询方返回“陈旧”缓存的同时，自动在后台刷新缓存，以便稍后能使用新数据。
  - 2024.04.13 版本起，数据类型从 `u16` 改为 `u32`，以允许设置更大的过期时长。
- `cache-refresh` 若当前查询的缓存的 TTL 不足 N 秒，则提前在后台刷新该缓存。
  - 2024.04.13 版本起，单位从 **秒** 改为 **百分比**，如 30 表示 TTL 不足 30% 时提前刷新。
- `cache-nodata-ttl` 给 NODATA 响应提供默认的缓存时长，默认 60 秒，0 表示不缓存。
- `cache-ignore` 不要缓存给定的域名（后缀，最高支持 8 级），此选项可多次指定。

### verdict-cache

- `verdict-cache` 启用 tag:none 域名的判决结果缓存，参数是缓存容量。
  - tag:none 域名的查询会同时转发给 china、trust 上游，根据 china 上游的 ip test 结果，决定最终响应。
  - 这里说的 **判决结果** 就是指这个 ip test 结果，即：给定的 tag:none 域名是 **大陆域名** 还是 **非大陆域名**。
  - 如果记下此信息，则后续查询同一域名时（未命中 DNS 缓存时），只转发给特定上游组，不同时转发。
  - 缓存容量上限是 65535，此缓存没有 TTL 限制；缓存满时会随机删除一个旧缓存数据。
  - 建议启用此缓存，可帮助减少 tag:none 域名的重复请求和判定，还能减少 DNS 泄露。
  - 注意，判决结果缓存与 DNS 缓存是互相独立的、互补的；这两个缓存系统可同时启用。

### hosts、dns-rr-ip

- `hosts` 加载 hosts 文件，参数默认值为 `/etc/hosts`，此选项可多次指定。
- `dns-rr-ip` 定义本地的 A/AAAA 记录（与 hosts 类似），此选项可多次指定。
  - 格式：`<names>=<ips>`，多个 name 使用逗号隔开，多个 ip 使用逗号隔开。

### cert-verify、ca-certs

- `cert-verify` 启用 DoT 上游的 SSL 证书验证，2024.04.30 版本开始默认不验证。
  - wolfssl 在某些平台（arm32、mips）可能无法正确验证 SSL 证书，见 [#169](https://github.com/zfl9/chinadns-ng/issues/169)。
  - 注意，2024.04.27 版本强制启用证书验证，此选项是 2024.04.30 版本添加的。
- `ca-certs` 根证书路径，用于验证 DoT 上游的 SSL 证书。默认自动检测。

### no-ipset-blacklist

- `no-ipset-blacklist` 若指定此选项，则 add-ip 时不进行内置的 IP 过滤。
  - 默认情况下，以下 IP 不会被添加到 ipset/nftset 集合，见 [#162](https://github.com/zfl9/chinadns-ng/issues/162)
  - `127.0.0.0/8`、`0.0.0.0/8`、`::1`、`::` (loopback地址、全0地址)

### 其他杂项配置

- `timeout-sec` 用于指定上游的响应超时时长，单位秒，默认 5 秒。
- `repeat-times` 针对可信 DNS (UDP) [重复发包](#trust上游存在一定的丢包怎么缓解)，默认为 1，最大为 5。
- `noip-as-chnip` 接受来自 china 上游的没有 IP 地址的响应，[详细说明](#--noip-as-chnip-选项的作用)。
- `fair-mode` 从`2023.03.06`版本开始，只有公平模式，指不指定都一样。
- `reuse-port` 用于多进程负载均衡（实践证明没这个必要，不建议使用）。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

## 域名列表

- 域名列表的文件格式是按行分隔的**域名后缀**，如`baidu.com`、`www.google.com`、`www.google.com.hk`，不要以`.`开头或结尾，出于性能考虑，域名`label`数量做了人为限制，最多只能`4`个，过长的会被截断，如`test.www.google.com.hk`截断为`www.google.com.hk`。

- 如果一个域名在黑名单和白名单中都能匹配成功，那么你可能需要注意一下优先级问题，默认是优先黑名单(gfwlist)，如果希望优先白名单(chnlist)，请指定选项 `-M/--chnlist-first`。

- 2023.04.17 版本起，在匹配一个域名时，将优先考虑子域名模式而不是父域名模式。举个例子，假设 gfwlist 中有 `tw.iqiyi.com`，chnlist 中有 `iqiyi.com`；则不论黑白名单哪个优先，查询 `tw.iqiyi.com` 和 `*.tw.iqiyi.com` 都是命中 gfwlist 列表。因此 `gfwlist优先、chnlist优先` 在新版本中只对两个列表中 **完全相同** 的域名模式有影响。

- 建议同时启用黑名单和白名单，不必担心查询效率，条目数量只会影响一点儿内存占用，对查询速度没影响，也不必担心内存占用，我在`Linux x86-64 (CentOS 7)`上的实测数据如下：
  - 没有黑白名单时，内存为`140`KB；
  - 加载 5700+ 条`gfwlist`时，内存为`304`KB；
  - 加载 5700+ 条`gfwlist`以及 73300+ 条`chnlist`时，内存为`2424`KB；
  - 如果确实内存吃紧，可以使用更加精简的chnlist替代源（不建议只使用gfwlist列表）。
  - 2023.04.11 版本针对域名列表的内存占用做了进一步优化，因此占用会更少，测试数据就不贴了。

## 简单测试

导入项目根目录下的 `chnroute*.ipset` 或 `chnroute*.nftset`：

```bash
# 使用 ipset
ipset -R <chnroute.ipset
ipset -R <chnroute6.ipset

# 使用 nftset
nft -f chnroute.nftset
nft -f chnroute6.nftset
```

> 只要没有从内核删除 ipset/nftset 集合，下次运行就不需要再次导入了。

运行 chinadns-ng，我自己配了全局透明代理，所以访问 `8.8.8.8` 会走代理出去。

```bash
# 加载 gfwlist 和 chnlist，并动态添加 tag:chn 域名解析结果至 ipset/nftset
chinadns-ng -g gfwlist.txt -m chnlist.txt -a # 使用 ipset
chinadns-ng -g gfwlist.txt -m chnlist.txt -a -4 inet@global@chnroute -6 inet@global@chnroute6 # 使用 nftset
```

chinadns-ng 默认监听 `127.0.0.1:65353`，可以给 chinadns-ng 带上 -v 参数，使用 dig 测试，观察其日志。

## 常见问题

### tag:chn、tag:gfw、tag:none 是指什么

这是 chinadns-ng 对域名的一个简单分类：

- 被 chnlist.txt 匹配的域名归为 `tag:chn`
- 被 gfwlist.txt 匹配的域名归为 `tag:gfw`
- 被 `group-dnl` 匹配的域名归为 `自定义组`
- 其它域名默认归为 `tag:none`，可通过 -d 修改

**域名分流** 和 **ipset/nftset** 的核心流程，可以用这几句话来描述：

- `tag:chn`：只走 china 上游（单纯转发），如果启用 --add-tagchn-ip，则添加解析结果至 ipset/nftset
- `tag:gfw`：只走 trust 上游（单纯转发），如果启用 --add-taggfw-ip，则添加解析结果至 ipset/nftset
- `自定义组`：只走 所属组的 上游（单纯转发），如果启用 --group-ipset，则添加解析结果至 ipset/nftset
- `tag:none`：同时走 china 和 trust，如果 china 上游返回国内 IP，则接受其结果，否则采纳 trust 结果

> `tag:chn`和`tag:gfw`和`自定义组`不存在任何判定/过滤；`tag:none`的判定/过滤也仅限于 china 上游的响应结果

---

### 如何以守护进程形式在后台运行 chinadns-ng

```bash
(chinadns-ng 参数... </dev/null &>>/var/log/chinadns-ng.log &)
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
chinadns-ng -g gfwlist.txt -m chnlist.txt 其他参数... # 重新运行 chinadns-ng
```

---

### 如何使用 TCP 协议与 DNS 上游进行通信

从 2024.03.07 版本开始，有以下更改：

- 假设上游地址为 `1.1.1.1`，则根据**查询方的传入协议**来选择与上游的通信协议：
  - 若查询方的传入协议为 UDP，则 chinadns-ng 与该上游的通信协议是 UDP。
  - 若查询方的传入协议为 TCP，则 chinadns-ng 与该上游的通信协议是 TCP。
- 假设上游地址为 `tcp://1.1.1.1`，则 chinadns-ng 与该上游的通信方式总是 TCP。
- 假设上游地址为 `udp://1.1.1.1`，则 chinadns-ng 与该上游的通信方式总是 UDP。

对于之前的版本，原生只支持 UDP 协议，如果想使用 TCP 访问上游，可以使用 [dns2tcp](https://github.com/zfl9/dns2tcp) 这个小工具，作为 chinadns-ng 的上游。其他协议也是一样的道理，比如 DoH/DoT/DoQ，可以借助 [dnsproxy](https://github.com/AdguardTeam/dnsproxy) 等实用工具。

```bash
# 运行 dns2tcp
dns2tcp -L "127.0.0.1#5353" -R "8.8.8.8#53"

# 运行 chinadns-ng
chinadns-ng -c 114.114.114.114 -t '127.0.0.1#5353'
```

---

### 为什么不内置 TCP、DoH、DoT 等协议的支持

> 2024.03.07 版本起，已内置完整的 TCP 支持（传入、传出）。\
> 2024.04.27 版本起，支持 DoT 协议的上游，DoH 不打算实现。

我想让代码保持简单，只做真正必要的事情，其他事情让专业的工具去干。

换句话说，保持简单和愚蠢，只做一件事，并认真做好这件事。

---

### chinadns-ng 并不读取 chnroute.ipset、chnroute6.ipset

> 只有 tag:none 域名存在 ipset/nftset 判断&&过滤，tag:gfw 和 tag:chn 域名不会走 ip test 逻辑。

启动时也不会检查这些 ipset 集合是否存在，它只是在收到 dns 响应时通过 netlink 询问 ipset 模块，给定的 ip 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它会立即生效，不需要重启 chinadns-ng。使用 ipset 存储地址段还能与 iptables 规则更好的契合，因为不需要维护两份独立的 chnroute 列表。~~TODO：支持`nftables sets`~~（已支持）。

---

### 接受 china 上游返回的 IP为保留地址 的解析记录

将对应的保留地址(段)加入到 `chnroute`、`chnroute6` 集合即可。chinadns-ng 判断是否为"大陆IP"的核心就是查询 chnroute、chnroute6 集合，程序内部并没有其他隐含的判断规则。

注意：**只有 tag:none 域名需要这么做**；对于 tag:chn 域名，chinadns-ng 只是单纯转发，不涉及 ipset/nftset 判定；所以你也可以将相关域名加入 chnlist.txt（支持从多个文件加载域名列表）。

为什么没有默认将保留地址加入 `chnroute*.ipset/nftset`？因为我担心 gfw 会给受污染域名返回保留地址，所以没放到 chnroute 去。不过现在受污染域名都走 gfwlist.txt 机制了，只会走 trust 上游，加进去应该没问题。

---

### received an error code from kernel: (-2) No such file or directory

> 只有 tag:none 域名存在 ipset/nftset 判断&&过滤，tag:gfw 和 tag:chn 域名不会走 ip test 逻辑。

意思是指定的 ipset 集合不存在；如果是 `[ipset_addr4_is_exists]` 提示此错误，说明没有导入 `chnroute` ipset（IPv4）；如果是 `[ipset_addr6_is_exists]` 提示此错误，说明没有导入 `chnroute6` ipset（IPv6）。要解决此问题，请导入项目根目录下 `chnroute.ipset`、`chnroute6.ipset` 文件。

需要提示的是：chinadns-ng 在查询 ipset 集合时，如果遇到类似的 ipset 错误，都会将给定 IP 视为国外 IP。因此如果你因为各种原因不想导入 `chnroute6.ipset`，那么产生的效果就是：当客户端查询 IPv6 域名时（即 AAAA 查询），会导致所有国内 DNS 返回的解析结果都被过滤，然后采用可信 DNS 的解析结果。

---

### trust上游存在一定的丢包，怎么缓解

- 方法1：**重复发包**，也即 `--repeat-times N` 选项，这里的 `N` 默认为 1，可以改为 3，表示在给一个 trust 上游（UDP）转发查询消息时，同时发送 3 个相同的查询消息。
- 方法2：**TCP查询**，对于新版本（>= 2024.03.07），在 trust 上游的地址前加上 `tcp://`；对于老版本，可以加一层 [dns2tcp](https://github.com/zfl9/dns2tcp)，来将 chinadns-ng 发出的 UDP 查询转为 TCP 查询。

推荐方法2，因为 QoS 等因素，TCP 流量的优先级通常比 UDP 高，且 TCP 本身就提供丢包重传等机制，比重复发包策略更可靠。另外，很多代理程序的 UDP 实现效率较低，很有可能出现 TCP 查询总体耗时低于 UDP 查询的情况。

---

### 为何选择 ipset/nftset 来处理 chnroute 查询

因为使用 ipset/nftset 可以与 iptables/nftables 规则共用一份 chnroute；达到联动的效果。

---

### 是否支持 nftables 的 set 查询接口

~~目前还不支持，但已加入 TODO 列表，不出意外应该快了（主要是还在寻找不依赖任何库的情况下访问`nft set`）~~。2023.04.11 版本已支持。

---

### 是否打算支持 geoip.dat 等格式的 chnroute

目前没有这个计划，因为如果要自己实现 chnroute 集合，那就要实现高性能的数据结构和算法，这有点超出了我的能力范围。但更重要的是因为 chinadns-ng 通常与 iptables/nftables 一起使用（配合透明代理），若使用非 ipset/nftset 实现，会导致两份重复的 chnroute，且无法与 iptables/nftables 规则实现联动。

---

### 是否打算支持 geosite.dat 等格式的 gfwlist/chnlist

目前也没有这个计划，这些二进制格式需要引入 protobuf 等库，我不是很想引入依赖，而且 geosite.dat 本身也大。

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

传统上，这是通过 dnsmasq 来实现的，但 dnsmasq 的 server/ipset/nftset 功能不擅长处理大量域名，影响性能，只是 gfwlist.txt 域名数量比 chnlist.txt 少，所以影响较小。如果你在意性能，如低端路由器，可使用 chinadns-ng 来实现。

---

### 使用 chinadns-ng 替代 dnsmasq 的注意事项

chinadns-ng 2.0 已经足以替代经典用例下的 dnsmasq：

- 域名分流效率比 dnsmasq 高得多，即使存在大量域名规则，也不影响性能，内存占用也很低
- nftset 操作效率比 dnsmasq 高，即使在短时间内写入大量 IP 也没问题（dnsmasq 可能会报错）
- dnsmasq 的 TCP DNS 实现方式非常低效，每个 TCP 连接都可能在后台 fork 一个 dnsmasq 进程
- chinadns-ng 可强制使用 TCP 上游，且原生支持 DoT，wolfssl 的体积/性能/内存开销都非常优秀

对于路由器这种场景，你可能仍然需要 dnsmasq 的 DHCP 等功能，这种情况下，建议关闭 dnsmasq 的 DNS 功能：

- 修改 dnsmasq 配置，将`port`改为0，关闭 dnsmasq 的 DNS 功能，其他功能不受影响（如 DHCP）
- 此时请务必配置 `dhcp-option=option:dns-server,0.0.0.0`，确保会下发 dns-server 给 DHCP 客户端
- 因为关闭 DNS 功能后，在未显式配置相关 dhcp-option 的情况下，dnsmasq 不会自动下发 dns-server
- 0.0.0.0 是一个特殊 IP，dnsmasq 在内部会替换为“dnsmasq 所在主机的 IP”，避免写死 IP 地址，更灵活

---

### --noip-as-chnip 选项的作用

> 此选项只作用于 `tag:none 域名` && `qtype=A/AAAA` && `china 上游`，trust 上游不存在过滤。

chinadns-ng 对 tag:none 域名的 A/AAAA 查询有特殊处理逻辑：对 china 上游返回的 reply 进行 ip test (chnroute)，如果测试结果是 china IP，则采纳 china 上游的结果，否则采纳 trust 上游的结果（为了减少重复判定，可启用 verdict-cache 来缓存该测试结果）。

要进行 ip test，显然要求 reply 中有 IP 地址；如果没有 IP（如 NODATA 响应），就没办法 test 了。

- 默认情况下，chinadns-ng 将 no-ip 视为 **非 china IP**，也即：采纳 trust 上游结果。
- 若指定了 `--noip-as-chnip`，则将 no-ip 视为 **china IP**，也即：采纳 china 上游结果。

默认拒绝 china 上游的 no-ip 结果是为了避开 gfw 污染，防止 gfw 故意对某些域名返回空 answer (no-ip)。

---

### 如何以普通用户身份运行 chinadns-ng

向内核查询 ipset/nftset 需要 `CAP_NET_ADMIN` 权限，使用非 root 用户身份运行 chinadns-ng 时将产生 `Operation not permitted` 错误。解决方法有很多，这里介绍其中一种：

```shell
# 授予 CAP_NET_ADMIN 权限
# 用于执行 ipset/nftset 操作
sudo setcap cap_net_admin+ep /usr/local/bin/chinadns-ng

# 授予 CAP_NET_ADMIN + CAP_NET_BIND_SERVICE 权限
# 用于执行 ipset/nftset 操作、监听小于 1024 的端口
sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/chinadns-ng
```
