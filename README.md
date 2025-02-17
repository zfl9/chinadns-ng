## 简介

[ChinaDNS](https://github.com/shadowsocks/ChinaDNS) 的个人重构版本，功能简述：

- 基于 epoll、netlink(ipset/nftset) 实现，性能更强。
- 完整支持 IPv4 和 IPv6 协议，兼容 EDNS 请求和响应。
- 手动指定国内 DNS 和可信 DNS，而非自动识别，更加可控。
- 修复原版对保留地址的处理问题，去除过时特性，只留核心功能。
- 修复原版对可信 DNS 先于国内 DNS 返回而导致判断失效的问题。
- 支持 `chnlist/gfwlist` 域名列表，并深度优化了性能以及内存占用。
- 支持纯域名分流：要么走china上游，要么走trust上游，不进行IP测试。
- 可动态收集域名的解析结果IP至`ipset/nftset`，辅助各种代理/分流场景。
- 支持`nftables set`，并针对 IP add 操作进行了性能优化，避免操作延迟。
- 更加细致的 no-ipv6(AAAA) 控制，可根据域名类型，IP测试结果进行过滤。
- DNS 缓存、stale 缓存模式、缓存预刷新、缓存忽略名单（不缓存的域名）。
- 支持 tag:none 域名的判定结果缓存，避免重复请求和判定，减少DNS泄露。
- 除默认的 china、trust 组外，还有 6 个自定义组（上游DNS、ipset/nftset）。

---

对于常规的使用模式，大致原理和流程可总结为：

- 两组DNS上游：china组(大陆DNS)、trust组(国外DNS)。

- 两个域名列表：chnlist.txt(大陆域名)、gfwlist.txt(受污染域名)。

- chnlist.txt域名(tag:chn域名)，转发给china组，保证大陆域名不会被解析到国外，对大陆域名cdn友好。

- gfwlist.txt域名(tag:gfw域名)，转发给trust组，trust需返回未受污染的结果，比如走代理，具体方式不限。

- 其他域名(tag:none域名)，同时转发给china组和trust组，如果china组解析结果(A/AAAA)是大陆ip，则采纳china组，否则采纳trust组。是否为大陆ip的核心依据，就是测试ip是否在`ipset-name4/6`指定的地址集合中。

- 若启用了tag:none域名的判决缓存，则同一域名的后续请求只会转发给特定的上游组（china组或trust组，具体取决于之前的ip测试结果），建议启用此功能，避免重复请求、判定，减少DNS泄露。

- 如果使用纯域名分流模式，则不存在tag:none域名，因此要么走china组，要么走trust组，可避免dns泄露问题。

- 若启用`--add-tagchn-ip`，则tag:chn域名的解析结果IP会被动态添加到指定的ipset/nftset，配合chnroute透明代理分流时，可用于实现大陆域名必走直连，使dns分流与ip分流一致；类似 dnsmasq 的 ipset/nftset 功能。

- 若启用`--add-taggfw-ip`，则tag:gfw域名的解析结果IP会被动态添加到指定的ipset/nftset，可用来实现gfwlist透明代理分流；也可配合chnroute透明代理分流，用来收集黑名单域名的IP，用于iptables/nftables操作，比如确保黑名单域名必走代理，即使某些黑名单域名的IP是大陆IP。

> chinadns-ng 根据域名 tag 来执行不同逻辑，包括 ipset/nftset 的逻辑（test、add），见 [原理](#tagchntaggfwtagnone-%E6%98%AF%E6%8C%87%E4%BB%80%E4%B9%88)。

## 编译

> 请前往 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载可执行文件，添加可执行权限，放到 PATH 路径下（如 `/usr/local/bin/`）。

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

# 本机 (若构建失败，请手动指定"-Dtarget"和"-Dcpu")
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

# mips64/mips64el 请前往 releases 页面下载预编译的可执行文件
# 如果想自己编译，请先前往 zig 根目录，按顺序 apply 这两个补丁
# - https://github.com/ziglang/zig/pull/14541.patch
# - https://github.com/ziglang/zig/pull/14556.patch

# riscv64
zig build -Dtarget=riscv64-linux-musl
```

</p></details>

## Docker

因为要访问内核的 ipset/nftset，docker run 时请带上 `--privileged` 参数。

请前往 [releases](https://github.com/zfl9/chinadns-ng/releases) 页面下载可执行文件（无依赖），cp 至目标容器，运行即可。

## OpenWrt

- 某些科学上网插件附带了 chinadns-ng，请查看对应插件的文档。
- https://github.com/pexcn/openwrt-chinadns-ng (未适配 2.0 的新功能)。

## 配置示例

- chinadns-ng 通常与 iptables/nftables 透明代理一起使用。
- chinadns-ng 也可作为单纯的 DNS 转发器（如 UDP->TCP）使用。
- 下面列举的 3 种分流模式配置其实都是 [zfl9/ss-tproxy](https://github.com/zfl9/ss-tproxy) 中的相关用例。
- 程序不会自动创建 ipset/nftset 集合；如需 ip test/add，请先导入/创建 set。
- 所有带 ipset 字眼的配置都支持 nftset，如需使用 nftset，请阅读 [nftset 说明](#ipsetnftset-相关说明)。

---

### chnroute 分流

- chnlist.txt (tag:chn) 走国内上游，将 IP 收集至 `chnip,chnip6` ipset（可选）
- gfwlist.txt (tag:gfw) 走可信上游，将 IP 收集至 `gfwip,gfwip6` ipset（可选）
- 其他域名 (tag:none) 同时走国内和可信上游，根据 IP 测试结果决定最终响应

<details><summary><b>点我展开</b></summary><p>

```shell
# 监听地址和端口
bind-addr 0.0.0.0
bind-port 53

# 国内上游、可信上游
china-dns 223.5.5.5
trust-dns tcp://8.8.8.8

# 域名列表，用于分流
chnlist-file /etc/chinadns/chnlist.txt
gfwlist-file /etc/chinadns/gfwlist.txt
# chnlist-first

# 收集 tag:chn、tag:gfw 域名的 IP (可选)
add-tagchn-ip chnip,chnip6
add-taggfw-ip gfwip,gfwip6

# 测试 tag:none 域名的 IP (针对国内上游)
ipset-name4 chnroute
ipset-name6 chnroute6

# dns 缓存
cache 4096
cache-stale 86400
cache-refresh 20

# verdict 缓存 (用于 tag:none 域名)
verdict-cache 4096

# 详细日志
# verbose
```

</p></details>

---

### gfwlist 分流

- gfwlist.txt (tag:gfw) 走可信上游，将 IP 收集至 `gfwip,gfwip6` ipset（可选）
- 其他域名 (tag:chn) 走国内上游，不需要收集 IP（未指定 add-tagchn-ip）

<details><summary><b>点我展开</b></summary><p>

```shell
# 监听地址和端口
bind-addr 0.0.0.0
bind-port 53

# 国内上游、可信上游
china-dns 223.5.5.5
trust-dns tcp://8.8.8.8

# 域名列表，用于分流
# 未被 gfwlist.txt 匹配的归为 tag:chn
gfwlist-file /etc/chinadns/gfwlist.txt
default-tag chn

# 收集 tag:gfw 域名的 IP (可选)
add-taggfw-ip gfwip,gfwip6

# dns 缓存
cache 4096
cache-stale 86400
cache-refresh 20

# 详细日志
# verbose
```

</p></details>

---

### chnlist 分流

- chnlist.txt (tag:chn) 走国内上游，将 IP 收集至 `chnip,chnip6` ipset（可选）
- 其他域名 (tag:gfw) 走可信上游，不需要收集 IP（未指定 add-taggfw-ip）

<details><summary><b>点我展开</b></summary><p>

```shell
# 监听地址和端口
bind-addr 0.0.0.0
bind-port 53

# 国内上游、可信上游
china-dns 223.5.5.5
trust-dns tcp://8.8.8.8

# 域名列表，用于分流
# 未被 chnlist.txt 匹配的归为 tag:gfw
chnlist-file /etc/chinadns/chnlist.txt
default-tag gfw

# 收集 tag:chn 域名的 IP (可选)
add-tagchn-ip chnip,chnip6

# dns 缓存
cache 4096
cache-stale 86400
cache-refresh 20

# 详细日志
# verbose
```

</p></details>

---

### DNS 转发器

- 转发器不执行分流操作，但其他功能仍可正常使用，如 DNS 缓存、ip add、ipv6 过滤等。
- 核心在于 `-d chn`，由于未指定域名列表，因此所有查询都是 tag:chn，从而实现单纯转发。

```bash
# 127.0.0.1:53(udp/tcp) => 1.1.1.1(udp/tcp/tls)
# 允许指定任意多个 upstream，多次给出 -c 选项即可
# 使用 -d gfw 也是一样的，只不过将 -c 改为 -t 选项
chinadns-ng -b 127.0.0.1 -l 53 -d chn -c 1.1.1.1
chinadns-ng -b 127.0.0.1 -l 53 -d chn -c udp://1.1.1.1
chinadns-ng -b 127.0.0.1 -l 53 -d chn -c tcp://1.1.1.1
chinadns-ng -b 127.0.0.1 -l 53 -d chn -c tls://1.1.1.1
```

## 命令选项

- `-f` 短选项、`--foobar` 长选项
- `--foo <value>`：选项值是 required 的
- `--bar [value]`：选项值是 optional 的
- `--flag`：没有选项值，即 bool/flag 选项
- 配置文件中使用长选项格式（没有`--`），如 `verbose`

<details><summary><b>点我展开所有选项</b></summary><p>

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
 -N, --no-ipv6 [rules]                tag:<name>[@ip:*], ip:china, ip:non_china
                                      if no rules, then filter all AAAA queries
 --filter-qtype <qtypes>              filter queries with the given qtype (u16)
 --cache <size>                       enable dns caching, size 0 means disabled
 --cache-stale <N>                    use stale cache: expired time <= N(second)
 --cache-refresh <N>                  pre-refresh the cached data if TTL <= N(%)
 --cache-nodata-ttl <ttl>             TTL of the NODATA response, default is 60
 --cache-ignore <domain>              ignore the dns cache for this domain(suffix)
 --cache-db <path>                    dns cache persistence (from/to db file)
 --verdict-cache <size>               enable verdict caching for tag:none domains
 --verdict-cache-db <path>            verdict cache persistence (from/to db file)
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

</p></details>

---

### config

- `-C/--config <path>` 指定配置文件路径，支持多个配置文件。
  - 配置文件是一个 UTF-8 纯文本文件，没有特定的文件扩展名。
  - 格式 `optname [value]`，`optname` 是不带 `--` 的长命令行选项名。
  - 例如 `bind-addr 127.0.0.1`、`bind-port 65353`、`noip-as-chnip`。
  - 空白行、`#`开头的行 被忽略；不支持行尾注释（如`verbose #foo`）。
  - 文件中可多次使用 `config <path>` 配置行来实现配置文件包含的效果。
- `-C/--config` 只是从给定文本文件读取“命令行选项”并处理，无其他特别之处。
- `-C/--config` 和其他命令行选项可随意混用，不可重复的选项以最后一个为准。

### bind-addr、bind-port

- `bind-addr` 用于指定监听地址，默认为 127.0.0.1。
  - 2023.10.28 版本起，若监听地址为 `::`，则允许来自 IPv4/IPv6 的 DNS 查询。
  - 2024.03.07 版本起，`bind-addr` 允许指定多次，以便监听多个不同的 ip 地址。
- `bind-port` 用于指定监听端口，默认为 65353。
  - 2024.03.07 版本起，将同时监听 UDP 和 TCP 端口，之前只监听了 UDP。
  - 2024.03.25 版本起，可以给 `bind-port` 指定要监听的协议（UDP、TCP）：
    - `--bind-port 65353`：监听 UDP 和 TCP（默认）。
    - `--bind-port 65353@udp`：只监听 UDP。
    - `--bind-port 65353@tcp`：只监听 TCP。
  - 2024.07.16 版本起，`bind-port` 允许指定多次，以便监听多个不同的 port。

### china-dns、trust-dns

- `china-dns` 选项指定国内上游 DNS 服务器，多个用逗号隔开。
- `trust-dns` 选项指定可信上游 DNS 服务器，多个用逗号隔开。
  - 国内上游默认为 `114.114.114.114`，可信上游默认为 `8.8.8.8`。
  - 组内的多个上游服务器是并发查询的模式，采纳最先返回的那个结果。
  - 2024.03.07 版本起，允许多次指定 `china-dns`、`trust-dns` 选项/配置。
  - 2024.03.07 版本起，每组上游的服务器数量不受限制（之前最多两个）。

### 上游服务器的地址格式

- 完整格式：`proto:// host@ ip #port ?count=N ?life=N`
- 注：加空格只是为了方便阅读和说明，实际格式中并没有空格。
- `proto://`：可省略，查询协议，默认为`无`。
  - `无`：UDP/TCP 上游，根据查询方的传入协议来决定使用 UDP 查询还是 TCP 查询。
  - `udp://`：UDP 上游。
  - `tcp://`：TCP 上游。
  - `tls://`：DoT 上游（需使用 wolfssl 版本）。
- `host@`：可省略，用于 DoT 上游。
  - 提供 SSL/TLS 握手时的 SNI（服务器名称指示）信息。
  - 启用 SSL/TLS 证书验证时，将检查证书中的域名是否与之匹配。
- `ip`：不可省略，支持 IPv4 和 IPv6 地址（不需要用 `[]` 括起来）。
- `#port`：可省略，默认为所选定协议的标准端口（UDP/TCP 是 53，DoT 是 853）。
- `?count=N`：可省略，默认为 10，表示单个会话最多处理多少查询，见 [#189](https://github.com/zfl9/chinadns-ng/issues/189)。
  - 0 表示不限制，只要上游不主动断开连接，对应 TCP/TLS 会话就一直存在。
- `?life=N`：可省略，默认为 10，表示单个会话最多存活多少秒，见 [#189](https://github.com/zfl9/chinadns-ng/issues/189)。
  - 0 表示不限制，只要上游不主动断开连接，对应 TCP/TLS 会话就一直存在。

### chnlist-file、gfwlist-file、chnlist-first

- `chnlist-file` 白名单 [域名列表文件](#域名列表)，命中的域名只走国内 DNS。
- `gfwlist-file` 黑名单 [域名列表文件](#域名列表)，命中的域名只走可信 DNS。
  - 2023.04.01 版本起，可指定多个路径，逗号隔开，如 `-g a.txt,b.txt`。
  - 2024.03.07 版本起，可多次指定 `chnlist-file`、`gfwlist-file` 选项。
- `chnlist-first` 选项表示优先加载 chnlist，默认是优先加载 gfwlist。
  - 只有 chnlist 和 gfwlist 文件都提供时，`*-first` 才有实际意义。

### default-tag

- `default-tag` 可用于实现"纯域名分流"，也可用于实现 [gfwlist分流](#chinadns-ng-也可用于-gfwlist-透明代理分流)。
- 其核心逻辑是设置 **未匹配任何列表的域名** 的`tag`，并无其他特别之处。
- 通常与`-g`或`-m`选项一起使用，比如下述例子，实现了"纯域名分流"模式：
  - `-g gfwlist.txt -d chn`：gfw列表的域名走可信上游，其他走国内上游。
  - `-m chnlist.txt -d gfw`：chn列表的域名走国内上游，其他走可信上游。
- 如果想了解更多细节，建议看一下 [chinadns-ng 的核心处理流程](#tagchntaggfwtagnone-是指什么)。

### add-tagchn-ip、add-taggfw-ip

- `add-tagchn-ip` 用于动态添加 tag:chn 域名的解析结果 ip 至 ipset/nftset 集合。
- `add-taggfw-ip` 用于动态添加 tag:gfw 域名的解析结果 ip 至 ipset/nftset 集合。
  - 参数为`ipv4集合名[,ipv6集合名]`，nftset 格式和注意事项见 [nftset 相关说明](#ipsetnftset-相关说明)。
  - 对于`add-tagchn-ip`，若未给出集合名，则使用`ipset-name4/6`的那个集合。
  - 2024.04.13 版本起，可使用特殊集合名 `null` 表示对应集合不会被使用：
    - `--add-tagchn-ip null,chnip6`：表示不需要收集 ipv4 地址
    - `--add-tagchn-ip chnip,null`：表示不需要收集 ipv6 地址
    - `--add-tagchn-ip chnip`：表示不需要收集 ipv6 地址
    - 注意：仅当 ipv6 集合为 `null` 时，才可被省略

### ipset-name4、ipset-name6

- `ipset-name4` 大陆 IPv4 地址的 ipset/nftset 集合名，默认为 `chnroute` (ipset)。
- `ipset-name6` 大陆 IPv6 地址的 ipset/nftset 集合名，默认为 `chnroute6` (ipset)。
- 这两个集合用于 tag:none 域名，用于判定 china 上游的解析结果是否为大陆 IP。
- 2024.04.13 版本起，也用于 `--no-ipv6` 的 `ip:china`、`ip:non_china` 规则。
- 2024.04.13 版本起，可使用特殊集合名 `null` 表示对应集合不会被使用。

### ipset/nftset 相关说明

相关配置/命令行选项：

- **ip test**：`ipset-name4`、`ipset-name6`（默认为 chnroute、chnroute6）
- **ip add**：`add-tagchn-ip`、`add-taggfw-ip`、`group-ipset`（无默认行为）
- ip add 选项的参数为`ipv4集合名[,ipv6集合名]`，`null`可作为空集合的占位符
- 注意：所有相关配置要么使用 ipset 后端，要么使用 nftset 后端，不允许混用
- 程序不会自动创建 ipset/nftset 集合，如果需要，请先手动导入/创建相关集合

ipset 相关说明：

- 集合名正常给出即可，如 chnroute
- res/chnroute.ipset 文件的集合名：`chnroute`
- res/chnroute6.ipset 文件的集合名：`chnroute6`

nftset 相关说明：

- 集合名的完整格式：`family名@table名@set名`
- 创建 nftset 集合时，必须带上 `flags interval` 标志
- 支持的 family：`ip`、`ip6`、`inet`、`arp`、`bridge`、`netdev`
- res/chnroute.nftset 文件的集合名：`inet@global@chnroute`
- res/chnroute6.nftset 文件的集合名：`inet@global@chnroute6`

### group、group-*

- `group` 声明一个自定义组（tag），参数值是组（tag）的名字。
  - 支持最多 6 个自定义组，每个组都有 3 个信息可配置，其中 ipset 可选。
  - 加载域名列表文件时，优先加载自定义组，然后加载内置组（chn、gfw）。
  - 内置组的加载顺序没有改变，依旧默认 gfw 优先，使用 `-M` 切换为 chn 优先。
  - 对于多个自定义组，按照命令行参数/配置顺序，后声明的组具有更高优先级。
  - 用例 1：将 DDNS域名 划分出来，单独一个组，用域名提供商的 DNS 去解析。
  - 用例 2：将 公司域名 划分出来，单独一个组，用公司内网专用的 DNS 去解析。
  - 2024.04.27 版本起，使用 `null` 作为 group 名时，表示过滤该组的域名查询。
    - null 组只有 `group-dnl` 信息，查询相关域名时，将返回 NODATA 响应消息。
- `group-dnl` 当前组的[域名列表文件](#域名列表)，多个用逗号隔开，可多次指定。
- `group-upstream` 当前组的上游 DNS，多个用逗号隔开，可多次指定。
- `group-ipset` 当前组的 ipset/nftset (可选)，用于收集解析出的结果 IP。

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

- `no-ipv6` 过滤 AAAA 查询（查询域名的 IPv6 地址），默认不启用。
  - 此选项可多次指定，选项参数为`过滤规则`。
    - 如果没有选项参数，则表示过滤所有 AAAA 查询。
    - 选项参数中可以有多条`过滤规则`，中间用逗号隔开。
    - 被`过滤规则`匹配的查询将以 NODATA 形式进行响应。
  - `过滤规则`的完整形式为`tag:域名组@ip:测试结果`。
    - 每个域名组都有一个 AAAA 过滤器，不同域名组的过滤规则互相独立。
    - `tag:域名组`是域名组选择器，表示`过滤条件`将要添加到哪个域名组中。
    - `ip:测试结果`是`过滤条件`，若域名组中的查询符合其条件，则被“过滤”。
    - 若未指定`tag:域名组@`部分，则该`过滤条件`将添加到每个域名组中。
    - 若未指定`@ip:测试结果`部分，则该域名组的所有查询都将被“过滤”。
  - `ip:测试结果`只有以下两种（二选一）：
    - `ip:china`：若域名解析结果为 **大陆 IPv6 地址**，则“过滤”。
    - `ip:non_china`：若域名解析结果为 **非大陆 IPv6 地址**，则“过滤”。
    - IPv6 数据库由 `--ipset-name6` 选项提供，默认为 `chnroute6` (ipset)。
  - 列举一些 `过滤规则`，以及对应的 AAAA 过滤效果：
    - `tag:none`：过滤 none 域名组中 所有 AAAA 查询。
    - `ip:non_china`：过滤 所有 域名组中 解析结果为 '非大陆 IPv6' 的 AAAA 查询。
    - `tag:none@ip:non_china`：过滤 none 域名组中 解析结果为 '非大陆 IPv6' 的 AAAA 查询。

### filter-qtype

- `filter-qtype` 过滤给定 qtype 的查询，多个用逗号隔开，可多次指定。
  - `--filter-qtype 64,65`：过滤 SVCB(64)、HTTPS(65) 查询

### cache、cache-*

- `cache` 启用 DNS 缓存，参数是缓存容量（最多缓存多少个请求的响应消息）。
- `cache-stale` 允许使用 TTL 已过期的（陈旧）缓存，参数是最大过期时长（秒）。
  - 向查询方返回“陈旧”缓存的同时，自动在后台刷新缓存，以便稍后能使用新数据。
  - 2024.04.13 版本起，数据类型从 `u16` 改为 `u32`，以允许设置更大的过期时长。
- `cache-refresh` 若当前查询的缓存的 TTL 不足初始值的百分之 N，则提前在后台刷新。
- `cache-nodata-ttl` 给 NODATA 响应提供默认的缓存时长，默认 60 秒，0 表示不缓存。
- `cache-ignore` 不要缓存给定的域名（后缀，最高支持 8 级），此选项可多次指定。
- `cache-db` 启用缓存持久化，参数是 db 文件路径（可以不预先创建）。
  - 进程启动时，自动从 db 恢复缓存；进程退出时，自动将缓存写回至 db。
  - “进程退出”是指进程收到`SIGTERM/SIGINT`信号，即`kill <PID>`或`CTRL+C`。
  - “缓存写回”可通过`SIGUSR1`信号强制触发（未启用持久化则写至`/tmp/chinadns@cache.db`）。
  - 为了降低性能开销，恢复缓存时不进行校验，请勿修改 db 文件，请勿跨平台共享 db 文件。
  - 有时可能需要手动清空 db 文件来丢弃旧缓存（关进程，清空文件，重新启动），例如：
    - 更改了`cache-ignore`、域名列表（内容更改、优先级更改等）。
    - ~~需要重新触发 add ip 操作（有缓存的情况下不会触发 add ip）~~。
    - 2024.07.21 版本起，从 db 恢复的缓存被首次查询时将触发 add-ip。
  - tool/dns_cache_mgr 可用于操纵 db 文件，进入 tool 目录，`./make.sh` 即可。
    - `./dns_cache_mgr`：列出 db 中的所有缓存条目（域名、qtype、TTL、size 等）。
    - `./dns_cache_mgr -r 域名后缀`：删除给定域名的缓存条目，-r 选项可以多次指定。
    - 默认 db 文件路径是当前目录下的 `dns-cache.db`，可通过 `-f 文件路径` 选项修改。

### verdict-cache

- `verdict-cache` 启用 tag:none 域名的判决结果缓存，参数是缓存容量。
  - tag:none 域名的查询会同时转发给 china、trust 上游，根据 china 上游的 ip test 结果，决定最终响应。
  - 这里说的 **判决结果** 就是指这个 ip test 结果，即：给定的 tag:none 域名是 **大陆域名** 还是 **非大陆域名**。
  - 如果记下此信息，则后续查询同一域名时（未命中 DNS 缓存时），只转发给特定上游组，不同时转发。
  - 缓存容量上限是 65535，此缓存没有 TTL 限制；缓存满时会随机删除一个旧缓存数据。
  - 建议启用此缓存，可帮助减少 tag:none 域名的重复请求和判定，还能减少 DNS 泄露。
  - 注意，判决结果缓存与 DNS 缓存是互相独立的、互补的；这两个缓存系统可同时启用。
- `verdict-cache-db` 启用缓存持久化，参数是 db 文件路径（可以不预先创建）。
  - 进程启动时，自动从 db 恢复缓存；进程退出时，自动将缓存写回至 db。
  - “进程退出”是指进程收到`SIGTERM/SIGINT`信号，即`kill <PID>`或`CTRL+C`。
  - “缓存写回”可通过`SIGUSR1`信号强制触发（未启用持久化则写至`/tmp/chinadns@verdict-cache.db`）。
  - db 是“纯文本”文件，可手动编辑和共享，第一个字段为“是否大陆域名(1是0否)”，第二个字段为“域名”。

### hosts、dns-rr-ip

- `hosts` 加载 hosts 文件，参数默认值为 `/etc/hosts`，此选项可多次指定。
- `dns-rr-ip` 定义本地的 A/AAAA 记录（与 hosts 类似），此选项可多次指定。
  - 格式：`<names>=<ips>`，多个 name 使用逗号隔开，多个 ip 使用逗号隔开。

### cert-verify、ca-certs

- `cert-verify` 验证 DoT 上游的 SSL 证书（有效性，是否受信任，域名是否匹配）。
  - wolfssl 在某些平台（arm32、mips）可能无法正确验证 SSL 证书，见 [#169](https://github.com/zfl9/chinadns-ng/issues/169)。
- `ca-certs` CA 根证书路径，用于验证 DoT 上游的 SSL 证书。默认自动检测。

### no-ipset-blacklist

- `no-ipset-blacklist` 若指定此选项，则 add-ip 时不进行内置的 IP 过滤。
  - 默认情况下，以下 IP 不会被添加到 ipset/nftset 集合，见 [#162](https://github.com/zfl9/chinadns-ng/issues/162)
  - `127.0.0.0/8`、`0.0.0.0/8`、`::1`、`::` (loopback地址、全0地址)

### 其他杂项配置

- `timeout-sec` 用于指定上游的响应超时时长，单位秒，默认 5 秒。
- `repeat-times` 针对可信 DNS (UDP) [重复发包](#trust上游存在一定的丢包怎么缓解)，默认为 1，最大为 5。
- `noip-as-chnip` 接受来自 china 上游的没有 IP 地址的响应，[详细说明](#--noip-as-chnip-选项的作用)。
- `fair-mode` 从`2023.03.06`版本开始，只有公平模式，指不指定都一样。
- `reuse-port` 用于多进程负载均衡（实践证明没必要，单进程已经够用）。
- `verbose` 选项表示记录详细的运行日志，除非调试，否则不建议启用。

## 域名列表

**文件格式**

域名列表是一个纯文本文件（不支持注释），每行都是一个 **域名后缀**，如`baidu.com`、`www.google.com`、`www.google.com.hk`，不要以`.`开头或结尾，出于性能考虑，域名`label`数量做了人为限制，最多只能`4`个，过长的会被截断，如`test.www.google.com.hk`截断为`www.google.com.hk`。

---

**加载顺序**

所有组的域名列表都被 **加载** 到同一个数据结构，一个 **域名后缀** 一旦被加载，其内部属性就不会被修改。因此，当一个 **域名后缀** 存在于多个组的域名列表时，优先加载的那个组将“获胜”。举个例子：假设 `foo.com` 同时存在于 tag:chn、tag:gfw 组的域名列表内，且优先加载 tag:gfw 组，则 `foo.com` 属于 tag:gfw 组。

先加载“自定义组”的域名列表，然后再加载“内置组”的域名列表（chn 和 gfw 谁先，取决于`--chnlist-first`）。

---

**匹配顺序**

收到 dns query 时，会对 qname 进行 **最长后缀匹配**。举个例子，若 qname 为 `x.y.z.d.c.b.a`，则匹配顺序为：

- `d.c.b.a`，检查数据结构中是否存在此域名后缀。
- `c.b.a`，检查数据结构中是否存在此域名后缀。
- `b.a`，检查数据结构中是否存在此域名后缀。
- `a`，检查数据结构中是否存在此域名后缀。

一旦其中某个 **域名后缀** 匹配成功，匹配就结束，并获取该 **域名后缀** 所属的 tag(group)，并将 tag 信息记录到该 dns query 的相关数据结构，后续所有逻辑（分流、ipset/nftset）都基于这个 tag 信息，与 qname 无关。

如果都匹配失败，则该 dns query 的 tag 被设为 `default-tag` 选项的值，默认情况下，`default-tag` 是 none。global 分流、gfwlist 分流都基于此机制实现。你可以将 `default-tag` 设为不同的 tag，来实现各种目的。

---

**性能、内存开销**

chinadns-ng 在编码时特意考虑了性能和内存占用，并进行了深度优化，因此不必担心查询效率和内存开销。域名条目数量只会影响一点儿内存占用，对查询速度没影响，也不必担心内存占用，这是在`Linux x86-64`的实测数据：

- 没有加载域名列表时，内存为 `140` KB
- 加载 5700+ 条 `gfwlist.txt` 时，内存为 `304` KB
- 加载 5700+ 条 `gfwlist.txt` 以及 73300+ 条 `chnlist.txt` 时，内存为 `2424` KB
- 如果确实内存吃紧，可以使用更加精简的 chnlist 源（不建议只使用 gfwlist.txt 列表）
- 2023.04.11 版本针对域名列表的内存占用做了进一步优化，因此占用会更少，测试数据就不贴了

## 简单测试

导入 chnroute/chnroute6 大陆 IP 数据库（用于 tag:none 域名的 IP 测试）：

```bash
# ipset (chnroute, chnroute6)
ipset -R <res/chnroute.ipset
ipset -R <res/chnroute6.ipset

# nftset (inet@global@chnroute, inet@global@chnroute6)
nft -f res/chnroute.nftset
nft -f res/chnroute6.nftset

# 只需导入一次，除非对应集合已从内核移除（比如重启了）
```

运行 chinadns-ng，我自己配了全局透明代理，所以访问 `8.8.8.8` 会走代理。

```bash
# ipset
chinadns-ng -m res/chnlist.txt -g res/gfwlist.txt -v

# nftset
chinadns-ng -m res/chnlist.txt -g res/gfwlist.txt -v -4 inet@global@chnroute -6 inet@global@chnroute6
```

chinadns-ng 默认监听 `127.0.0.1:65353`，可以给 chinadns-ng 加上 -v 参数，使用 dig 测试，观察其日志。

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
# 纯 shell 语法：
(chinadns-ng 参数... </dev/null &>>/var/log/chinadns-ng.log &)

# 也可借助 systemd 的 service 来实现，此处不展开叙述
```

---

### 如何更新 chnroute.ipset、chnroute6.ipset

```bash
cd res
./update-chnroute.sh
./update-chnroute6.sh
ipset -F chnroute
ipset -F chnroute6
ipset -R -exist <chnroute.ipset
ipset -R -exist <chnroute6.ipset
# 支持运行时重载 ipset/nftset，无需操作 chinadns-ng 进程
```

---

### 如何更新 chnroute.nftset、chnroute6.nftset

```bash
cd res
./update-chnroute-nft.sh
./update-chnroute6-nft.sh
nft flush set inet global chnroute
nft flush set inet global chnroute6
nft -f chnroute.nftset
nft -f chnroute6.nftset
# 支持运行时重载 ipset/nftset，无需操作 chinadns-ng 进程
```

---

### 如何更新 chnlist.txt、gfwlist.txt

```bash
cd res
./update-chnlist.sh
./update-gfwlist.sh
# pkill chinadns-ng # 关闭旧的 chinadns-ng 进程
chinadns-ng -m chnlist.txt -g gfwlist.txt 其他参数... # 重新运行 chinadns-ng
```

---

### 如何使用 TCP 协议与 DNS 上游进行通信

从 2024.03.07 版本开始，有以下更改：

- 若上游地址为 `1.1.1.1`，则根据 **查询方的传入协议** 来选择与上游的通信协议：
  - 若查询方的传入协议为 UDP，则 chinadns-ng 与该上游的通信协议为 UDP。
  - 若查询方的传入协议为 TCP，则 chinadns-ng 与该上游的通信协议为 TCP。
- 若上游地址为 `udp://1.1.1.1`，则 chinadns-ng 与该上游的通信方式为 UDP。
- 若上游地址为 `tcp://1.1.1.1`，则 chinadns-ng 与该上游的通信方式为 TCP。
- 若上游地址为 `tls://1.1.1.1`，则 chinadns-ng 与该上游的通信方式为 TLS(DoT)。

---

### 为什么不内置 ~~TCP~~、~~DoT~~、DoH 等协议的支持

- 2024.03.07 版本起，已内置完整的 TCP 支持（传入、传出）。
- 2024.04.27 版本起，支持 DoT 协议的上游，DoH 不打算实现。

我想让代码保持简单，只做真正必要的事，其他事让专业工具去做。

换句话说，让程序保持简单和愚蠢，只做一件事，并认真做好这件事。

---

### chinadns-ng 并不读取 chnroute.ipset、chnroute6.ipset

启动时也不会检查这些 ipset/nftset 集合是否已存在，程序只在收到来自国内上游的 DNS 响应时（仅针对 tag:none 域名），通过 netlink 查询给定 ipset/nftset 集合，对应 IP 是否存在。这种机制使得我们可以在 chinadns-ng 运行时直接更新 chnroute、chnroute6 列表，它立即生效，不需要重启 chinadns-ng。

> 只有 tag:none 域名存在 ipset/nftset 判断&&过滤。

---

### 接受 china 上游返回的 IP为保留地址 的解析记录

将对应的地址(段)加入到 `chnroute`、`chnroute6` 集合即可。chinadns-ng 判断是否为"大陆 IP"的核心依据就是查询 chnroute、chnroute6 集合，程序内部并没有其他隐含的判断规则。

注意：**只有 tag:none 域名需要这么做**；对于 tag:chn 域名，chinadns-ng 只是转发，不涉及 ipset/nftset 判定；所以你也可以将相关域名加入到 chnlist.txt 列表（支持从多个文件加载域名列表）。

为什么没有默认将保留地址加入 `chnroute*.ipset/nftset`？因为我担心 GFW/ISP 会给受污染域名返回保留地址，所以没放到 chnroute 去。不过现在受污染域名都走 gfwlist.txt 机制了，只会走 trust 上游，加进去应该是没问题的。

---

### received an error code from kernel: (-2) No such file or directory

- 如果是 ip test 报错，说明未导入 chnroute、chnroute6，请导入相关 ipset/nftset 集合。
- 如果是 ip add 报错，说明未提前创建给定的 ipset/nftset，请创建配置中给出的相关集合。

---

### trust上游存在一定的丢包，怎么缓解

- 方法1：**重复发包**，也即 `--repeat-times N` 选项，这里的 `N` 默认为 1，可以改为 3，表示在给一个 trust 上游（UDP）转发查询消息时，同时发送 3 个相同的查询消息。
- 方法2：**TCP查询**，对于新版本（>= 2024.03.07），在 trust 上游的地址前加上 `tcp://`；对于老版本，可以加一层 [dns2tcp](https://github.com/zfl9/dns2tcp)，来将 chinadns-ng 发出的 UDP 查询转为 TCP 查询。

推荐方法2，因为 QoS 等因素，TCP 流量的优先级通常比 UDP 高，且 TCP 本身就提供丢包重传等机制，比重复发包策略更可靠。另外，很多代理程序的 UDP 实现效率较低，很有可能出现 TCP 查询总体耗时低于 UDP 查询的情况。

---

### 为何选择 ipset/nftset 来处理 chnroute 查询

因为使用 ipset/nftset 可以与 iptables/nftables 规则共用一份 chnroute；达到联动的效果。

---

### 是否打算支持 geoip.dat 等格式的 chnroute

目前没有这个计划，因为 chinadns-ng 通常与 iptables/nftables 一起使用（配合透明代理），若使用非 ipset/nftset 实现，会导致两份重复的 chnroute，且无法与 iptables/nftables 规则实现联动。

---

### 是否打算支持 geosite.dat 等格式的 gfwlist/chnlist

目前没有这个计划，这些二进制格式需要引入 protobuf 等库，我不想引入依赖，而且 geosite.dat 本身也很大。

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

对于路由器等场景，你可能仍然需要 dnsmasq 的 DHCP 等功能，这种情况下，建议关闭 dnsmasq 的 DNS：

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

默认拒绝 china 上游的 no-ip 结果是为了减少 GFW/ISP 污染，防止其故意对某些域名返回空 answer (no-ip)。

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
