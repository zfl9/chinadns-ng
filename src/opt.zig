const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const groups = @import("groups.zig");
const str2int = @import("str2int.zig");
const Tag = @import("tag.zig").Tag;
const cache_ignore = @import("cache_ignore.zig");
const local_rr = @import("local_rr.zig");
const assert = std.debug.assert;

const help =
    \\usage: chinadns-ng <options...>. the existing options are as follows:
    \\ -C, --config <path>                  format similar to the long option
    \\ -b, --bind-addr <ip>                 listen address, default: 127.0.0.1
    \\ -l, --bind-port <port[@proto]>       listen port number, default: 65353
    \\ -c, --china-dns <upstreams>          china dns server, default: <114 DNS>
    \\ -t, --trust-dns <upstreams>          trust dns server, default: <Google DNS>
    \\ -m, --chnlist-file <paths>           path(s) of chnlist, '-' indicate stdin
    \\ -g, --gfwlist-file <paths>           path(s) of gfwlist, '-' indicate stdin
    \\ -M, --chnlist-first                  match chnlist first, default gfwlist first
    \\ -d, --default-tag <tag>              chn or gfw or <user-tag> or none(default)
    \\ -a, --add-tagchn-ip [set4,set6]      add the ip of name-tag:chn to ipset/nftset
    \\                                      use '--ipset-name4/6' setname if no value
    \\ -A, --add-taggfw-ip <set4,set6>      add the ip of name-tag:gfw to ipset/nftset
    \\ -4, --ipset-name4 <set4>             ip test for tag:none, default: chnroute
    \\ -6, --ipset-name6 <set6>             ip test for tag:none, default: chnroute6
    \\                                      if setname contains @, then use nftset
    \\                                      format: family_name@table_name@set_name
    \\ --group <name>                       define rule group: {dnl, upstream, ipset}
    \\ --group-dnl <paths>                  domain name list for the current group
    \\ --group-upstream <upstreams>         upstream dns server for the current group
    \\ --group-ipset <set4,set6>            add the ip of the current group to ipset
    \\ -N, --no-ipv6 [rules]                tag:<name>[@ip:*], ip:china, ip:non_china
    \\                                      if no rules, then filter all AAAA queries
    \\ --filter-qtype <qtypes>              filter queries with the given qtype (u16)
    \\ --cache <size>                       enable dns caching, size 0 means disabled
    \\ --cache-stale <N>                    use stale cache: expired time <= N(second)
    \\ --cache-refresh <N>                  pre-refresh the cached data if TTL <= N(%)
    \\ --cache-nodata-ttl <ttl>             TTL of the NODATA response, default is 60
    \\ --cache-ignore <domain>              ignore the dns cache for this domain(suffix)
    \\ --cache-db <path>                    dns cache persistence (from/to db file)
    \\ --verdict-cache <size>               enable verdict caching for tag:none domains
    \\ --verdict-cache-db <path>            verdict cache persistence (from/to db file)
    \\ --hosts [path]                       load hosts file, default path is /etc/hosts
    \\ --dns-rr-ip <names>=<ips>            define local resource records of type A/AAAA
    \\ --cert-verify                        enable SSL certificate validation, default: no
    \\ --ca-certs <path>                    CA certs path for SSL certificate validation
    \\ --no-ipset-blacklist                 add-ip: don't enable built-in ip blacklist
    \\                                      blacklist: 127.0.0.0/8, 0.0.0.0/8, ::1, ::
    \\ -o, --timeout-sec <sec>              response timeout of upstream, default: 5
    \\ -p, --repeat-times <num>             num of packets to trustdns, default:1, max:5
    \\ -n, --noip-as-chnip                  allow no-ip reply from chinadns (tag:none)
    \\ -f, --fair-mode                      enable fair mode (nop, only fair mode now)
    \\ -r, --reuse-port                     enable SO_REUSEPORT, default: <disabled>
    \\ -v, --verbose                        print the verbose log, default: <disabled>
    \\ -V, --version                        print `chinadns-ng` version number and exit
    \\ -h, --help                           print `chinadns-ng` help information and exit
    \\bug report: https://github.com/zfl9/chinadns-ng. email: zfl9.com@gmail.com (Otokaze)
;

const version: cc.ConstStr = b: {
    var target: [:0]const u8 = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.abi);

    if (builtin.target.isGnuLibC())
        target = target ++ std.fmt.comptimePrint(".{}", .{builtin.os.version_range.linux.glibc});

    if (!std.mem.eql(u8, target, build_opts.target))
        @compileError("target-triple mismatch: " ++ target ++ " != " ++ build_opts.target);

    const cpu_model = builtin.cpu.model.name;

    if (!std.mem.startsWith(u8, build_opts.cpu, cpu_model))
        @compileError("cpu-model mismatch: " ++ cpu_model ++ " != " ++ build_opts.cpu);

    var prefix: [:0]const u8 = "ChinaDNS-NG " ++ build_opts.version ++ " " ++ build_opts.commit_id;

    if (build_opts.enable_wolfssl)
        prefix = prefix ++ " | wolfssl-" ++ build_opts.wolfssl_version;

    if (build_opts.enable_mimalloc)
        prefix = prefix ++ " | mimalloc-" ++ build_opts.mimalloc_version;

    break :b std.fmt.comptimePrint("{s} | target:{s} | cpu:{s} | mode:{s} | {s}", .{
        prefix,
        build_opts.target,
        build_opts.cpu,
        build_opts.mode,
        "<https://github.com/zfl9/chinadns-ng>",
    });
};

// ================================================================

comptime {
    // @compileLog("sizeof(OptDef):", @sizeOf(OptDef), "alignof(OptDef):", @alignOf(OptDef));
    // @compileLog("sizeof([]const u8):", @sizeOf([]const u8), "alignof([]const u8):", @alignOf([]const u8));
    // @compileLog("sizeof(OptFn):", @sizeOf(OptFn), "alignof(OptFn):", @alignOf(OptFn));
    // @compileLog("sizeof(enum{a,b,c}):", @sizeOf(enum { a, b, c }), "alignof(enum{a,b,c}):", @alignOf(enum { a, b, c }));
}

const OptDef = struct {
    short: []const u8, // short name
    long: []const u8, // long name
    optfn: OptFn,
    value: enum { required, optional, no_value },
};

const OptFn = std.meta.FnPtr(fn (in_value: ?[]const u8) void);

// zig fmt: off
const optdef_array = [_]OptDef{
    .{ .short = "C", .long = "config",             .value = .required, .optfn = opt_config,             },
    .{ .short = "b", .long = "bind-addr",          .value = .required, .optfn = opt_bind_addr,          },
    .{ .short = "l", .long = "bind-port",          .value = .required, .optfn = opt_bind_port,          },
    .{ .short = "c", .long = "china-dns",          .value = .required, .optfn = opt_china_dns,          },
    .{ .short = "t", .long = "trust-dns",          .value = .required, .optfn = opt_trust_dns,          },
    .{ .short = "m", .long = "chnlist-file",       .value = .required, .optfn = opt_chnlist_file,       },
    .{ .short = "g", .long = "gfwlist-file",       .value = .required, .optfn = opt_gfwlist_file,       },
    .{ .short = "M", .long = "chnlist-first",      .value = .no_value, .optfn = opt_chnlist_first,      },
    .{ .short = "d", .long = "default-tag",        .value = .required, .optfn = opt_default_tag,        },
    .{ .short = "a", .long = "add-tagchn-ip",      .value = .optional, .optfn = opt_add_tagchn_ip,      },
    .{ .short = "A", .long = "add-taggfw-ip",      .value = .required, .optfn = opt_add_taggfw_ip,      },
    .{ .short = "4", .long = "ipset-name4",        .value = .required, .optfn = opt_ipset_name4,        },
    .{ .short = "6", .long = "ipset-name6",        .value = .required, .optfn = opt_ipset_name6,        },
    .{ .short = "",  .long = "group",              .value = .required, .optfn = opt_group,              },
    .{ .short = "",  .long = "group-dnl",          .value = .required, .optfn = opt_group_dnl,          },
    .{ .short = "",  .long = "group-upstream",     .value = .required, .optfn = opt_group_upstream,     },
    .{ .short = "",  .long = "group-ipset",        .value = .required, .optfn = opt_group_ipset,        },
    .{ .short = "N", .long = "no-ipv6",            .value = .optional, .optfn = opt_no_ipv6,            },
    .{ .short = "",  .long = "filter-qtype",       .value = .required, .optfn = opt_filter_qtype,       },
    .{ .short = "",  .long = "cache",              .value = .required, .optfn = opt_cache,              },
    .{ .short = "",  .long = "cache-stale",        .value = .required, .optfn = opt_cache_stale,        },
    .{ .short = "",  .long = "cache-refresh",      .value = .required, .optfn = opt_cache_refresh,      },
    .{ .short = "",  .long = "cache-nodata-ttl",   .value = .required, .optfn = opt_cache_nodata_ttl,   },
    .{ .short = "",  .long = "cache-ignore",       .value = .required, .optfn = opt_cache_ignore,       },
    .{ .short = "",  .long = "cache-db",           .value = .required, .optfn = opt_cache_db,           },
    .{ .short = "",  .long = "verdict-cache",      .value = .required, .optfn = opt_verdict_cache,      },
    .{ .short = "",  .long = "verdict-cache-db",   .value = .required, .optfn = opt_verdict_cache_db,   },
    .{ .short = "",  .long = "hosts",              .value = .optional, .optfn = opt_hosts,              },
    .{ .short = "",  .long = "dns-rr-ip",          .value = .required, .optfn = opt_dns_rr_ip,          },
    .{ .short = "",  .long = "cert-verify",        .value = .no_value, .optfn = opt_cert_verify,        },
    .{ .short = "",  .long = "ca-certs",           .value = .required, .optfn = opt_ca_certs,           },
    .{ .short = "",  .long = "no-ipset-blacklist", .value = .no_value, .optfn = opt_no_ipset_blacklist, },
    .{ .short = "o", .long = "timeout-sec",        .value = .required, .optfn = opt_timeout_sec,        },
    .{ .short = "p", .long = "repeat-times",       .value = .required, .optfn = opt_repeat_times,       },
    .{ .short = "n", .long = "noip-as-chnip",      .value = .no_value, .optfn = opt_noip_as_chnip,      },
    .{ .short = "f", .long = "fair-mode",          .value = .no_value, .optfn = opt_fair_mode,          },
    .{ .short = "r", .long = "reuse-port",         .value = .no_value, .optfn = opt_reuse_port,         },
    .{ .short = "v", .long = "verbose",            .value = .no_value, .optfn = opt_verbose,            },
    .{ .short = "V", .long = "version",            .value = .no_value, .optfn = opt_version,            },
    .{ .short = "h", .long = "help",               .value = .no_value, .optfn = opt_help,               },
};
// zig fmt: on

noinline fn get_optdef(name: []const u8) ?OptDef {
    if (name.len == 0)
        return null;

    for (optdef_array) |optdef| {
        if (std.mem.eql(u8, optdef.short, name) or std.mem.eql(u8, optdef.long, name))
            return optdef;
    }

    return null;
}

// ================================================================

/// print(fmt, args)
pub fn printf(comptime src: std.builtin.SourceLocation, comptime fmt: [:0]const u8, args: anytype) void {
    cc.printf("%s " ++ fmt ++ "\n", .{comptime log.srcinfo(src).ptr} ++ args);
}

/// print("msg: value")
pub fn print(comptime src: std.builtin.SourceLocation, msg: [:0]const u8, value: []const u8) void {
    printf(src, "%s: '%.*s'", .{ msg.ptr, cc.to_int(value.len), value.ptr });
}

/// print(fmt, args) + print(help) + exit(1)
fn printf_exit(comptime src: std.builtin.SourceLocation, comptime fmt: [:0]const u8, args: anytype) noreturn {
    printf(src, fmt, args);
    cc.printf("%s\n", .{help});
    cc.exit(1);
}

/// print("msg: value") + print(help) + exit(1)
fn print_exit(comptime src: std.builtin.SourceLocation, msg: [:0]const u8, value: []const u8) noreturn {
    printf_exit(src, "%s: '%.*s'", .{ msg.ptr, cc.to_int(value.len), value.ptr });
}

/// print("invalid opt-value: value") + print(help) + exit(1)
fn invalid_optvalue(comptime src: std.builtin.SourceLocation, value: []const u8) noreturn {
    print_exit(src, "invalid opt-value", value);
}

// ================================================================

fn opt_config(in_value: ?[]const u8) void {
    // prevent stack overflow due to recursion
    const static = struct {
        var depth: u8 = 0;
    };

    const src = @src();
    const filename = in_value.?;

    if (static.depth + 1 > 10)
        print_exit(src, "config chain is too deep", filename);

    static.depth += 1;
    defer static.depth -= 1;

    if (filename.len > c.PATH_MAX)
        print_exit(src, "filename is too long", filename);

    const mem = cc.mmap_file(cc.to_cstr(filename)) orelse
        printf_exit(src, "failed to open file: '%.*s' (%m)", .{ cc.to_int(filename.len), filename.ptr });
    defer _ = cc.munmap(mem);

    var line_it = std.mem.split(u8, mem, "\n");
    while (line_it.next()) |line| {
        const err: cc.ConstStr = e: {
            // optname [optvalue]
            var it = std.mem.tokenize(u8, line, " \t\r");

            const optname = it.next() orelse continue;

            if (std.mem.startsWith(u8, optname, "#")) continue;

            const optvalue = it.next();

            if (it.next() != null)
                break :e "too many values";

            const optdef = get_optdef(optname) orelse
                break :e "unknown option";

            switch (optdef.value) {
                .required => {
                    if (optvalue == null)
                        break :e "missing opt-value";
                },
                .no_value => {
                    if (optvalue != null)
                        break :e "unexpected opt-value";
                },
                else => {},
            }

            if (optvalue != null and optvalue.?.len <= 0)
                break :e "invalid format";

            optdef.optfn(optvalue);

            continue;
        };

        // error handling
        printf_exit(src, "'%.*s': %s: %.*s", .{ cc.to_int(filename.len), filename.ptr, err, cc.to_int(line.len), line.ptr });
    }
}

pub noinline fn check_ip(value: []const u8) ?void {
    if (cc.ip_family(cc.to_cstr(value)) == null) {
        print(@src(), "invalid ip", value);
        return null;
    }
}

pub noinline fn check_port(value: []const u8) ?u16 {
    const port = str2int.parse(u16, value, 10) orelse 0;
    if (port == 0) {
        print(@src(), "invalid port", value);
        return null;
    }
    return port;
}

fn opt_bind_addr(in_value: ?[]const u8) void {
    const value = in_value.?;
    check_ip(value) orelse invalid_optvalue(@src(), value);
    g.bind_ips.add(value);
}

fn opt_bind_port(in_value: ?[]const u8) void {
    const value = in_value.?;
    const src = @src();

    // 53 (53@tcp+udp)
    // 53@tcp
    // 53@udp
    // 53@tcp+udp
    var it = std.mem.split(u8, value, "@");

    // port
    const port = check_port(it.first()) orelse invalid_optvalue(src, value);

    var tcp = true;
    var udp = true;

    // proto
    if (it.next()) |proto| {
        if (std.mem.eql(u8, proto, "tcp+udp") or std.mem.eql(u8, proto, "udp+tcp")) {
            //
        } else if (std.mem.eql(u8, proto, "tcp")) {
            udp = false;
        } else if (std.mem.eql(u8, proto, "udp")) {
            tcp = false;
        } else {
            invalid_optvalue(src, value);
        }
    }

    if (it.next() != null)
        invalid_optvalue(src, value);

    for (g.bind_ports) |*v| {
        if (v.port == port) {
            v.tcp = tcp;
            v.udp = udp;
            break; // found
        }
    } else { // not found
        const new_n = g.bind_ports.len + 1;
        const slice = g.allocator.realloc(g.bind_ports, new_n) catch unreachable;
        g.bind_ports = slice[0..new_n];
        g.bind_ports[new_n - 1] = .{
            .port = port,
            .tcp = tcp,
            .udp = udp,
        };
    }
}

fn opt_china_dns(in_value: ?[]const u8) void {
    const value = in_value.?;
    groups.add_upstream(.chn, value) orelse invalid_optvalue(@src(), value);
}

fn opt_trust_dns(in_value: ?[]const u8) void {
    const value = in_value.?;
    groups.add_upstream(.gfw, value) orelse invalid_optvalue(@src(), value);
}

fn opt_chnlist_file(in_value: ?[]const u8) void {
    const value = in_value.?;
    groups.add_dnl(.chn, value) orelse invalid_optvalue(@src(), value);
}

fn opt_gfwlist_file(in_value: ?[]const u8) void {
    const value = in_value.?;
    groups.add_dnl(.gfw, value) orelse invalid_optvalue(@src(), value);
}

fn opt_chnlist_first(_: ?[]const u8) void {
    g.flags.gfwlist_first = false;
}

fn opt_default_tag(in_value: ?[]const u8) void {
    const name = in_value.?;
    g.default_tag = Tag.from_name(cc.to_cstr(name)) orelse invalid_optvalue(@src(), name);
}

fn opt_add_tagchn_ip(in_value: ?[]const u8) void {
    // empty string means 'no_value'
    groups.set_ipset(.chn, in_value orelse "").?;
}

fn opt_add_taggfw_ip(in_value: ?[]const u8) void {
    groups.set_ipset(.gfw, in_value.?).?;
}

fn opt_ipset_name4(in_value: ?[]const u8) void {
    g.chnroute_name.set(in_value.?);
}

fn opt_ipset_name6(in_value: ?[]const u8) void {
    g.chnroute6_name.set(in_value.?);
}

var _tag: Tag = .none;

fn opt_group(in_value: ?[]const u8) void {
    const group_name = in_value.?;

    var overflow: bool = undefined;
    _tag = Tag.register(cc.to_cstr(group_name), &overflow) orelse {
        const reason = cc.b2s(overflow, "overflow", "invalid");
        printf_exit(@src(), "can't register group '%.*s': %s", .{ cc.to_int(group_name.len), group_name.ptr, reason });
    };
}

fn check_group_context(comptime src: std.builtin.SourceLocation, value: []const u8) void {
    if (_tag == .none)
        print_exit(src, "out of group context", value);
}

fn opt_group_dnl(in_value: ?[]const u8) void {
    const value = in_value.?;
    const src = @src();

    check_group_context(src, value);
    groups.add_dnl(_tag, value) orelse invalid_optvalue(src, value);
}

fn opt_group_upstream(in_value: ?[]const u8) void {
    const value = in_value.?;
    const src = @src();

    check_group_context(src, value);
    groups.add_upstream(_tag, value) orelse invalid_optvalue(src, value);
}

fn opt_group_ipset(in_value: ?[]const u8) void {
    const value = in_value.?;
    const src = @src();

    check_group_context(src, value);
    groups.set_ipset(_tag, value) orelse invalid_optvalue(src, value);
}

fn opt_no_ipv6(in_value: ?[]const u8) void {
    groups.add_ip6_filter(in_value) orelse invalid_optvalue(@src(), in_value orelse "");
}

fn opt_filter_qtype(in_value: ?[]const u8) void {
    const value = in_value.?;

    var it = std.mem.split(u8, value, ",");
    while (it.next()) |str_qtype| {
        const qtype = str2int.parse(u16, str_qtype, 10) orelse invalid_optvalue(@src(), value);
        _ = std.mem.indexOfScalar(u16, g.filter_qtypes, qtype) orelse {
            const new_n = g.filter_qtypes.len + 1;
            const slice = g.allocator.realloc(g.filter_qtypes, new_n) catch unreachable;
            g.filter_qtypes = slice[0..new_n];
            g.filter_qtypes[new_n - 1] = qtype;
        };
    }
}

fn opt_cache(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.cache_size = str2int.parse(@TypeOf(g.cache_size), value, 10) orelse
        invalid_optvalue(@src(), value);
}

fn opt_cache_stale(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.cache_stale = str2int.parse(@TypeOf(g.cache_stale), value, 10) orelse
        invalid_optvalue(@src(), value);
}

fn opt_cache_refresh(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.cache_refresh = str2int.parse(@TypeOf(g.cache_refresh), value, 10) orelse
        invalid_optvalue(@src(), value);
}

fn opt_cache_nodata_ttl(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.cache_nodata_ttl = str2int.parse(@TypeOf(g.cache_nodata_ttl), value, 10) orelse
        invalid_optvalue(@src(), value);
}

fn opt_cache_ignore(in_value: ?[]const u8) void {
    const domain = in_value.?;
    cache_ignore.add(domain) orelse invalid_optvalue(@src(), domain);
}

fn opt_cache_db(in_value: ?[]const u8) void {
    const path = in_value.?;
    g.cache_db = (g.allocator.dupeZ(u8, path) catch unreachable).ptr;
}

fn opt_verdict_cache(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.verdict_cache_size = str2int.parse(@TypeOf(g.verdict_cache_size), value, 10) orelse
        invalid_optvalue(@src(), value);
}

fn opt_verdict_cache_db(in_value: ?[]const u8) void {
    const path = in_value.?;
    g.verdict_cache_db = (g.allocator.dupeZ(u8, path) catch unreachable).ptr;
}

fn opt_hosts(in_value: ?[]const u8) void {
    const path = in_value orelse "/etc/hosts";
    local_rr.read_hosts(path) orelse
        print_exit(@src(), "failed to load hosts", path);
}

fn opt_dns_rr_ip(in_value: ?[]const u8) void {
    const value = in_value.?;
    const src = @src();

    const sep = std.mem.indexOfScalar(u8, value, '=') orelse invalid_optvalue(src, value);
    const name_list = value[0..sep];
    const ip_list = value[sep + 1 ..];

    var name_it = std.mem.split(u8, name_list, ",");
    while (name_it.next()) |name| {
        var ip_it = std.mem.split(u8, ip_list, ",");
        while (ip_it.next()) |ip|
            local_rr.add_ip(name, ip) orelse invalid_optvalue(src, value);
    }
}

fn opt_cert_verify(_: ?[]const u8) void {
    g.cert_verify = true;
}

fn opt_ca_certs(in_value: ?[]const u8) void {
    g.ca_certs.set(in_value.?);
}

fn opt_no_ipset_blacklist(_: ?[]const u8) void {
    c.ipset_blacklist = false;
}

fn opt_timeout_sec(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.upstream_timeout = str2int.parse(@TypeOf(g.upstream_timeout), value, 10) orelse 0;
    if (g.upstream_timeout == 0) invalid_optvalue(@src(), value);
}

fn opt_repeat_times(in_value: ?[]const u8) void {
    const value = in_value.?;
    g.trustdns_packet_n = str2int.parse(@TypeOf(g.trustdns_packet_n), value, 10) orelse 0;
    if (g.trustdns_packet_n == 0) invalid_optvalue(@src(), value);
    g.trustdns_packet_n = std.math.min(g.trustdns_packet_n, g.TRUSTDNS_PACKET_MAX);
}

fn opt_noip_as_chnip(_: ?[]const u8) void {
    g.flags.noip_as_chnip = true;
}

fn opt_fair_mode(_: ?[]const u8) void {
    // legacy option, deprecated
}

fn opt_reuse_port(_: ?[]const u8) void {
    g.flags.reuse_port = true;
}

fn opt_verbose(_: ?[]const u8) void {
    g.flags.verbose = true;
}

fn opt_version(_: ?[]const u8) void {
    cc.printf("%s\n", .{version});
    cc.exit(0);
}

fn opt_help(_: ?[]const u8) void {
    cc.printf("%s\n", .{help});
    cc.exit(0);
}

// ================================================================

const Parser = struct {
    idx: usize,

    pub fn init() Parser {
        return .{ .idx = 1 };
    }

    pub noinline fn parse(self: *Parser) void {
        const arg = self.pop_arg() orelse return;

        const err: [:0]const u8 = e: {
            if (std.mem.startsWith(u8, arg, "--")) {
                if (arg.len < 4)
                    break :e "invalid long option";

                // --name
                // --name=value
                // --name value
                if (std.mem.indexOfScalar(u8, arg, '=')) |sep|
                    self.handle(arg[2..sep], arg[sep + 1 ..])
                else
                    self.handle(arg[2..], null);
                //
            } else if (std.mem.startsWith(u8, arg, "-")) {
                if (arg.len < 2)
                    break :e "invalid short option";

                // -x
                // -x5
                // -x=5
                // -x 5
                if (arg.len == 2)
                    self.handle(arg[1..], null)
                else if (arg[2] == '=')
                    self.handle(arg[1..2], arg[3..])
                else
                    self.handle(arg[1..2], arg[2..]);
                //
            } else {
                break :e "expect an option, got the pos-argument";
            }

            return @call(.{ .modifier = .always_tail }, Parser.parse, .{self});
        };

        // error handling
        print_exit(@src(), err, arg);
    }

    noinline fn peek_arg(self: Parser) ?[:0]const u8 {
        const argv = std.os.argv;

        return if (self.idx < argv.len)
            cc.strslice_c(argv[self.idx])
        else
            null;
    }

    noinline fn pop_arg(self: *Parser) ?[:0]const u8 {
        if (self.peek_arg()) |arg| {
            self.idx += 1;
            return arg;
        }
        return null;
    }

    noinline fn take_value(self: *Parser, name: []const u8, required: bool) ?[:0]const u8 {
        const arg = self.peek_arg() orelse {
            if (required)
                print_exit(@src(), "expect a value for option", name);
            return null;
        };

        if (required or !std.mem.startsWith(u8, arg, "-")) {
            _ = self.pop_arg();
            return arg;
        }

        return null;
    }

    noinline fn handle(self: *Parser, name: []const u8, in_value: ?[:0]const u8) void {
        const src = @src();

        const optdef = get_optdef(name) orelse
            print_exit(src, "unknown option", name);

        const value = switch (optdef.value) {
            .required => if (in_value) |v| v else self.take_value(name, true),
            .optional => if (in_value) |v| v else self.take_value(name, false),
            .no_value => if (in_value == null) null else {
                printf_exit(src, "option '%.*s' not accept value: '%s'", .{ cc.to_int(name.len), name.ptr, in_value.?.ptr });
            },
        };

        if (value != null and value.?.len <= 0)
            printf_exit(src, "option '%.*s' not accept empty string", .{ cc.to_int(name.len), name.ptr });

        optdef.optfn(value);
    }
};

// ================================================================

pub fn parse() void {
    @setCold(true);

    var parser = Parser.init();
    parser.parse();

    if (g.bind_ips.is_null())
        g.bind_ips.add("127.0.0.1");

    if (g.bind_ports.len == 0)
        g.bind_ports = cc.remove_const(struct {
            const default = &[_]g.BindPort{.{ .port = 65353, .tcp = true, .udp = true }};
        }.default);

    if (groups.get_upstream_group(.chn).is_empty())
        groups.add_upstream(.chn, "114.114.114.114") orelse unreachable;

    if (groups.get_upstream_group(.gfw).is_empty())
        groups.add_upstream(.gfw, "8.8.8.8") orelse unreachable;

    if (g.chnroute_name.is_null())
        g.chnroute_name.set("chnroute");

    if (g.chnroute6_name.is_null())
        g.chnroute6_name.set("chnroute6");

    // see the `opt_add_tagchn_ip`
    const ipset_name46 = groups.get_ipset_name46(.chn);
    if (!ipset_name46.is_null() and ipset_name46.is_empty())
        ipset_name46.set_x(&.{ g.chnroute_name.slice(), ",", g.chnroute6_name.slice() });
}
