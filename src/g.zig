//! global variables

const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");

const cc = @import("cc.zig");
const dnl = @import("dnl.zig");
const NoAAAA = @import("NoAAAA.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");

pub const VERSION: cc.ConstStr = b: {
    var target: [:0]const u8 = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.abi);

    if (builtin.target.isGnuLibC())
        target = target ++ std.fmt.comptimePrint(".{}", .{builtin.os.version_range.linux.glibc});

    if (!std.mem.eql(u8, target, build_opts.cc_target))
        @compileError("target-triple mismatch: " ++ target ++ " != " ++ build_opts.cc_target);

    const cpu_model = builtin.cpu.model.name;

    if (!std.mem.startsWith(u8, build_opts.cc_cpu, cpu_model))
        @compileError("cpu-model mismatch: " ++ cpu_model ++ " != " ++ build_opts.cc_cpu);

    var prefix: [:0]const u8 = "ChinaDNS-NG " ++ build_opts.version;

    if (build_opts.enable_openssl)
        prefix = prefix ++ " | openssl-" ++ build_opts.openssl_version;

    if (build_opts.enable_mimalloc)
        prefix = prefix ++ " | mimalloc-" ++ build_opts.mimalloc_version;

    break :b std.fmt.comptimePrint("{s} | target:{s} | cpu:{s} | mode:{s} | {s}", .{
        prefix,
        build_opts.cc_target,
        build_opts.cc_cpu,
        build_opts.cc_mode,
        "<https://github.com/zfl9/chinadns-ng>",
    });
};

/// verbose logging
pub var verbose: bool = false;

/// SO_REUSEPORT
pub var reuse_port: bool = false;

/// for tag:none (china-upstream)
pub var noip_as_chnip: bool = false;

/// how to filter AAAA query
pub var noaaaa_query: NoAAAA = .{};

/// "file1,file2,..."
pub var gfwlist_filenames: StrList = .{};

/// "file1,file2,..."
pub var chnlist_filenames: StrList = .{};

/// only effect the same domains
pub var gfwlist_first: bool = true;

/// default tag for domains that do not match any list
pub var default_tag: dnl.Tag = .none;

/// for tag:none (ip test)
pub var chnroute_name: DynStr = .{};

/// for tag:none (ip6 test)
pub var chnroute6_name: DynStr = .{};

/// for tag:chn (ip add) "set4,set6"
pub var chnip_setnames: DynStr = .{};

/// for tag:gfw (ip add) "set4,set6"
pub var gfwip_setnames: DynStr = .{};

/// ["ip1", "ip2", ...]
pub var bind_ips: StrList = .{};

pub var bind_port: u16 = 65353;

/// ["ip[#port]", "ip[#port]", ...]
pub var chinadns_addrs: StrList = .{};

/// ["ip[#port]", "ip[#port]", ...]
pub var trustdns_addrs: StrList = .{};

/// too large may cause stack overflow
pub const TRUSTDNS_PACKET_MAX: u8 = 5;

/// number of packets to send
pub var trustdns_packet_n: u8 = 1;

/// in seconds
pub var upstream_timeout: u8 = 5;
