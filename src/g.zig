//! global variables

const std = @import("std");
const cc = @import("cc.zig");
const ipset = @import("ipset.zig");
const NoAAAA = @import("NoAAAA.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const EvLoop = @import("EvLoop.zig");
const flags_op = @import("flags_op.zig");
const Tag = @import("tag.zig").Tag;

pub const Flags = enum(u8) {
    verbose = 1 << 0,
    reuse_port = 1 << 1,
    noip_as_chnip = 1 << 2,
    gfwlist_first = 1 << 3,
    _,
    pub usingnamespace flags_op.get(Flags);
};

pub var flags: Flags = Flags.init(.{.gfwlist_first});

pub inline fn verbose() bool {
    return flags.has(.verbose);
}

pub var noaaaa_rule: NoAAAA = .{};
pub var filter_qtypes: []u16 = &.{};

/// default tag for domains that do not match any list
pub var default_tag: Tag = .none;

/// for ip test (tag:none or no-AAAA)
pub var chnroute_name: DynStr = .{};
pub var chnroute6_name: DynStr = .{};
pub var chnroute_testctx: *const ipset.testctx_t = undefined;

/// ["ip1", "ip2", ...]
pub var bind_ips: StrList = .{};

pub const BindPort = struct {
    port: u16,
    tcp: bool,
    udp: bool,
};
pub var bind_ports: []BindPort = &.{};

/// too large may cause stack overflow
pub const TRUSTDNS_PACKET_MAX: u8 = 5;

/// number of packets to send (udp)
pub var trustdns_packet_n: u8 = 1;

/// in seconds
pub var upstream_timeout: u8 = 5;

/// dns cache (0 means disable)
pub var cache_size: u16 = 0;

/// allow stale cache
/// - `0`: disable
/// - `N`: N is the max expired_sec
pub var cache_stale: u32 = 0;

/// refresh current cache if TTL <= N(%)
pub var cache_refresh: u8 = 0;

/// rcode=NOERROR && no-records
pub var cache_nodata_ttl: u16 = 60;

/// [tag:none] verdict cache size
pub var verdict_cache_size: u16 = 0;

/// load/save verdict cache from/to this file
pub var verdict_cache_db: ?cc.ConstStr = null;

pub var evloop: EvLoop = undefined;

/// global memory allocator
pub var allocator: std.mem.Allocator = undefined;

pub var cert_verify: bool = false;

/// the location of CA certs
pub var ca_certs: DynStr = .{};

/// received SIGUSR1 ?
pub const sigusr1: *volatile c_int = &sigusr1_v;
var sigusr1_v: c_int = 0;

/// received SIGTERM ?
pub const sigexit: *volatile c_int = &sigexit_v;
var sigexit_v: c_int = 0;
