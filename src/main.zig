const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const heap = std.heap;
const assert = std.debug.assert;

const tests = @import("tests.zig");

const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const dnl = @import("dnl.zig");
const dns = @import("dns.zig");
const ipset = @import("ipset.zig");
const fmtchk = @import("fmtchk.zig");
const str2int = @import("str2int.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const server = @import("server.zig");
const Upstream = @import("Upstream.zig");
const EvLoop = @import("EvLoop.zig");
const co = @import("co.zig");
const Rc = @import("Rc.zig");
const RcMsg = @import("RcMsg.zig");

// TODO:
// - alloc_only allocator
// - vla/alloca allocator (another stack)

/// used in tests.zig for discover all test fns
pub const project_modules = .{
    c,       cc,     g,        log,    opt,     net,
    dnl,     dns,    ipset,    fmtchk, str2int, DynStr,
    StrList, server, Upstream, EvLoop, Rc,      RcMsg,
};

/// the rewrite is to avoid generating unnecessary code in release mode.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        c.abort();
}

/// called by EvLoop.check_timeout
pub const check_timeout = server.check_timeout;

pub fn main() u8 {
    const is_debug = builtin.mode == .Debug;

    const gpa_t = if (is_debug) std.heap.GeneralPurposeAllocator(.{}) else void;
    var gpa: gpa_t = undefined;

    g.allocator = if (is_debug) b: {
        gpa = gpa_t{};
        break :b gpa.allocator();
    } else std.heap.c_allocator;

    // ============================================================================

    _ = c.signal(c.SIGPIPE, c.SIG_IGNORE());

    _ = cc.setvbuf(cc.stdout, null, c._IOLBF, 256);

    // setting default values for TZ
    _ = cc.setenv("TZ", ":/etc/localtime", false);

    if (build_opts.is_test)
        return tests.main();

    // ============================================================================

    opt.parse();

    net.init();

    for (g.bind_ips.items) |ip|
        log.info(@src(), "local listen addr: %s#%u", .{ ip.?, cc.to_uint(g.bind_port) });

    for (g.china_group.items()) |*v| {
        if (v.proto == .udp_in) continue; // avoid duplicate printing
        log.info(@src(), "china upstream: %s", .{v.url.ptr});
    }

    for (g.trust_group.items()) |*v| {
        if (v.proto == .udp_in) continue; // avoid duplicate printing
        log.info(@src(), "trust upstream: %s", .{v.url.ptr});
    }

    dnl.init();

    log.info(@src(), "default domain name tag: %s", .{g.default_tag.desc()});

    ipset.init();

    g.noaaaa_query.display();

    log.info(@src(), "response timeout of upstream: %u", .{cc.to_uint(g.upstream_timeout)});

    if (g.trustdns_packet_n > 1)
        log.info(@src(), "num of packets to trustdns: %u", .{cc.to_uint(g.trustdns_packet_n)});

    log.info(@src(), "%s no-ip reply from chinadns", .{cc.b2s(g.noip_as_chnip, "accept", "filter")});

    if (g.reuse_port)
        log.info(@src(), "SO_REUSEPORT for listening socket", .{});

    if (g.verbose)
        log.info(@src(), "printing the verbose runtime log", .{});

    // ============================================================================

    g.evloop = EvLoop.init();

    server.start();

    g.evloop.run();

    return 0;
}
