const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const heap = std.heap;

const tests = @import("tests.zig");

const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const dnl = @import("dnl.zig");
const ipset = @import("ipset.zig");
const fmtchk = @import("fmtchk.zig");
const str2int = @import("str2int.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");
const Upstream = @import("Upstream.zig");
const Epoll = @import("Epoll.zig");

// TODO:
// - alloc_only allocator
// - vla/alloca allocator (another stack)

/// used in tests.zig for discover all test fns
pub const project_modules = .{
    c, cc, g, log, opt, net, dnl, ipset, fmtchk, str2int, DynStr, StrList, Upstream, Epoll,
};

/// the rewrite is to avoid generating unnecessary code in release mode.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        c.abort();
}

// =======================================================================================================

var _epoll: Epoll = undefined;

/// called by Epoll.check_timeout
pub fn check_timeout() c_int {
    // TODO
    return -1;
}

pub fn on_tcp_accept(ctx: *Epoll.Event.Ctx, fd: c_int, events: u32) void {
    _ = events;
    _ = fd;
    _ = ctx;
    // TODO
}

pub fn on_udp_request(ctx: *Epoll.Event.Ctx, fd: c_int, events: u32) void {
    _ = events;
    _ = fd;
    _ = ctx;
    // TODO
}

pub fn main() u8 {
    net.ignore_sigpipe();

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

    for (g.chinadns_list.items()) |v, i|
        log.info(@src(), "chinadns server#%zu: %s", .{ i + 1, v.url.ptr });

    for (g.trustdns_list.items()) |v, i|
        log.info(@src(), "trustdns server#%zu: %s", .{ i + 1, v.url.ptr });

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

    _epoll = Epoll.create();

    // create listening sockets
    for (g.bind_ips.items) |ip| {
        const fds = net.new_dns_server(ip.?, g.bind_port);
        const ctxs = cc.malloc_many(Epoll.Event.Ctx, 2).?;
        ctxs[0] = .{ .callback = on_tcp_accept, .fd = fds[0] };
        ctxs[1] = .{ .callback = on_udp_request, .fd = fds[1] };
        const err: [:0]const u8 = b: {
            if (!_epoll.add(fds[0], c.EPOLLIN, &ctxs[0]))
                break :b "tcp";
            if (!_epoll.add(fds[1], c.EPOLLIN, &ctxs[1]))
                break :b "udp";
            break :b "";
        };
        if (err.len > 0) {
            log.err(@src(), "failed to register %s server listen event", .{err.ptr});
            c.exit(1);
        }
    }

    _epoll.loop();

    return 0;
}
