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

/// create and start coroutine
inline fn coro_create(comptime func: anytype, args: anytype) void {
    const buf = cc.align_malloc_many(u8, @frameSize(func), std.Target.stack_align).?;
    _ = @asyncCall(buf, {}, func, args);
    // @call(.{ .modifier = .async_kw, .stack = buf }, func, args);
}

/// free memory of coroutine
/// https://github.com/ziglang/zig/issues/10622
inline fn coro_destroy(top_frame: anyframe) void {
    const ptr = @intToPtr(*anyopaque, @ptrToInt(top_frame));
    return @call(.{ .modifier = .always_tail }, cc.free, .{ptr});
}

// =======================================================================================================

var _epoll: Epoll = undefined;

fn do_tcp_listen(server_sock: c_int) void {
    defer coro_destroy(@frame());

    _epoll.do_accept(server_sock, struct {
        fn callback(sock: c_int) void {
            coro_create(do_tcp_service, .{sock});
        }
    }.callback);
}

fn do_tcp_service(sock: c_int) void {
    defer coro_destroy(@frame());

    defer _ = c.close(sock);

    // TODO: tcp nodelay

    var addr: net.SockAddr = undefined;
    var addrlen: c.socklen_t = @sizeOf(net.SockAddr);
    _ = c.getpeername(sock, &addr.sa, &addrlen);

    var ip: [c.INET6_ADDRSTRLEN - 1:0]u8 = undefined;
    var port: u16 = undefined;
    addr.to_text(&ip, &port);

    log.info(@src(), "new connection from %s#%u", .{ &ip, cc.to_uint(port) });

    // TODO
}

fn do_udp_service(server_sock: c_int) void {
    defer coro_destroy(@frame());

    _ = server_sock;
    // TODO

}

/// called by Epoll.check_timeout
pub fn check_timeout() c_int {
    // TODO
    return -1;
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
        coro_create(do_tcp_listen, .{fds[0]});
        coro_create(do_udp_service, .{fds[1]});
    }

    _epoll.loop();

    return 0;
}
