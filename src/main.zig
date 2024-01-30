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
const EvLoop = @import("EvLoop.zig");
const coro = @import("coro.zig");

// TODO:
// - alloc_only allocator
// - vla/alloca allocator (another stack)

/// used in tests.zig for discover all test fns
pub const project_modules = .{
    c, cc, g, log, opt, net, dnl, ipset, fmtchk, str2int, DynStr, StrList, Upstream, EvLoop,
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

var _evloop: EvLoop = undefined;

fn listen_tcp(fd: c_int, ip: cc.ConstStr) void {
    defer coro.on_terminate(@frame());

    const fd_obj = EvLoop.FdObj.new(fd);
    defer fd_obj.free(&_evloop);

    while (true) {
        const conn_fd = _evloop.accept(fd_obj, null, null) orelse {
            log.err(@src(), "failed to accept on %s#%u: (%d) %m", .{ ip, cc.to_uint(g.bind_port), cc.errno() });
            // TODO: if it is a recoverable error then continue
            return;
        };
        coro.create(service_tcp, .{conn_fd});
    }
}

fn service_tcp(fd: c_int) void {
    defer coro.on_terminate(@frame());

    const fd_obj = EvLoop.FdObj.new(fd);
    defer fd_obj.free(&_evloop);

    // var query_ids = std.AutoHashMapUnmanaged(u16, void).init();
    // _ = query_ids;

    var addr: net.Addr = undefined;
    var addrlen: c.socklen_t = @sizeOf(net.Addr);
    _ = c.getpeername(fd, &addr.sa, &addrlen);

    var ip: net.IpStrBuf = undefined;
    var port: u16 = undefined;
    addr.to_text(&ip, &port);

    log.info(@src(), "new connection:%d from %s#%u", .{ fd, &ip, cc.to_uint(port) });

    while (true) {
        // read the msg length (be16)
        var len: u16 = undefined;
        _evloop.recv_exactly(fd_obj, std.mem.asBytes(&len), 0) orelse {
            const err = cc.errno();
            if (err == 0)
                log.info(@src(), "connection:%d closed", .{fd})
            else
                log.err(@src(), "recv(%d, %s#%u, @len) failed: (%d) %m", .{ fd, &ip, cc.to_uint(port), cc.errno() });
            return;
        };
        len = std.mem.bigToNative(u16, len);

        // if (len < c.DNS_PACKET_MINSIZE)
        if (len < 17) {
            log.err(@src(), "query msg is too small: %u < %d", .{ cc.to_uint(len), cc.to_int(17) });
            return;
        }
        if (len > c.DNS_PACKET_MAXSIZE) {
            log.err(@src(), "query msg is too large: %u > %d", .{ cc.to_uint(len), c.DNS_PACKET_MAXSIZE });
            return;
        }

        // read the msg body
        var buf: [c.DNS_PACKET_MAXSIZE]u8 = undefined;
        _evloop.recv_exactly(fd_obj, buf[0..len], 0) orelse {
            const err = cc.errno();
            if (err == 0)
                log.info(@src(), "connection:%d closed", .{fd})
            else
                log.err(@src(), "recv(%d, %s#%u, @len) failed: (%d) %m", .{ fd, &ip, cc.to_uint(port), cc.errno() });
            return;
        };

        const id = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, buf[0..2]).*);
        log.info(@src(), "recv query(id=%u, sz=%u) from %s#%u", .{ cc.to_uint(id), cc.to_uint(len), &ip, cc.to_uint(port) });

        // TODO: forward to upstreams
    }
}

fn listen_udp(fd: c_int, bind_ip: cc.ConstStr) void {
    defer coro.on_terminate(@frame());

    const fd_obj = EvLoop.FdObj.new(fd);
    defer fd_obj.free(&_evloop);

    while (true) {
        var buf: [c.DNS_PACKET_MAXSIZE]u8 = undefined;

        var addr: net.Addr = undefined;
        var addrlen: c.socklen_t = @sizeOf(net.Addr);

        const len = _evloop.recvfrom(fd_obj, &buf, 0, &addr.sa, &addrlen) orelse {
            log.err(@src(), "recvfrom(%d) on %s#%u failed: (%d) %m", .{ fd, bind_ip, cc.to_uint(g.bind_port), cc.errno() });
            return;
        };

        const msg = buf[0..len];
        // std.debug.assert(len >= c.DNS_PACKET_MINSIZE);
        std.debug.assert(len >= 17);

        var ip: net.IpStrBuf = undefined;
        var port: u16 = undefined;
        addr.to_text(&ip, &port);

        const id = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, msg[0..2]).*);
        log.info(@src(), "recv query(id=%u, sz=%zu) from %s#%u", .{ cc.to_uint(id), len, &ip, cc.to_uint(port) });

        // TODO: forward to upstreams
    }
}

/// called by EvLoop.check_timeout
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

    _evloop = EvLoop.init();

    // create listening sockets
    for (g.bind_ips.items) |ip| {
        const fds = net.new_dns_server(ip.?, g.bind_port);
        coro.create(listen_tcp, .{ fds[0], ip.? });
        coro.create(listen_udp, .{ fds[1], ip.? });
    }

    _evloop.run();

    return 0;
}
