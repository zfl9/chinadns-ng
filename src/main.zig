const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");
const modules = @import("modules.zig");
const tests = @import("tests.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const net = @import("net.zig");
const ipset = @import("ipset.zig");
const server = @import("server.zig");
const EvLoop = @import("EvLoop.zig");
const co = @import("co.zig");
const groups = @import("groups.zig");
const cache = @import("cache.zig");
const verdict_cache = @import("verdict_cache.zig");
const assert = std.debug.assert;

// ============================================================================

/// the rewrite is to avoid generating unnecessary code in release mode.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        cc.abort();
}

// ============================================================================

const FnEnum = enum {
    module_init,
    module_deinit,
    check_timeout,
};

pub fn call_module_fn(comptime fn_enum: FnEnum, args: anytype) void {
    const fn_name = comptime @tagName(fn_enum);
    comptime var i = 0;
    inline while (i < modules.module_list.len) : (i += 1) {
        const module = modules.module_list[i];
        const module_name: cc.ConstStr = modules.name_list[i];
        if (@hasDecl(module, fn_name)) {
            if (false) log.debug(@src(), "%s.%s()", .{ module_name, fn_name.ptr });
            const options: std.builtin.CallOptions = .{};
            const func = @field(module, fn_name);
            @call(options, func, args);
        }
    }
}

// ============================================================================

const _debug = builtin.mode == .Debug;

const gpa_t = if (_debug) std.heap.GeneralPurposeAllocator(.{}) else void;
var _gpa: gpa_t = undefined;

// ============================================================================

var _pipe_fds: [2]c_int = undefined;

fn sig_handler(sig: c_int) callconv(.C) void {
    _ = cc.write(_pipe_fds[1], std.mem.asBytes(&sig));
}

fn sig_listener() void {
    defer co.terminate(@frame(), @frameSize(sig_listener));

    const src = @src();

    cc.pipe2(&_pipe_fds, c.O_CLOEXEC | c.O_NONBLOCK) orelse {
        log.err(src, "pipe() failed: (%d) %m", .{cc.errno()});
        return;
    };

    // read side
    const fdobj = EvLoop.Fd.new(_pipe_fds[0]);
    defer fdobj.free();

    // write side
    defer _ = cc.close(_pipe_fds[1]);

    // register signal handler
    _ = cc.signal(c.SIGINT, sig_handler); // CTRL C
    _ = cc.signal(c.SIGTERM, sig_handler); // kill <PID>
    _ = cc.signal(c.SIGUSR1, sig_handler); // dump cache to file
    if (_debug) _ = cc.signal(c.SIGUSR2, sig_handler); // detect memory leaks

    // listening for signal
    while (true) {
        var sig: c_int = undefined;

        g.evloop.read(fdobj, std.mem.asBytes(&sig)) catch |err| switch (err) {
            error.eof => return log.err(src, "read(fd:%d) failed: EOF", .{fdobj.fd}),
            error.errno => return log.err(src, "read(fd:%d) failed: (%d) %m", .{ fdobj.fd, cc.errno() }),
        };

        switch (sig) {
            c.SIGINT, c.SIGTERM => {
                cache.dump(.on_exit);
                verdict_cache.dump(.on_exit);
                cc.exit(0);
            },
            c.SIGUSR1 => {
                cache.dump(.on_manual);
                verdict_cache.dump(.on_manual);
            },
            c.SIGUSR2 => {
                if (_debug)
                    _ = _gpa.detectLeaks()
                else
                    unreachable;
            },
            else => unreachable,
        }
    }
}

// ============================================================================

pub fn main() u8 {
    g.allocator = if (_debug) b: {
        _gpa = .{};
        break :b _gpa.allocator();
    } else std.heap.c_allocator;

    defer {
        if (_debug)
            _ = _gpa.deinit();
    }

    // ============================================================================

    _ = cc.signal(c.SIGPIPE, cc.SIG_IGN());

    _ = cc.setvbuf(cc.stdout, null, c._IOLBF, 256);

    // setting default values for TZ
    _ = cc.setenv("TZ", ":/etc/localtime", false);

    // ============================================================================

    g.evloop = EvLoop.init();

    // used only for business-independent initialization, such as global variables
    call_module_fn(.module_init, .{});
    defer if (_debug) call_module_fn(.module_deinit, .{});

    // ============================================================================

    if (build_opts.is_test)
        return tests.main();

    // ============================================================================

    opt.parse();

    net.init();

    const src = @src();

    for (g.bind_ips.items()) |ip| {
        for (g.bind_ports) |p| {
            const proto: cc.ConstStr = if (p.tcp and p.udp) "" else if (p.tcp) "@tcp" else "@udp";
            log.info(src, "local listen addr: %s#%u%s", .{ ip, cc.to_uint(p.port), proto });
        }
    }

    groups.on_start();

    if (g.default_tag == .none or groups.require_ip_test()) {
        const name46 = cc.to_cstr_x(&.{ g.chnroute_name.slice(), ",", g.chnroute6_name.slice() });
        g.chnroute_testctx = ipset.new_testctx(name46);
        log.info(src, "ip test db: %s", .{name46});
    }

    log.info(src, "default domain name tag: %s", .{g.default_tag.name()});

    if (g.cache_size > 0) {
        log.info(src, "enable dns cache, capacity: %u", .{cc.to_uint(g.cache_size)});

        if (g.cache_stale > 0)
            log.info(src, "use stale cache, excess TTL: %lu", .{cc.to_ulong(g.cache_stale)});

        if (g.cache_refresh > 0)
            log.info(src, "pre-refresh cache, remain TTL: %u%%", .{cc.to_uint(g.cache_refresh)});

        if (g.cache_nodata_ttl > 0)
            log.info(src, "cache NODATA response, TTL: %u", .{cc.to_uint(g.cache_nodata_ttl)});

        cache.load();
    }

    if (g.verdict_cache_size > 0) {
        log.info(src, "enable verdict cache, capacity: %u", .{cc.to_uint(g.verdict_cache_size)});

        verdict_cache.load();
    }

    log.info(src, "response timeout of upstream: %u", .{cc.to_uint(g.upstream_timeout)});

    if (g.trustdns_packet_n > 1)
        log.info(src, "num of packets to trustdns: %u", .{cc.to_uint(g.trustdns_packet_n)});

    if (g.default_tag == .none) {
        const action = cc.b2s(g.flags.noip_as_chnip, "accept", "filter");
        log.info(src, "%s no-ip reply from chinadns", .{action});
    }

    if (g.flags.reuse_port)
        log.info(src, "SO_REUSEPORT for listening socket", .{});

    if (g.verbose())
        log.info(src, "printing the verbose runtime log", .{});

    // ============================================================================

    server.start();

    co.start(sig_listener, .{});

    g.evloop.run();

    return 0;
}
