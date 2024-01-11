const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");

const tests = @import("tests.zig");

const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const dnl = @import("dnl.zig");
const ipset = @import("ipset.zig");
const fmtchk = @import("fmtchk.zig");
const str2int = @import("str2int.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");

// TODO:
// - alloc_only allocator
// - vla/alloca allocator (another stack)

/// used in tests.zig for discover all test fns
pub const project_modules = .{
    c, cc, g, log, opt, dnl, ipset, fmtchk, str2int, DynStr, StrList,
};

/// the rewrite is to avoid generating unnecessary code in release mode.
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        c.abort();
}

pub fn main() u8 {
    c.ignore_sigpipe();

    _ = cc.setvbuf(cc.stdout, null, c._IOLBF, 256);

    // setting default values for TZ
    _ = cc.setenv("TZ", ":/etc/localtime", false);

    if (build_opts.is_test)
        return tests.main();

    opt.parse();

    c.net_init();

    for (g.bind_ips.items) |ip|
        log.info(@src(), "local listen addr: %s#%u", .{ ip.?, cc.to_uint(g.bind_port) });

    for (g.chinadns_addrs.items) |addr, i|
        log.info(@src(), "chinadns server#%zu: %s", .{ i + 1, addr.? });

    for (g.trustdns_addrs.items) |addr, i|
        log.info(@src(), "trustdns server#%zu: %s", .{ i + 1, addr.? });

    dnl.init();

    log.info(@src(), "default domain name tag: %s", .{g.default_tag.desc()});

    ipset.init();

    return 0;
}
