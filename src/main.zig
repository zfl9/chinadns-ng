const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("build_opts");

const tests = @import("tests.zig");
const c = @import("c.zig");
const C = @import("C.zig");
const g = @import("g.zig");
const log = @import("log.zig");
const opt = @import("opt.zig");
const dnl = @import("dnl.zig");
const fmtchk = @import("fmtchk.zig");
const str2int = @import("str2int.zig");
const DynStr = @import("DynStr.zig");
const StrList = @import("StrList.zig");

// TODO:
// - alloc_only allocator
// - vla/alloca allocator (another stack)

// for tests.zig to discover all test fns
pub const project_modules = .{
    c, C, g, log, opt, dnl, fmtchk, str2int, DynStr, StrList,
};

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe)
        std.builtin.default_panic(msg, error_return_trace, ret_addr)
    else
        c.abort();
}

extern fn c_main(argc: c_int, argv: [*:null]?C.Str) c_int;

pub fn main() u8 {
    if (build_opts.is_test)
        return C.to_u8(tests.main());

    // test opt.zig
    opt.parse();

    // add sentinel `null`
    const raw_argv = std.os.argv;
    const argv = std.heap.raw_c_allocator.allocSentinel(?C.Str, raw_argv.len, null) catch unreachable;
    std.mem.copy(?C.Str, argv, raw_argv);

    // assert
    const x = argv[0.. :null];
    const y = argv[0..argv.len :null];
    _ = x;
    _ = y;

    return C.to_u8(c_main(C.to_int(argv.len), argv.ptr));
}
