const std = @import("std");
const cc = @import("cc.zig");
const g = @import("g.zig");
const assert = std.debug.assert;

/// create and start a new coroutine
pub fn create(comptime func: anytype, args: anytype) void {
    const buf = g.allocator.alignedAlloc(u8, std.Target.stack_align, @frameSize(func)) catch unreachable;
    _ = @asyncCall(buf, {}, func, args);
    // @call(.{ .modifier = .async_kw, .stack = buf }, func, args);
    check_terminated();
}

/// if the coroutine is at the last pause point, its memory will be freed after resume
pub fn do_resume(frame: anyframe) void {
    resume frame;
    check_terminated();
}

/// called when the coroutine is about to terminate: `defer co.terminate(@frame(), frame_size)`
pub fn terminate(top_frame: anyframe, frame_size: usize) void {
    assert(_terminated == null);
    _terminated = top_frame;
    _frame_size = frame_size;
}

var _terminated: ?anyframe = null;
var _frame_size: usize = 0;

/// free the memory of a terminated coroutine
fn check_terminated() void {
    const top_frame = _terminated orelse return;
    _terminated = null;

    // https://github.com/ziglang/zig/issues/10622
    const ptr = @intToPtr([*]u8, @ptrToInt(top_frame));
    return g.allocator.free(ptr[0.._frame_size]);
}
