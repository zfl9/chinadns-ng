const std = @import("std");
const cc = @import("cc.zig");
const assert = std.debug.assert;

/// create and start a new coroutine
pub fn create(comptime func: anytype, args: anytype) void {
    const buf = cc.align_malloc_many(u8, @frameSize(func), std.Target.stack_align).?;
    _ = @asyncCall(buf, {}, func, args);
    // @call(.{ .modifier = .async_kw, .stack = buf }, func, args);
    check_terminated();
}

/// if the coroutine is at the last pause point, its memory will be freed after resume
pub fn do_resume(frame: anyframe) void {
    resume frame;
    check_terminated();
}

/// called when the coroutine is about to terminate: `defer co.terminate(@frame())`
pub fn terminate(top_frame: anyframe) void {
    assert(_terminated == null);
    _terminated = top_frame;
}

var _terminated: ?anyframe = null;

/// free the memory of a terminated coroutine
fn check_terminated() void {
    const top_frame = _terminated orelse return;
    _terminated = null;

    // https://github.com/ziglang/zig/issues/10622
    const ptr = @intToPtr(*anyopaque, @ptrToInt(top_frame));
    return cc.free(ptr);
}
