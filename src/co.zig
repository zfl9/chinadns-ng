const std = @import("std");
const cc = @import("cc.zig");
const g = @import("g.zig");
const assert = std.debug.assert;

/// create and start a new coroutine
pub fn start(comptime func: anytype, args: anytype) void {
    const buf = g.allocator.alignedAlloc(u8, std.Target.stack_align, @frameSize(func)) catch unreachable;
    _ = @asyncCall(buf, {}, func, args);
    check_terminated();
}

/// if the coroutine is at the last suspend point, its memory will be freed after resume
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

// ========================================================================

const SIZE = 64;
const ALIGN = @alignOf(std.c.max_align_t);
var _data: [SIZE]u8 align(ALIGN) = undefined;

/// pass data to the target coroutine on resume
pub fn data(comptime T: type) *T {
    comptime assert(@sizeOf(T) <= SIZE);
    comptime assert(@alignOf(T) <= ALIGN);
    return std.mem.bytesAsValue(T, _data[0..@sizeOf(T)]);
}

// ========================================================================

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
