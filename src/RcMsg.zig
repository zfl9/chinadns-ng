const std = @import("std");
const g = @import("g.zig");
const cc = @import("cc.zig");
const Rc = @import("Rc.zig");
const assert = std.debug.assert;
const Bytes = cc.Bytes;

// ==================================================

/// msg with ref_count
const RcMsg = @This();

rc: Rc = .{},
cap: u16, // capacity of the msg data
len: u16, // msg len (0 means empty)
// msg data (variable part)

// ==================================================

const alignment = @alignOf(RcMsg);
const header_len = @sizeOf(RcMsg);

fn header(bytes: []align(alignment) u8) *RcMsg {
    return std.mem.bytesAsValue(RcMsg, bytes[0..header_len]);
}

pub fn new(cap: u16) *RcMsg {
    const bytes = g.allocator.alignedAlloc(u8, alignment, header_len + cap) catch unreachable;
    const self = header(bytes);
    self.* = .{
        .cap = cap,
        .len = 0,
    };
    return self;
}

pub fn realloc(self: *RcMsg, new_cap: u16) *RcMsg {
    assert(self.is_unique());
    if (new_cap > self.cap) {
        const bytes = g.allocator.reallocAdvanced(
            self.mem(),
            alignment,
            header_len + new_cap,
            .exact,
        ) catch unreachable;
        const new_self = header(bytes);
        new_self.cap = new_cap;
        return new_self;
    }
    return self;
}

pub fn ref(self: *RcMsg) *RcMsg {
    self.rc.ref();
    return self;
}

pub fn unref(self: *RcMsg) void {
    return self.free();
}

pub fn free(self: *RcMsg) void {
    if (self.rc.unref() == 0)
        g.allocator.free(self.mem());
}

/// ref count is 1
pub fn is_unique(self: *const RcMsg) bool {
    return self.rc.ref_count == 1;
}

fn mem(self: anytype) Bytes(@TypeOf(self), .slice) {
    const P = Bytes(@TypeOf(self), .ptr);
    return @ptrCast(P, self)[0 .. header_len + self.cap];
}

pub fn buf(self: anytype) Bytes(@TypeOf(self), .slice) {
    return self.mem()[header_len..];
}

pub fn msg(self: anytype) Bytes(@TypeOf(self), .slice) {
    return self.buf()[0..self.len];
}

// =============================================================

pub fn @"test: return type"() !void {
    const var_rcmsg: *RcMsg = RcMsg.new(512);
    const const_rcmsg: *const RcMsg = var_rcmsg;
    defer var_rcmsg.free();

    const var_msg = var_rcmsg.msg();
    const const_msg = const_rcmsg.msg();

    try std.testing.expectEqual([]u8, @TypeOf(var_msg));
    try std.testing.expectEqual([]const u8, @TypeOf(const_msg));
}

pub fn @"test: realloc"() !void {
    const rcmsg = RcMsg.new(512);
    const no_change = rcmsg.realloc(512);
    try std.testing.expectEqual(rcmsg, no_change);

    const expanded = rcmsg.realloc(5120); // rcmsg is freed
    defer expanded.free();
    try std.testing.expectEqual(@as(u16, 5120), expanded.cap);
}
