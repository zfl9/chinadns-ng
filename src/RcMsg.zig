const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const Rc = @import("Rc.zig");

const assert = std.debug.assert;
const isConstPtr = std.meta.trait.isConstPtr;

/// msg with ref_count
const RcMsg = @This();

rc: Rc = .{},
cap: u16, // capacity of the msg data
len: u16, // msg len (0 means empty)
// msg data (variable part)

const header_len = @sizeOf(RcMsg);

fn as_rcmsg(bytes: []u8) *RcMsg {
    const aligned = @alignCast(@alignOf(RcMsg), bytes);
    return std.mem.bytesAsValue(RcMsg, aligned[0..header_len]);
}

pub fn new(cap: u16) *RcMsg {
    const bytes = cc.malloc_many(u8, header_len + cap).?;
    const self = as_rcmsg(bytes);
    self.* = .{
        .cap = cap,
        .len = 0,
    };
    return self;
}

pub fn realloc(self: *RcMsg, new_cap: u16) *RcMsg {
    assert(self.is_unique());
    if (new_cap > self.cap) {
        const bytes = cc.realloc(u8, self.mem(), header_len + new_cap).?;
        const new_self = as_rcmsg(bytes);
        new_self.cap = new_cap;
        return new_self;
    }
    return self;
}

pub fn ref(self: *RcMsg) *RcMsg {
    self.rc.ref();
    return self;
}

pub const unref = free;

pub fn free(self: *RcMsg) void {
    if (self.rc.unref() == 0)
        cc.free(self);
}

/// ref count is 1
pub fn is_unique(self: *const RcMsg) bool {
    return self.rc.ref_count == 1;
}

fn RetType(comptime T: type, comptime ptr: bool) type {
    if (isConstPtr(T))
        return if (ptr) [*]const u8 else []const u8
    else
        return if (ptr) [*]u8 else []u8;
}

fn mem(self: anytype) RetType(@TypeOf(self), false) {
    const T = RetType(@TypeOf(self), true);
    return @ptrCast(T, self)[0 .. header_len + self.cap];
}

pub fn buf(self: anytype) RetType(@TypeOf(self), false) {
    return self.mem()[header_len..];
}

pub fn msg(self: anytype) RetType(@TypeOf(self), false) {
    return self.mem()[header_len .. header_len + self.len];
}

// =============================================================

pub fn @"test: RcMsg api"() !void {
    const var_rcmsg: *RcMsg = RcMsg.new(512);
    const const_rcmsg: *const RcMsg = var_rcmsg;
    const msg1 = var_rcmsg.msg();
    const msg2 = const_rcmsg.msg();
    try std.testing.expectEqual([]u8, @TypeOf(msg1));
    try std.testing.expectEqual([]const u8, @TypeOf(msg2));

    const msg3 = var_rcmsg.realloc(512);
    try std.testing.expectEqual(var_rcmsg, msg3);

    const msg4 = var_rcmsg.realloc(5120);
    try std.testing.expectEqual(@as(u16, 5120), msg4.cap);
}
