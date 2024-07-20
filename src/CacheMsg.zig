const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const Rc = @import("Rc.zig");
const ListNode = @import("ListNode.zig");
const Bytes = cc.Bytes;

// =======================================================

const CacheMsg = @This();

next: ?*CacheMsg = null, // for hashmap
list_node: ListNode = undefined,
update_time: c.time_t,
hashv: c_uint,
ttl: i32,
ttl_r: i32, // refresh if ttl <= ttl_r
rc: Rc = .{},
msg_len: u16,
qnamelen: u8,
// msg: [msg_len]u8, // {header, question, answer, authority, additional}

// =======================================================

const metadata_len = @sizeOf(CacheMsg);
const alignment = @alignOf(CacheMsg);

fn init(self: *CacheMsg, in_msg: []const u8, qnamelen: c_int, ttl: i32, hashv: c_uint) *CacheMsg {
    self.* = .{
        .hashv = hashv,
        .update_time = cc.time(),
        .ttl = ttl,
        .ttl_r = @divTrunc(ttl * g.cache_refresh, 100),
        .msg_len = cc.to_u16(in_msg.len),
        .qnamelen = cc.to_u8(qnamelen),
    };
    @memcpy(self.msg().ptr, in_msg.ptr, in_msg.len);
    return self;
}

/// the `in_msg` will be copied
pub fn new(in_msg: []const u8, qnamelen: c_int, ttl: i32, hashv: c_uint) *CacheMsg {
    const bytes = g.allocator.alignedAlloc(u8, alignment, metadata_len + in_msg.len) catch unreachable;
    const self: *CacheMsg = std.mem.bytesAsValue(CacheMsg, bytes[0..metadata_len]);
    return self.init(in_msg, qnamelen, ttl, hashv);
}

/// the `in_msg` will be copied \
/// if reuse fail, `self` will be freed
pub fn reuse(self: *CacheMsg, in_msg: []const u8, qnamelen: c_int, ttl: i32, hashv: c_uint) *CacheMsg {
    if (self.rc.ref_count == 1 and g.allocator.resize(self.mem(), metadata_len + in_msg.len) != null) {
        return self.init(in_msg, qnamelen, ttl, hashv);
    } else {
        self.free(); // free the old cache
        return new(in_msg, qnamelen, ttl, hashv);
    }
}

pub fn ref(self: *CacheMsg) void {
    return self.rc.ref();
}

pub fn unref(self: *CacheMsg) void {
    return self.free();
}

pub fn free(self: *CacheMsg) void {
    if (self.rc.unref() == 0)
        g.allocator.free(self.mem());
}

pub fn from_list_node(node: *ListNode) *CacheMsg {
    return @fieldParentPtr(CacheMsg, "list_node", node);
}

pub fn from_msg(in_msg: []const u8) *CacheMsg {
    const metadata_addr = @ptrToInt(in_msg.ptr) - metadata_len;
    return @intToPtr(*CacheMsg, metadata_addr);
}

fn mem(self: anytype) Bytes(@TypeOf(self), .slice) {
    const P = Bytes(@TypeOf(self), .ptr);
    return @ptrCast(P, self)[0 .. metadata_len + self.msg_len];
}

pub fn msg(self: anytype) Bytes(@TypeOf(self), .slice) {
    return self.mem()[metadata_len..];
}

pub fn question(self: *const CacheMsg) []const u8 {
    return dns.question(self.msg(), self.qnamelen);
}

fn calc_ttl_change(self: *const CacheMsg, now: c.time_t) i32 {
    const update_time = self.update_time;
    const elapsed_sec = if (now > update_time) now - update_time else 0;
    return -cc.to_i32(elapsed_sec);
}

/// return `ttl` (<= 0 means expired)
pub fn update_ttl(self: *CacheMsg) i32 {
    if (self.rc.ref_count > 1)
        return self.get_ttl();

    const now = cc.time();
    const ttl_change = self.calc_ttl_change(now);

    if (ttl_change != 0) {
        self.update_time = now;
        self.ttl += ttl_change;
        dns.update_ttl(self.msg(), self.qnamelen, ttl_change);
    }

    return self.ttl;
}

/// return `ttl` (<= 0 means expired)
pub fn get_ttl(self: *const CacheMsg) i32 {
    return self.ttl + self.calc_ttl_change(cc.time());
}
