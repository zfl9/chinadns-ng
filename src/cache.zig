const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const Bytes = cc.Bytes;

const ReplyData = struct {
    last_access: c.time_t, // last access time
    question_len: u16,
    data_len: u16,
    // data: [data_len]u8, // {question, answer, authority, additional}

    const alignment = @alignOf(ReplyData);
    const header_len = @sizeOf(ReplyData);

    fn header(bytes: []align(alignment) u8) *ReplyData {
        return std.mem.bytesAsValue(ReplyData, bytes[0..header_len]);
    }

    /// the data will be copied
    pub fn new(in_data: []const u8, qnamelen: c_int) *ReplyData {
        const bytes = g.allocator.alignedAlloc(u8, alignment, header_len + in_data.len) catch unreachable;
        const self = header(bytes);
        self.* = .{
            .last_access = cc.time(),
            .question_len = dns.to_question_len(qnamelen),
            .data_len = cc.to_u16(in_data.len),
        };
        @memcpy(self.data(), in_data.ptr, in_data.len);
        return self;
    }

    pub fn free(self: *ReplyData) void {
        g.allocator.free(self.mem());
    }

    fn mem(self: anytype) Bytes(@TypeOf(self), .slice) {
        const P = Bytes(@TypeOf(self), .ptr);
        return @ptrCast(P, self)[0 .. header_len + self.data_len];
    }

    pub fn data(self: anytype) Bytes(@TypeOf(self), .slice) {
        return self.mem()[header_len..];
    }

    pub fn question(self: anytype) Bytes(@TypeOf(self), .slice) {
        return self.data()[0..self.question_len];
    }

    /// answer + authority + additional
    pub fn records(self: anytype) Bytes(@TypeOf(self), .slice) {
        return self.data()[self.question_len..];
    }

    /// return `is_expired`, or `null` if failed
    pub fn update_ttl(self: *ReplyData) ?bool {
        const elapsed_sec = std.math.sub(c.time_t, cc.time(), self.last_access) catch 0;
        return dns.update_ttl(self.records(), @truncate(u32, elapsed_sec));
    }
};

/// question => ReplyData
var _cache: std.StringHashMapUnmanaged(*ReplyData) = .{};

/// the `rmsg` should be checked by the `dns.check_reply()` first
pub fn add(rmsg: []const u8, qnamelen: c_int) void {
    _ = qnamelen;
    _ = rmsg;
    // TODO
}
