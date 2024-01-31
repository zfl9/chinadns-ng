const std = @import("std");
const log = @import("log.zig");

pub const Flags = u8;

// struct fields
flags: Flags = 0,

pub const ALL: Flags = std.math.maxInt(Flags);
pub const TAG_GFW: Flags = 1 << 0;
pub const TAG_CHN: Flags = 1 << 1;
pub const TAG_NONE: Flags = 1 << 2;
pub const CHINA_DNS: Flags = 1 << 3;
pub const TRUST_DNS: Flags = 1 << 4;
pub const CHINA_IPCHK: Flags = 1 << 5;
pub const TRUST_IPCHK: Flags = 1 << 6;

const Self = @This();

pub inline fn has(self: Self, flags: Flags) bool {
    return self.flags & flags == flags;
}

pub inline fn has_any(self: Self, flags: Flags) bool {
    return self.flags & flags != 0;
}

pub fn add(self: *Self, flags: Flags) void {
    self.flags |= flags;

    // try simplify to flags ALL
    if (self.flags != ALL) {
        const all_tag = TAG_GFW | TAG_CHN | TAG_NONE;
        const all_dns = CHINA_DNS | TRUST_DNS;

        if (self.has(all_tag) or self.has(all_dns))
            self.flags = ALL;
    }
}

pub fn display(self: Self) void {
    if (self.flags == 0) return;

    // zig fmt: off
    const list = .{
        .{ .flags = ALL,         .msg = "filter AAAA for all domain", .brk = {} },
        .{ .flags = TAG_CHN,     .msg = "filter AAAA for tag_chn domain" },
        .{ .flags = TAG_GFW,     .msg = "filter AAAA for tag_gfw domain" },
        .{ .flags = TAG_NONE,    .msg = "filter AAAA for tag_none domain" },
        .{ .flags = CHINA_DNS,   .msg = "filter AAAA for china upstream" },
        .{ .flags = TRUST_DNS,   .msg = "filter AAAA for trust upstream" },
        .{ .flags = CHINA_IPCHK, .msg = "check AAAA ip of china upstream" },
        .{ .flags = TRUST_IPCHK, .msg = "check AAAA ip of trust upstream" },
    };
    // zig fmt: on

    inline for (list) |v| {
        if (self.has(v.flags)) {
            log.info(@src(), v.msg, .{});
            if (@hasField(@TypeOf(v), "brk")) break;
        }
    }
}
