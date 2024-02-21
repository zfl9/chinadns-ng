const std = @import("std");
const log = @import("log.zig");
const dnl = @import("dnl.zig");
const cc = @import("cc.zig");

const NoAAAA = @This();

pub const Flags = u8;

// struct fields
flags: Flags = 0,

pub const ALL: Flags = std.math.maxInt(Flags);
pub const ALL_TAG = TAG_GFW | TAG_CHN | TAG_NONE;
pub const ALL_DNS = CHINA_DNS | TRUST_DNS;

pub const TAG_GFW: Flags = 1 << 0;
pub const TAG_CHN: Flags = 1 << 1;
pub const TAG_NONE: Flags = 1 << 2;

pub const CHINA_DNS: Flags = 1 << 3;
pub const TRUST_DNS: Flags = 1 << 4;

pub const CHINA_IPCHK: Flags = 1 << 5;
pub const TRUST_IPCHK: Flags = 1 << 6;

pub fn has(self: NoAAAA, flags: Flags) bool {
    return self.flags & flags == flags;
}

pub fn has_any(self: NoAAAA, flags: Flags) bool {
    return self.flags & flags != 0;
}

pub fn add(self: *NoAAAA, flags: Flags) void {
    self.flags |= flags;

    // try simplify to flags ALL
    if (self.flags != ALL and (self.has(ALL_TAG) or self.has(ALL_DNS)))
        self.flags = ALL;
}

/// return the rule (string literal) that caused the filter
pub fn filter(self: NoAAAA, name_tag: dnl.Tag) ?cc.ConstStr {
    if (self.flags == 0)
        return null;

    if (self.flags == ALL)
        return "all";

    switch (name_tag) {
        .chn => {
            if (self.has(TAG_CHN)) return "tag_chn";
            if (self.has(CHINA_DNS)) return "china_dns";
        },
        .gfw => {
            if (self.has(TAG_GFW)) return "tag_gfw";
            if (self.has(TRUST_DNS)) return "trust_dns";
        },
        .none => {
            if (self.has(TAG_NONE)) return "tag_none";
        },
    }

    return null;
}

pub fn display(self: NoAAAA) void {
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
