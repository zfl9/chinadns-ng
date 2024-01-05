const std = @import("std");
const maxInt = std.math.maxInt;

pub const Flags = u8;

// struct fields
flags: Flags = 0,

pub const ALL: Flags = maxInt(Flags);
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

pub inline fn add(self: *Self, flags: Flags) void {
    self.flags |= flags;

    // try simplify to flags ALL
    if (self.flags != ALL) {
        const all_tag = TAG_GFW | TAG_CHN | TAG_NONE;
        const all_dns = CHINA_DNS | TRUST_DNS;

        if (self.has(all_tag) or self.has(all_dns))
            self.flags = ALL;
    }
}
