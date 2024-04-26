const std = @import("std");
const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const testing = std.testing;

const U8_MAX = std.math.maxInt(u8);

pub const Tag = enum(u8) {
    chn = c.TAG_CHN,
    gfw = c.TAG_GFW,
    none = c.TAG_NONE,
    _,

    pub inline fn int(tag: Tag) u8 {
        return @enumToInt(tag);
    }

    pub inline fn name(tag: Tag) cc.ConstStr {
        return c.tag_to_name(tag.int());
    }

    pub inline fn valid(tag: Tag) bool {
        return c.tag_is_valid(tag.int());
    }

    pub inline fn is_null(tag: Tag) bool {
        return cc.memeql(cc.strslice_c(tag.name()), "null");
    }

    pub inline fn from_int(v: u8) Tag {
        return @intToEnum(Tag, v);
    }

    pub inline fn from_name(tag_name: cc.ConstStr) ?Tag {
        const v = c.tag_from_name(tag_name);
        return if (v != U8_MAX) from_int(v) else null;
    }

    /// register a user-defined tag (`tag_name` will be copied)
    /// if already registered, the same tag value is returned
    /// `p_overflow`: used to determine why it failed
    pub inline fn register(tag_name: cc.ConstStr, p_overflow: ?*bool) ?Tag {
        const v = c.tag_register(tag_name, p_overflow);
        return if (v != U8_MAX) from_int(v) else null;
    }
};

// ========================================================

pub fn @"test: to name"() !void {
    try testing.expectEqualStrings("chn", cc.strslice_c(Tag.chn.name()));
    try testing.expectEqualStrings("gfw", cc.strslice_c(Tag.gfw.name()));
    try testing.expectEqualStrings("none", cc.strslice_c(Tag.none.name()));
}

pub fn @"test: from name"() !void {
    try testing.expectEqual(Tag.chn, Tag.from_name("chn").?);
    try testing.expectEqual(Tag.gfw, Tag.from_name("gfw").?);
    try testing.expectEqual(Tag.none, Tag.from_name("none").?);
}
