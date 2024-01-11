const c = @import("c.zig");
const cc = @import("cc.zig");
const g = @import("g.zig");
const std = @import("std");
const testing = std.testing;

pub const Tag = enum(u8) {
    gfw = c.NAME_TAG_GFW,
    chn = c.NAME_TAG_CHN,
    none = c.NAME_TAG_NONE,

    pub inline fn to_int(tag: Tag) u8 {
        return @enumToInt(tag);
    }

    pub inline fn from_int(v: u8) Tag {
        return @intToEnum(Tag, v);
    }

    pub inline fn desc(tag: Tag) cc.ConstStr {
        return c.get_tag_desc(tag.to_int());
    }
};

pub inline fn init() void {
    return c.dnl_init(g.gfwlist_filenames.items.ptr, g.chnlist_filenames.items.ptr, g.gfwlist_first);
}

pub inline fn is_empty() bool {
    return c.dnl_is_empty();
}

pub inline fn get_name_tag(domain_name: [:0]const u8) Tag {
    return Tag.from_int(c.get_name_tag(domain_name.ptr, cc.to_int(domain_name.len), g.default_tag.to_int()));
}

pub fn @"test: get tag desc"() !void {
    try testing.expectEqualStrings("gfw", cc.strslice(Tag.gfw.desc()));
    try testing.expectEqualStrings("chn", cc.strslice(Tag.chn.desc()));
    try testing.expectEqualStrings("none", cc.strslice(Tag.none.desc()));
}
