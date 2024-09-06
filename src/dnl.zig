const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const Tag = @import("tag.zig").Tag;
const testing = std.testing;

/// {"a.txt", "b.txt", null}
pub const filenames_t = [*:null]?cc.ConstStr;

pub inline fn init(tag_to_filenames: *const [c.TAG__MAX + 1]?filenames_t) void {
    return c.dnl_init(tag_to_filenames, g.flags.gfwlist_first);
}

pub inline fn is_empty() bool {
    return c.dnl_is_empty();
}

pub inline fn get_tag(name: [*]const u8, namelen: c_int) Tag {
    return if (namelen > 0 and !is_empty())
        Tag.from_int(c.dnl_get_tag(name, namelen, g.default_tag.int()))
    else
        g.default_tag;
}
