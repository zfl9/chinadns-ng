const std = @import("std");
const g = @import("g.zig");
const cc = @import("cc.zig");
const SentinelVector = @import("sentinel_vector.zig").SentinelVector;

// ==================================================

const StrList = @This();

vec: SentinelVector(?cc.ConstStr, null) = .{},

// ==================================================

/// a copy of string `str` will be created (strdup)
/// if the string already exists, it will not be added
pub fn add(self: *StrList, str: []const u8) void {
    for (self.items()) |cstr| {
        if (std.mem.eql(u8, cc.strslice_c(cstr), str))
            return;
    }
    self.vec.append().* = (g.allocator.dupeZ(u8, str) catch unreachable).ptr;
}

pub fn items_z(self: *const StrList) [:null]?cc.ConstStr {
    return self.vec.items;
}

pub fn items(self: *const StrList) []cc.ConstStr {
    return @ptrCast([]cc.ConstStr, self.items_z());
}

pub fn is_null(self: *const StrList) bool {
    return self.vec.is_null();
}

pub fn is_empty(self: *const StrList) bool {
    return self.vec.is_empty();
}
