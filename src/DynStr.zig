const cc = @import("cc.zig");
const SentinelVector = @import("sentinel_vector.zig").SentinelVector;

// ==========================================

const DynStr = @This();

vec: SentinelVector(u8, 0) = .{},

// ==========================================

/// copy string to buffer
pub fn set(self: *DynStr, str: []const u8) void {
    return self.set_x(&.{str});
}

/// copy strings to buffer
pub fn set_x(self: *DynStr, str_list: []const []const u8) void {
    var strlen: usize = 0;
    for (str_list) |str|
        strlen += str.len;

    self.vec.resize(strlen);

    var ptr = self.vec.items.ptr;
    for (str_list) |str| {
        @memcpy(ptr, str.ptr, str.len);
        ptr += str.len;
    }
}

pub fn slice(self: *const DynStr) [:0]const u8 {
    return self.vec.items;
}

pub fn cstr(self: *const DynStr) cc.ConstStr {
    return self.slice().ptr;
}

pub fn is_null(self: *const DynStr) bool {
    return self.vec.is_null();
}

pub fn is_empty(self: *const DynStr) bool {
    return self.vec.is_empty();
}
