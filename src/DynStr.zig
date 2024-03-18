//! for simple short strings, such as the value of a command line option.
//! not looking for performance, but it's better to keep the structure compact.

const cc = @import("cc.zig");
const g = @import("g.zig");

// ==========================================

const DynStr = @This();

/// string content
str: [:0]u8 = &[_:0]u8{},
/// 0 means null, no memory allocated
capacity: usize = 0,

// ==========================================

/// copy string to buffer
pub fn set(self: *DynStr, str: []const u8) void {
    return self.set_ex(&.{str});
}

/// copy strings to buffer
pub fn set_ex(self: *DynStr, str_list: []const []const u8) void {
    var strlen: usize = 0;
    for (str_list) |str|
        strlen += str.len;

    self.check_cap(strlen);
    self.str.len = strlen;

    var offset: usize = 0;
    for (str_list) |str| {
        @memcpy(self.str.ptr + offset, str.ptr, str.len);
        offset += str.len;
    }

    // end with 0
    self.str[strlen] = 0;
}

fn check_cap(self: *DynStr, strlen: usize) void {
    if (strlen + 1 > self.capacity) {
        const new_mem = g.allocator.realloc(self.get_mem(), strlen + 1) catch unreachable;
        self.set_mem(new_mem);
    }
}

fn get_mem(self: *const DynStr) []u8 {
    return self.str.ptr[0..self.capacity];
}

fn set_mem(self: *DynStr, new_mem: []u8) void {
    self.str.ptr = @ptrCast(@TypeOf(self.str.ptr), new_mem.ptr);
    self.capacity = new_mem.len;
}

pub inline fn is_null(self: *const DynStr) bool {
    return self.capacity == 0;
}

pub inline fn is_empty(self: *const DynStr) bool {
    return self.str.len == 0;
}
