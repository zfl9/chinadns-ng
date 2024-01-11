//! for simple short strings, such as the value of a command line option.
//! not looking for performance, but it's better to keep the structure compact.

const cc = @import("cc.zig");

/// string content
str: [:0]u8 = &[_:0]u8{},
/// 0 means null, no memory allocated
capacity: usize = 0,

const Self = @This();

pub fn deinit(self: *Self) void {
    if (!self.is_null())
        cc.free(self.get_memory());
}

/// copy string to buffer
pub fn set(self: *Self, str: []const u8) void {
    return self.set_ex(&.{str});
}

/// copy strings to buffer
pub fn set_ex(self: *Self, str_list: []const []const u8) void {
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

fn check_cap(self: *Self, strlen: usize) void {
    if (strlen + 1 > self.capacity) {
        const new_memory = cc.realloc(u8, self.get_memory(), strlen + 1).?;
        self.set_memory(new_memory);
    }
}

fn get_memory(self: *const Self) []u8 {
    return self.str.ptr[0..self.capacity];
}

fn set_memory(self: *Self, new_memory: []u8) void {
    self.str.ptr = @ptrCast(@TypeOf(self.str.ptr), new_memory.ptr);
    self.capacity = new_memory.len;
}

pub inline fn is_null(self: *const Self) bool {
    return self.capacity == 0;
}

pub inline fn is_empty(self: *const Self) bool {
    return self.str.len == 0;
}
