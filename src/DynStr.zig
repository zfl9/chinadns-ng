//! for simple short strings, such as the value of a command line option.
//! not looking for performance, but it's better to keep the structure compact.

const C = @import("C.zig");

/// string content
str: [:0]u8 = &[_:0]u8{},
/// 0 means null, no memory allocated
capacity: usize = 0,

const Self = @This();

pub fn deinit(self: *Self) void {
    if (!self.is_null())
        C.free(self.get_memory());
}

/// copy string `s` to buffer
pub fn set(self: *Self, str: []const u8) void {
    self.check_cap(str.len);
    self.str.len = str.len;
    @memcpy(self.str.ptr, str.ptr, str.len);
    self.str[str.len] = 0;
}

fn check_cap(self: *Self, strlen: usize) void {
    if (strlen + 1 > self.capacity) {
        const new_memory = C.realloc(u8, self.get_memory(), strlen + 1).?;
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
