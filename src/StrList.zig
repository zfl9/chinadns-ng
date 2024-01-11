//! for simple short strings, such as the value of a command line option.
//! not looking for performance, but it's better to keep the structure compact.

const cc = @import("cc.zig");
const std = @import("std");

/// string pointers
items: [:null]?cc.ConstStr = &[_:null]?cc.ConstStr{},
/// 0 means null, no memory allocated
capacity: usize = 0,

const Self = @This();

pub fn deinit(self: *Self) void {
    if (self.is_null()) return;

    for (self.items) |ptr|
        cc.free(ptr);

    cc.free(self.get_memory());
}

/// a copy of string `str` will be created (strdup)
/// if the string already exists, it will not be added
/// TODO: replace strdup with alloc_only allocator
pub fn add(self: *Self, str: []const u8) void {
    for (self.items) |cstr| {
        if (std.mem.eql(u8, cc.strslice(cstr.?), str))
            return;
    }
    self.ensure_avail(1);
    self.items.len += 1;
    self.items[self.items.len - 1] = cc.strdup(str).ptr;
    self.items[self.items.len] = null;
}

pub fn ensure_avail(self: *Self, available_n: usize) void {
    if (self.capacity < self.items.len + available_n + 1) { // end with null
        const new_cap = std.math.max(self.items.len + available_n + 1, self.capacity * 3 / 2);
        const new_memory = cc.realloc(?cc.ConstStr, self.get_memory(), new_cap).?;
        self.set_memory(new_memory);
    }
}

fn get_memory(self: *const Self) []?cc.ConstStr {
    return self.items.ptr[0..self.capacity];
}

fn set_memory(self: *Self, new_memory: []?cc.ConstStr) void {
    self.items.ptr = @ptrCast(@TypeOf(self.items.ptr), new_memory.ptr);
    self.capacity = new_memory.len;
}

pub inline fn is_null(self: *const Self) bool {
    return self.capacity == 0;
}

pub inline fn is_empty(self: *const Self) bool {
    return self.items.len == 0;
}
