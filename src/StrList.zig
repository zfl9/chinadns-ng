//! for simple short strings, such as the value of a command line option.
//! not looking for performance, but it's better to keep the structure compact.

const std = @import("std");
const g = @import("g.zig");
const cc = @import("cc.zig");

// ==================================================

const StrList = @This();

/// string pointers
items: [:null]?cc.ConstStr = &[_:null]?cc.ConstStr{},
/// 0 means null, no memory allocated
capacity: usize = 0,

// ==================================================

/// a copy of string `str` will be created (strdup)
/// if the string already exists, it will not be added
/// TODO: replace strdup with alloc_only allocator
pub fn add(self: *StrList, str: []const u8) void {
    for (self.items) |cstr| {
        if (std.mem.eql(u8, cc.strslice(cstr.?), str))
            return;
    }
    self.ensure_available(1);
    self.items.len += 1;
    self.items[self.items.len - 1] = cc.strdup(str).ptr;
    self.items[self.items.len] = null;
}

pub fn ensure_available(self: *StrList, available_n: usize) void {
    if (self.capacity < self.items.len + available_n + 1) { // end with null
        const new_cap = std.math.max(self.items.len + available_n + 1, self.capacity * 3 / 2);
        const new_mem = g.allocator.realloc(self.get_mem(), new_cap) catch unreachable;
        self.set_mem(new_mem);
    }
}

fn get_mem(self: *const StrList) []?cc.ConstStr {
    return self.items.ptr[0..self.capacity];
}

fn set_mem(self: *StrList, new_mem: []?cc.ConstStr) void {
    self.items.ptr = @ptrCast(@TypeOf(self.items.ptr), new_mem.ptr);
    self.capacity = new_mem.len;
}

pub inline fn is_null(self: *const StrList) bool {
    return self.capacity == 0;
}

pub inline fn is_empty(self: *const StrList) bool {
    return self.items.len == 0;
}
