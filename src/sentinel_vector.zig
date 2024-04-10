const cc = @import("cc.zig");
const g = @import("g.zig");

// ==========================================
pub fn SentinelVector(comptime T: type, comptime sentinel: T) type {
    return struct {
        const Self = @This();

        /// sentinel-terminated slice
        items: [:sentinel]T = &[_:sentinel]T{},
        /// 0 means null, no memory allocated
        capacity: usize = 0,

        // ==========================================

        /// no memory allocated (initial state)
        pub fn is_null(self: *const Self) bool {
            return self.capacity == 0;
        }

        /// no items in the vector
        pub fn is_empty(self: *const Self) bool {
            return self.items.len == 0;
        }

        pub fn append(self: *Self) *T {
            self.resize(self.items.len + 1);
            return &self.items[self.items.len - 1];
        }

        /// end with sentinel
        pub fn resize(self: *Self, n_items: usize) void {
            if (n_items + 1 > self.capacity) {
                const new_mem = g.allocator.realloc(self.mem(), n_items + 1) catch unreachable;
                self.set_mem(new_mem);
            }
            self.items.len = n_items;
            self.items[n_items] = sentinel;
        }

        fn mem(self: *const Self) []T {
            return self.items.ptr[0..self.capacity];
        }

        fn set_mem(self: *Self, new_mem: []T) void {
            self.items.ptr = @ptrCast(@TypeOf(self.items.ptr), new_mem.ptr);
            self.capacity = new_mem.len;
        }
    };
}
