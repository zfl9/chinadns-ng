const std = @import("std");
const assert = std.debug.assert;

// ==========================================

const Rc = @This();

ref_count: u32 = 1,

// ==========================================

pub inline fn ref(self: *Rc) void {
    assert(self.ref_count > 0);
    self.ref_count += 1;
}

/// return the updated ref_count
pub inline fn unref(self: *Rc) u32 {
    assert(self.ref_count > 0);
    self.ref_count -= 1;
    return self.ref_count;
}
