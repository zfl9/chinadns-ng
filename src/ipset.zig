const c = @import("c.zig");
const cc = @import("cc.zig");

pub const testctx_t = c.struct_ipset_testctx;
pub const addctx_t = c.struct_ipset_addctx;

pub fn new_testctx(name46: cc.ConstStr) *const testctx_t {
    return c.ipset_new_testctx(name46).?;
}

pub fn new_addctx(name46: cc.ConstStr) *addctx_t {
    return c.ipset_new_addctx(name46).?;
}
