const c = @import("c.zig");
const g = @import("g.zig");

pub fn init() void {
    const need_ipset = !g.chnip_setnames.is_empty() or !g.gfwip_setnames.is_empty() or g.default_tag == .none;
    if (!need_ipset) return;

    c.ipset_init(
        g.chnroute_name.str,
        g.chnroute6_name.str,
        g.chnip_setnames.str,
        g.gfwip_setnames.str,
        g.default_tag.to_int(),
    );
}
