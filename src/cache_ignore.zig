const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const dns = @import("dns.zig");
const DynStr = @import("DynStr.zig");
const assert = std.debug.assert;

/// domains with these suffixes (wire-format) are not added to the cache
var _ignored_domains: std.StringHashMapUnmanaged(void) = .{};

/// LSB: level=1 (com)
/// MSB: level=8 (a.b.c.d.x.y.z.com)
/// 0001,0110 => level={2,3,5} is exists
var _exist_levels: u8 = 0;

const MAX_LEVEL = 8;

/// for opt.zig
pub fn add(ascii_domain: []const u8) ?void {
    var buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    var level: u8 = undefined;

    const opt_domain_z = dns.ascii_to_wire(ascii_domain, &buf, &level);
    if (opt_domain_z == null or level > MAX_LEVEL) {
        opt.print(@src(), "invalid domain", ascii_domain);
        return null;
    }

    const domain_z = opt_domain_z.?;
    const domain = domain_z[0 .. domain_z.len - 1];

    const res = _ignored_domains.getOrPut(g.allocator, domain) catch unreachable;
    if (res.found_existing)
        return;

    // ptr to dupe_domain
    res.key_ptr.* = g.allocator.dupe(u8, domain) catch unreachable;

    const bit = @as(u8, 1) << @intCast(u3, level - 1);
    _exist_levels |= bit;
}

pub fn is_ignored(rmsg: []const u8, qnamelen: c_int) bool {
    if (_ignored_domains.count() == 0)
        return false;

    var domains: [8][*]const u8 = undefined;
    var domain_end: [*]const u8 = undefined;

    const n = dns.qname_domains(rmsg, qnamelen, _exist_levels, &domains, &domain_end) orelse
        return true; // bad format

    for (domains[0..n]) |domain| {
        // const domain_len = domain_end - domain;
        const domain_len = cc.ptrdiff_u(u8, domain_end, domain);
        if (_ignored_domains.contains(domain[0..domain_len]))
            return true;
    }

    return false;
}
