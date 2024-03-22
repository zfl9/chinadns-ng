const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const opt = @import("opt.zig");
const dns = @import("dns.zig");
const DynStr = @import("DynStr.zig");
const assert = std.debug.assert;

/// domains with these suffixes (wire-format) are not added to the cache
var ignore_domains: std.StringHashMapUnmanaged(void) = .{};

/// LSB: level=1 (com)
/// MSB: level=8 (a.b.c.d.x.y.z.com)
/// 0001,0110 => level={2,3,5} is exists
var _exist_levels: u8 = 0;

var _keys_mem: []u8 = &.{};

const MAX_LEVEL = 8;

/// for opt.zig
pub fn add(ascii_domain: []const u8) ?void {
    var buf: [c.DNS_NAME_WIRE_MAXLEN]u8 = undefined;
    var level: u8 = undefined;

    const opt_domain_z = dns.ascii_to_wire(ascii_domain, &buf, &level);
    if (opt_domain_z == null or level > MAX_LEVEL) {
        opt.err_print(@src(), "invalid domain name", ascii_domain);
        return null;
    }
    const domain_z = opt_domain_z.?;
    const domain = domain_z[0 .. domain_z.len - 1];

    const res = ignore_domains.getOrPut(g.allocator, domain) catch unreachable;
    if (res.found_existing)
        return;

    const old_memlen = _keys_mem.len;
    const mem = g.allocator.realloc(_keys_mem, old_memlen + domain.len) catch unreachable;
    _keys_mem = mem;

    const dupe_domain = mem[old_memlen .. old_memlen + domain.len];
    @memcpy(dupe_domain.ptr, domain.ptr, domain.len);

    // ptr to dupe_domain
    res.key_ptr.* = dupe_domain;

    const bit = @as(u8, 1) << @intCast(u3, level - 1);
    _exist_levels |= bit;
}

pub fn has(rmsg: []const u8, qnamelen: c_int) bool {
    if (ignore_domains.count() == 0)
        return false;

    var domains: [8][*]const u8 = undefined;
    var domain_end: [*]const u8 = undefined;

    const n = dns.qname_domains(rmsg, qnamelen, _exist_levels, &domains, &domain_end) orelse
        return true; // bad format

    for (domains[0..n]) |domain| {
        // const domain_len = domain_end - domain;
        const domain_len = cc.ptrdiff_u(u8, domain_end, domain);
        if (ignore_domains.contains(domain[0..domain_len]))
            return true;
    }

    return false;
}
