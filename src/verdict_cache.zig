const std = @import("std");
const g = @import("g.zig");
const c = @import("c.zig");
const cc = @import("cc.zig");
const dns = @import("dns.zig");
const Upstream = @import("Upstream.zig");
const assert = std.debug.assert;

comptime {
    // @compileLog("sizeof(Verdict):", @sizeOf(Verdict));
    // @compileLog("bitsizeof(Verdict):", @bitSizeOf(Verdict));
}

/// tag:none && qtype=A/AAAA
/// [qname] => china_accepted
var _map: std.StringHashMapUnmanaged(bool) = .{};

const GetOrPutResult = @TypeOf(_map).GetOrPutResult;

/// `tag:none` domain
/// qtype `A` or `AAAA`
/// return `china_accepted`
pub fn get(msg: []const u8, qnamelen: c_int) ?bool {
    if (_map.count() == 0)
        return null;

    return _map.get(dns.get_qname(msg, qnamelen));
}

/// cache only if tag:none has both china_dns path and trust_dns path
pub fn add(msg: []const u8, qnamelen: c_int, china_accepted: bool) void {
    if (g.verdict_cache_size == 0)
        return;

    const qname = dns.get_qname(msg, qnamelen);
    const res = _map.getOrPut(g.allocator, qname) catch unreachable;

    if (!res.found_existing) {
        // init the new entry
        res.key_ptr.* = new_key(qname, &res);
    }

    // update the value
    res.value_ptr.* = china_accepted;
}

/// `_map.getOrPut() && !res.found_existing`
fn new_key(qname: []const u8, gop_res: *const GetOrPutResult) []const u8 {
    if (_map.count() > g.verdict_cache_size) {
        // remove an old cache
        var it = _map.keyIterator();
        while (it.next()) |key_ptr| {
            if (key_ptr != gop_res.key_ptr) {
                const removed_qname = cc.remove_const(key_ptr.*);

                _map.removeByPtr(key_ptr);
                assert(_map.count() == g.verdict_cache_size);

                // try reuse the removed_qname
                if (g.allocator.resize(removed_qname, qname.len)) |mem| {
                    const key = mem[0..qname.len];
                    @memcpy(key.ptr, qname.ptr, qname.len);
                    return key;
                } else {
                    g.allocator.free(removed_qname);
                    return g.allocator.dupe(u8, qname) catch unreachable;
                }
            }
        }
        unreachable;
    } else {
        return g.allocator.dupe(u8, qname) catch unreachable;
    }
}
